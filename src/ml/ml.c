/*******************************************************************************
 *
 * This file is provided under a dual license.  When you use or
 * distribute this software, you may choose to be licensed under
 * version 2 of the GNU General Public License ("GPLv2 License")
 * or BSD License.
 *
 * GPLv2 License
 *
 * Copyright(C) 2016 MediaTek Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See http://www.gnu.org/licenses/gpl-2.0.html for more details.
 *
 * BSD LICENSE
 *
 * Copyright(C) 2016 MediaTek Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 ******************************************************************************/

#include "includes.h"

#include "common.h"

#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "common/sae.h"
#include "rsn_supp/wpa.h"
#include "rsn_supp/wpa_i.h"
#include "rsn_supp/wpa_ie.h"
#include "ap/wpa_auth.h"
#include "ap/wpa_auth_i.h"
#include "ap/wpa_auth_ie.h"
#include "ap/hostapd.h"
#include "crypto/random.h"
#include "crypto/aes_wrap.h"
#include "utils/eloop.h"
#include "ml/ml.h"

#ifndef HOSTAPD
#include "wpa_supplicant_i.h"
#include "bss.h"
#include "driver_i.h" /* for drv cmd*/
#include "p2p/p2p_i.h"
#endif

#define CMD_PRESET_LINKID	"PRESET_LINKID"
#define CMD_GET_ML_CAPA		"GET_ML_CAPA"
#define CMD_GET_ML_PREFER_FREQ_LIST		"GET_ML_PREFER_FREQ_LIST"
#define CMD_GET_ML_2ND_FREQ "GET_ML_2ND_FREQ"

#define STATE_MACHINE_ML_GROUP \
	(((struct hostapd_data *)sm->wpa_auth->cb_ctx)->ml_group)
#define STATE_MACHINE_ML_GROUP_ADDR \
	(((struct hostapd_data *)sm->wpa_auth->cb_ctx)->ml_group)->ml_addr

struct wpa_ie_parse {
	const u8 *ap_rsn_ie;
	const u8 *ap_rsnxe;
	size_t ap_rsn_ie_len;
	size_t ap_rsnxe_len;
};

struct ml_gtk_data {
	u8 link_id;
	enum wpa_alg alg;
	int tx, key_rsc_len, keyidx;
	u8 gtk[32];
	int gtk_len;
};

/* common */

const u8 * ml_get_ie(const u8 *ies, size_t ie_len, u32 ml_ie_type)
{
	const struct element *elem;

	for_each_element_extid(elem, WLAN_EID_EXT_MULTI_LINK, ies, ie_len) {
		if (ML_IS_CTRL_TYPE(&elem->id, ml_ie_type))
			return &elem->id;
	}

	return NULL;
}

u8* ml_set_mac_kde(u8 *pos, const unsigned char *addr)
{
	if (addr == NULL)
		return pos;

	wpa_printf(MSG_DEBUG, "ML: MAC kde " MACSTR, MAC2STR(addr));
	return wpa_add_kde(pos, RSN_KEY_DATA_MAC_ADDR, addr, ETH_ALEN, NULL, 0);
}

u8* ml_set_ml_link_kde(u8 *pos, u8 link_id, const unsigned char *addr,
	const u8 *rsne, size_t rsne_len, const u8 *rsnxe, size_t rsnxe_len)
{
	u8 *buf, *cp, *ori;
	size_t len = 1 /* Link Information */ + ETH_ALEN + rsne_len + rsnxe_len;

	cp = buf = os_malloc(len);
	os_memset(cp, 0, len);
	*cp = link_id & BITS(0, 3);
	if (rsne && rsne_len)
		*cp |= BIT(4);
	if (rsnxe && rsnxe_len)
		*cp |= BIT(5);
	cp++;
	os_memcpy(cp, addr, ETH_ALEN);
	cp += ETH_ALEN;

	if (rsne && rsne_len) {
		os_memcpy(cp, rsne, rsne_len);
		cp += rsne_len;
	}

	if (rsnxe && rsnxe_len) {
		os_memcpy(cp, rsnxe, rsnxe_len);
		cp += rsnxe_len;
	}

	ori = pos;
	pos = wpa_add_kde(pos, RSN_KEY_DATA_MLO_LINK, buf, cp - buf, NULL, 0);
	wpa_hexdump_key(MSG_DEBUG, "ML: Link KDE", ori, pos - ori);

	os_free(buf);

	return pos;
}

int ml_parse_ie(const u8 *ie, size_t len,
		struct wpa_ml_ie_parse *ml, int log_level)
{
	const u8 *pos, *end;
	u16 ml_ctrl;

	wpa_hexdump(MSG_DEBUG, "ML IE", ie, len);

	os_memset(ml, 0, sizeof(*ml));
	pos = ie + 2; /* skip common ctrl */
	end = ie + len;
	if (pos > end)
		return -1;

	ml_ctrl = WPA_GET_LE16(ie);
	ml->type = ml_ctrl & ML_CTRL_TYPE_MASK;
	if (ml->type != ML_CTRL_TYPE_BASIC) {
		wpa_printf(log_level, "ML: invalid ML control type = %d",
			ml->type);
		return -1;
	}

	ml->common_info_len = *pos++;

	wpa_printf(log_level, "ML: common Info Len = %d", ml->common_info_len);

	/* Check ML control that which common info exist */
	os_memcpy(ml->ml_addr, pos, ETH_ALEN);
	pos += ETH_ALEN;
	wpa_printf(log_level, "ML: common Info MAC addr = "MACSTR"",
		MAC2STR(ml->ml_addr));

	if (ml_ctrl & ML_CTRL_LINK_ID_INFO_PRESENT) {
		ml->link_id = *pos;
		ml->link_id_present = 1;
		wpa_printf(log_level, "ML: common Info LinkID = %d", ml->link_id);
		pos += 1;
	}
	if (ml_ctrl & ML_CTRL_BSS_PARA_CHANGE_COUNT_PRESENT) {
		ml->bss_para_change_count = *pos;
		ml->bss_para_change_cnt_present = 1;
		wpa_printf(log_level, "ML: common Info BssParaChangeCount = %d", *pos);
		pos += 1;
	}
	if (ml_ctrl & ML_CTRL_MEDIUM_SYN_DELAY_INFO_PRESENT) {
		ml->medium_sync_delay = WPA_GET_LE16(pos);
		ml->medium_sync_delay_present = 1;
		wpa_printf(log_level, "ML: common Info MediumSynDelayInfo = %d", *pos);
		pos += 2;
	}
	if (ml_ctrl & ML_CTRL_EML_CAPA_PRESENT) {
		ml->eml_cap = WPA_GET_LE16(pos);
		ml->eml_cap_present = 1;
		wpa_printf(log_level, "ML: common Info EML capa = 0x%x", ml->eml_cap);
		pos += 2;
	}
	if (ml_ctrl & ML_CTRL_MLD_CAPA_PRESENT) {
		ml->mld_cap = WPA_GET_LE16(pos);
		ml->mld_cap_present = 1;
		wpa_printf(log_level, "ML: common Info MLD capa = 0x%x", ml->mld_cap);
		pos += 2;
	}
	if (ml_ctrl & ML_CTRL_MLD_ID_PRESENT) {
		ml->mld_id = *pos;
		ml->mld_id_present = 1;
		wpa_printf(log_level, "ML: common Info MLD ID = %d", ml->mld_id);
		pos += 1;
	}
	if (pos - (ie + 2) != ml->common_info_len) {
		ml->valid = false;
		wpa_printf(log_level, "ML: invalid ML control info len = %d",
			ml->common_info_len);
		return -1;
	} else {
		ml->valid = true;
	}

	/* pos point to link info, recusive parse it */
	while (pos < end) {
		u16 sta_ctrl;
		struct per_sta_profile *profile;
		u8 sta_info_len;
		const u8 *head, *tail;

		if (*pos != ML_SUB_ID_PER_STA_PROFILE ||
		    ml->prof_num >= ML_MAX_LINK_NUM)
			break;

		head = pos + 2;
		tail = head + pos[1];
		pos += 2;
		sta_ctrl = WPA_GET_LE16(pos);
		pos += 2;

		profile = &ml->profiles[ml->prof_num++];
		profile->link_id = sta_ctrl & ML_STA_CTRL_LINK_ID_MASK;
		profile->complete_profile =
			(sta_ctrl & ML_STA_CTRL_COMPLETE_PROFILE) > 0;

		wpa_printf(log_level, "ML: LinkID=%d Ctrl=0x%x(%s) Total=%d",
			profile->link_id, sta_ctrl,
			profile->complete_profile ? "COMPLETE" : "PARTIAL",
			ml->prof_num);

		sta_info_len = *pos++;

		if (sta_ctrl & ML_STA_CTRL_MAC_ADDR_PRESENT) {
			os_memcpy(profile->addr, pos, ETH_ALEN);
			profile->mac_addr_present = 1;
			wpa_printf(log_level, "ML: LinkID=%d, LinkAddr="MACSTR"",
				profile->link_id, MAC2STR(profile->addr));
			pos += ETH_ALEN;
		}
		if (sta_ctrl & ML_STA_CTRL_BCN_INTV_PRESENT) {
			profile->beacon_interval = WPA_GET_LE16(pos);
			profile->bcn_intvl_present = 1;
			wpa_printf(log_level, "ML: LinkID=%d, BCN_INTV = %d",
				profile->link_id, profile->beacon_interval);
			pos += 2;
		}
		if (sta_ctrl & ML_STA_CTRL_TSF_OFFSET_PRESENT) {
			os_memcpy(&profile->tsf_offset, pos, 8);
			profile->tsf_offset_present = 1;
			wpa_printf(log_level, "ML: LinkID=%d, TSF_OFFSET = %lu",
				profile->link_id, profile->tsf_offset);
			pos += 8;
		}
		if (sta_ctrl & ML_STA_CTRL_DTIM_INFO_PRESENT) {
			profile->dtim = WPA_GET_LE16(pos);
			profile->dtim_present = 1;
			wpa_printf(log_level, "ML: LinkID=%d, DTIM_INFO = 0x%x",
				profile->link_id, profile->dtim);
			pos += 2;
		}
		/* If the Complete Profile subfield = 1 and
		 * NSTR Link Pair Present = 1, then NSTR Indication Bitmap exist
		 * NSTR Bitmap Size = 1 if the length of the corresponding
		 * NSTR Indication Bitmap is 2 bytes, and = 0 if the
		 * length of the corresponding NSTR Indication Bitmap = 1 byte
		 */
		if ((sta_ctrl & ML_STA_CTRL_COMPLETE_PROFILE) &&
			(sta_ctrl & ML_STA_CTRL_NSTR_LINK_PAIR_PRESENT)) {
			if (((sta_ctrl & ML_STA_CTRL_NSTR_BMP_SIZE) >>
				ML_STA_CTRL_NSTR_BMP_SIZE_SHIFT) == 0) {
				profile->nstr_bmap = *pos;
				wpa_printf(log_level, "ML: LinkID=%d, NSTR_BMP0=0x%x",
					profile->link_id, profile->nstr_bmap);
				pos += 1;
			} else {
				profile->nstr_bmap = WPA_GET_LE16(pos);
				wpa_printf(log_level, "ML: LinkID=%d, NSTR_BMP1=0x%x",
					profile->link_id, profile->nstr_bmap);
				pos += 2;
			}
			profile->nstr_present = 1;
		}
		if (sta_ctrl & ML_STA_CTRL_BSS_PARA_CHANGE_COUNT_PRESENT) {
			profile->bss_para_change_count = *pos;
			profile->bss_para_change_count_present = 1;
			wpa_printf(log_level, "ML: LinkID=%d, BSS_PARA_CHANGE_COUNT=0x%x",
				profile->link_id, profile->bss_para_change_count);
			pos += 1;
		}
		if (pos - (head + 2) != sta_info_len) {
			wpa_printf(MSG_WARNING, "ML: invalid ML STA info len = %d",
				sta_info_len);
			pos = head + 2 + sta_info_len;
		}

		/* point to next Per-STA profile*/
		pos = tail;
	}

	return 0;
}

int ml_is_probe_req(const u8* ie, u8 len)
{
	const u8 *pos, *end;
	u16 ml_ctrl;

	if (!ie || len == 0)
		return 0;

	wpa_hexdump(MSG_DEBUG, "ML IE", ie, len);

	pos = ie + 2; /* skip common ctrl */
	end = ie + len;
	if (pos > end)
		return 0;

	ml_ctrl = WPA_GET_LE16(ie);
	return (ml_ctrl & ML_CTRL_TYPE_MASK) == ML_CTRL_TYPE_PROBE_REQ;
}

int ml_build_ml_probe_req(struct wpabuf *buf, u8 mld_id)
{
	u16 ctrl = 0;

	wpa_printf(MSG_DEBUG, "ML: write ml ie for probe request");

	wpabuf_put_u8(buf, WLAN_EID_EXTENSION);
	/* EID 1byte + ML Ctrl 2byte + CommonInfo 2byte */
	wpabuf_put_u8(buf, 5);
	wpabuf_put_u8(buf, WLAN_EID_EXT_MULTI_LINK);

	/* ml common control */
	ML_SET_CTRL_TYPE(ctrl, ML_CTRL_TYPE_PROBE_REQ);
	ML_SET_CTRL_PRESENCE(ctrl, MLD_ID_PRESENT);

	wpabuf_put_le16(buf, ctrl);

	/* len:1, mld id:1 */
	wpabuf_put_u8(buf, 2);

	/* mld id */
	wpabuf_put_u8(buf, mld_id);

	return 0;
}

int ml_build_ml_probe_resp(struct wpabuf *buf, const u8* ml_ie, u8 ml_len)
{
	u16 ctrl = 0;

	if (!ml_ie || ml_len == 0)
		return 0;

	wpa_printf(MSG_DEBUG, "ML: write ml ie for probe resp");

	wpabuf_put_u8(buf, WLAN_EID_EXTENSION);
	/* extid: 1, common ctrl: 2, common info: 7(len:1, mac:6) */
	wpabuf_put_u8(buf, 10);
	wpabuf_put_u8(buf, WLAN_EID_EXT_MULTI_LINK);

	/* ml common control */
	ML_SET_CTRL_TYPE(ctrl, ML_CTRL_TYPE_BASIC);

	/* A Basic Multi-Link element in an Authentication frame:
	 * the STA shall include the MLD MAC address of the MLD
	 * the STA shall set all subfields in the Presence Bitmap subfield of
	 * the Multi-Link Control field of the element to 0
	 * the STA shall not include the Link Info field of the element.
	 */
	ML_SET_CTRL_PRESENCE(ctrl, 0);
	wpabuf_put_le16(buf, ctrl);

	/* len:1, mac:6 */
	wpabuf_put_u8(buf, 7);

	/* fill ml mac addr, driver will take care of it */
	wpabuf_put_data(buf, broadcast_ether_addr, ETH_ALEN);

	return 0;
}

/* AP */
const u8 * ml_auth_spa(struct wpa_state_machine *sm, const u8 *peer_addr)
{
	if(sm && peer_addr && sm->dot11MultiLinkActivated) {
		if (os_memcmp(peer_addr, sm->sta_ml_ie->ml_addr, ETH_ALEN) != 0) {
			wpa_printf(MSG_INFO,
				"ML: SPA[" MACSTR "] use ml addr[" MACSTR "]",
				MAC2STR(peer_addr), MAC2STR(sm->sta_ml_ie->ml_addr));
			return sm->sta_ml_ie->ml_addr;
		}
	}

	return peer_addr;
}

const u8 * ml_auth_aa(struct wpa_state_machine *sm, const u8 *addr)
{
	if(sm && addr && sm->dot11MultiLinkActivated) {
		struct wpa_ml_group *ml_group = STATE_MACHINE_ML_GROUP;

		if (ml_group && os_memcmp(ml_group->ml_addr, addr, ETH_ALEN) != 0) {
			wpa_printf(MSG_INFO,
				"ML: AA[" MACSTR "] use ml addr[" MACSTR "]",
				MAC2STR(addr), MAC2STR(ml_group->ml_addr));
			return ml_group->ml_addr;
		}
	}

	return addr;
}

int ml_auth_get_capab(struct hostapd_data *hapd)
{
	char cmd[32], buf[256];
	u8 p2p = 0;

	if (!hapd->driver->driver_cmd)
		return false;

#ifdef CONFIG_P2P
	p2p = hapd->p2p != NULL;
#endif
	/* 1 means p2p mode */
	os_snprintf(cmd, sizeof(cmd), CMD_GET_ML_CAPA " %d", p2p);
	hapd->driver->driver_cmd(hapd->drv_priv, cmd, buf, sizeof(buf));
	wpa_printf(MSG_INFO, "ML: %s get ml capab %s", p2p ? "P2P" : "AP", buf);
	if (os_strstr(buf, "1"))
		return 1;

	return 0;
}

struct wpa_ml_link * ml_setup_link(struct hostapd_data *hapd,
	struct wpa_ml_group *ml_group, u8 link_id)
{
	struct wpa_ml_link *links, *link;

	links = os_realloc_array(ml_group->links, ml_group->ml_link_num + 1,
				 sizeof(struct wpa_ml_link));
	if (links == NULL)
		return NULL;
	ml_group->links = links;
	link = &links[ml_group->ml_link_num++];
	link->ctx = hapd;
	link->link_id = link_id;
	os_memcpy(link->addr, hapd->own_addr, ETH_ALEN);
	hapd->ml_group = ml_group;

	wpa_printf(MSG_INFO, "ML: Join ML Group=%p, link_id=%d", ml_group, link_id);

	return link;
}

struct wpa_ml_group *ml_alloc_group(struct hostapd_data *hapd,
				    u8 group_id)
{
	struct wpa_ml_group *ml_group = NULL;

	ml_group = os_zalloc(sizeof(*ml_group));
	ml_group->ctx = hapd;
	os_memcpy(ml_group->ml_addr, hapd->own_addr, ETH_ALEN);
	ml_group->ml_group_id = group_id;

	wpa_printf(MSG_INFO,
		"ML: Alloc ML Group=%p (ml_group_id=%d, ml_addr=" MACSTR ")",
		ml_group, group_id, MAC2STR(ml_group->ml_addr));

	return ml_group;
}

struct wpa_ml_group * ml_get_group(struct hapd_interfaces *interfaces)
{
	size_t i, j;

	wpa_printf(MSG_INFO, "ML: interfaces=%p, count=%u",
			     interfaces, (unsigned int)interfaces->count);

	/* search interfaces to find existed ml group */
	for (i = 0; i < interfaces->count; i++) {
		struct hostapd_iface *iface = interfaces->iface[i];

		wpa_printf(MSG_INFO, "ML: iface=%p, num_bss=%u",
				     iface, (unsigned int)iface->num_bss);

		for (j = 0; j < iface->num_bss; j++) {
			struct hostapd_data *hapd = iface->bss[j];

			if (hapd->ml_group) {
				wpa_printf(MSG_INFO,
					"ML: found ml_group=%p, ml_group_id=%d",
					hapd->ml_group, hapd->ml_group->ml_group_id);
				return hapd->ml_group;
			}
		}
	}

	return NULL;
}

int ml_group_init(struct hostapd_data *hapd)
{
	struct hapd_interfaces *interfaces = hapd->iface->interfaces;
	struct hostapd_config *iconf = hapd->iconf;
	struct wpa_ml_group *ml_group = NULL;
	struct wpa_ml_link *link;
	u8 i, capab;

	if (!interfaces)
		goto done;

	capab = ml_auth_get_capab(hapd);
	/* ml capable, try to add to existed group */
	if (capab)
		ml_group = ml_get_group(interfaces);

	wpa_printf(MSG_INFO, "ML: " MACSTR " ml_group_init, capab=%d, group=%p",
			MAC2STR(hapd->own_addr), capab, ml_group);

	/* found, join it */
	if (ml_group) {
		/* error check */
		for (i = 0; i < ml_group->ml_link_num; i++) {
			link = &ml_group->links[i];
			if (link->ctx == hapd) {
				wpa_printf(MSG_INFO, "ML: reinit link");
				return -1;
			}
		}
		if (ml_setup_link(hapd, ml_group, i) == NULL)
			return -1;
	} else {
		ml_group = ml_alloc_group(hapd, interfaces->ml_group_idx);
		if (ml_setup_link(hapd, ml_group, 0) == NULL) {
			os_free(ml_group);
			return -1;
		}
		interfaces->ml_group_idx++;
	}

done:
	return 0;
}

int ml_group_deinit(struct hostapd_data *hapd)
{
	struct wpa_ml_group *ml_group = hapd->ml_group;
	struct wpa_ml_link *link;
	size_t i, k = 0;

	if (!ml_group)
		return -1;

	for (i = 0; i < ml_group->ml_link_num; i++) {
		link = &ml_group->links[i];

		if (link->ctx == hapd) {
			wpa_printf(MSG_INFO, "ML: remove link %d", link->link_id);
			k = i;
			while (k < (ml_group->ml_link_num - 1)) {
				os_memcpy(&ml_group->links[k],
					&ml_group->links[k + 1], sizeof(*link));
				k++;
			}
			ml_group->ml_link_num--;
		}
	}
	hapd->ml_group = NULL;

	wpa_printf(MSG_INFO, "ML: total link num = %d", ml_group->ml_link_num);

	/* free ml group by ml group owner */
	if (ml_group->ml_link_num == 0) {
		wpa_printf(MSG_INFO, "ML: no link, free ml group %d", ml_group->ml_group_id);
		os_free(ml_group->links);
		os_free(ml_group);
	}

	return 0;
}

u8 ml_get_link_id(struct wpa_state_machine *sm)
{
	struct wpa_ml_group *ml_group = STATE_MACHINE_ML_GROUP;
	struct hostapd_data *hapd = (struct hostapd_data *)sm->wpa_auth->cb_ctx;
	struct wpa_ml_link *link;
	size_t i;

	for (i = 0; i < ml_group->ml_link_num; i++) {
		link = &ml_group->links[i];

		if (link->ctx == hapd)
			return link->link_id;
	}

	return 0xff;
}

int ml_new_assoc_sta(struct wpa_state_machine *sm, const u8 *ie, size_t len)
{
	if (!sm)
		return -1;

	wpa_printf(MSG_INFO, "ML: new assoc sta");

	os_free(sm->sta_ml_ie);
	if (ie == NULL || len == 0 || STATE_MACHINE_ML_GROUP == NULL) {
		sm->sta_ml_ie = NULL;
		sm->dot11MultiLinkActivated = 0;
	} else {
		struct wpa_ml_ie_parse ml;
		struct wpa_ml_group *ml_group = STATE_MACHINE_ML_GROUP;

		if (ml_parse_ie(ie, len, &ml, MSG_INFO) != 0 ||
		    ml.prof_num > ml_group->ml_link_num) {
			sm->sta_ml_ie = NULL;
			sm->dot11MultiLinkActivated = 0;
			return -1;
		} else {
			sm->sta_ml_ie = os_memdup(&ml, sizeof(ml));
			if (sm->sta_ml_ie == NULL) {
				sm->dot11MultiLinkActivated = 0;
				return -1;
			}

			sm->sta_ml_ie->link_id = ml_get_link_id(sm);
			sm->dot11MultiLinkActivated = 1;
		}
	}

	return 0;
}

u8* ml_add_m1_kde(struct wpa_state_machine *sm, u8 *pos)
{
	if (!sm->dot11MultiLinkActivated)
		return pos;

	wpa_printf(MSG_INFO, "ML: Add Mac into EAPOL-Key 1/4");
	return ml_set_mac_kde(pos, STATE_MACHINE_ML_GROUP_ADDR);
}

int ml_process_m2_kde(struct wpa_state_machine *sm,
			const u8 *key_data, size_t key_data_len)
{
	struct wpa_eapol_ie_parse kde;
	size_t i, j;

	if (wpa_parse_kde_ies(key_data, key_data_len, &kde) != 0 ||
	    !sm->dot11MultiLinkActivated)
		return 0;

	if (!kde.mac_addr) {
		wpa_printf(MSG_INFO, "ML: EAPOL-Key 2/4 no ml addr");
		return -1;
	}

	if (os_memcmp(sm->sta_ml_ie->ml_addr, kde.mac_addr, ETH_ALEN) != 0) {
		wpa_printf(MSG_INFO,
		"ML: EAPOL-Key 2/4 wrong ml addr ["MACSTR"] expect ["MACSTR"]",
			MAC2STR(kde.mac_addr), MAC2STR(sm->sta_ml_ie->ml_addr));
		return -1;
	}

	/* single link doesn't need profile and mlo link kde */
	if (sm->sta_ml_ie->prof_num != kde.mlo_link.num &&
	    sm->sta_ml_ie->prof_num + 1 != kde.mlo_link.num) {
		wpa_printf(MSG_INFO,
			"ML: EAPOL-Key 2/4 mlo link num mismatch (kde=%d, prof=%d)",
			(int)kde.mlo_link.num,
			sm->sta_ml_ie->prof_num);
		return -2;
	}

	wpa_printf(MSG_INFO,
		"ML: EAPOL-Key 2/4 mlo setup link ["MACSTR", link_id=%d]",
		MAC2STR(sm->addr), sm->sta_ml_ie->link_id);

	for (i = 0; i < kde.mlo_link.num; i++) {
		struct wpa_mlo_link_kde *mlo_link =
			(struct wpa_mlo_link_kde *) kde.mlo_link.kdes[i].data;

		wpa_printf(MSG_INFO,
			"ML: EAPOL-Key 2/4 mlo kde link ["MACSTR", link_id=%d]",
			MAC2STR(mlo_link->addr), mlo_link->info & 0xf);

		if (kde.mlo_link.kdes[i].len < 7) {
			wpa_printf(MSG_INFO,
				"ML: EAPOL-Key 2/4 error mlo link len=%d",
				(int)kde.mlo_link.kdes[i].len);
			return -3;
		}

		if (os_memcmp(sm->addr,	mlo_link->addr, ETH_ALEN) == 0 &&
	    		sm->sta_ml_ie->link_id == (mlo_link->info & 0xf))
			continue;

		for (j = 0; j < sm->sta_ml_ie->prof_num; j++) {
			if (os_memcmp(sm->sta_ml_ie->profiles[j].addr,
					mlo_link->addr, ETH_ALEN) == 0 &&
			    sm->sta_ml_ie->profiles[j].link_id ==
					(mlo_link->info & 0xf))
				break;
		}

		if (j == sm->sta_ml_ie->prof_num) {
			wpa_printf(MSG_INFO,
				"ML: EAPOL-Key 2/4 mlo link ["MACSTR", link_id=%d] not matched",
				MAC2STR(mlo_link->addr), mlo_link->info & 0xf);
			return -4;
		}
	}

	return 0;
}

u8* ml_add_m3_kde(struct wpa_state_machine *sm, u8 *pos)
{
	struct wpa_ml_group *ml_group = NULL;
	struct wpa_ml_link *link;
	u8 i, j;

	if (!sm->dot11MultiLinkActivated)
		return pos;

	wpa_printf(MSG_INFO, "ML: Add Mac/Link/GTK into EAPOL-Key 3/4");
	ml_group = STATE_MACHINE_ML_GROUP;
	pos = ml_set_mac_kde(pos, ml_group->ml_addr);

	for (i = 0; i < ml_group->ml_link_num; i++) {
		struct wpa_authenticator *auth;
		u8 *rsn_ie_buf = NULL;
		const u8 *rsne, *rsnxe;
		size_t rsne_len, rsnxe_len;
		u8 found = false;

		link = &ml_group->links[i];

		if (link->link_id == sm->sta_ml_ie->link_id) {
			found = true;
		} else {
			for (j = 0; j < sm->sta_ml_ie->prof_num; j++) {
				if (sm->sta_ml_ie->profiles[j].link_id ==
					link->link_id)
					found = true;
			}
		}

		if (!found)
			continue;

		auth = ((struct hostapd_data *)link->ctx)->wpa_auth;
		rsne = get_ie(auth->wpa_ie, auth->wpa_ie_len, WLAN_EID_RSN);
		rsne_len = rsne ? rsne[1] + 2 : 0;
		rsnxe = get_ie(auth->wpa_ie, auth->wpa_ie_len, WLAN_EID_RSNX);
		rsnxe_len = rsnxe ? rsnxe[1] + 2 : 0;

#ifdef CONFIG_IEEE80211R_AP
		if (wpa_key_mgmt_ft(sm->wpa_key_mgmt) && rsne) {
			int res;

			wpa_hexdump(MSG_DEBUG, "ML: WPA IE before FT processing",
				    rsne, rsne_len);
			/* Add PMKR1Name into RSN IE (PMKID-List) */
			rsn_ie_buf = os_malloc(rsne_len + 2 + 2 + PMKID_LEN);
			if (rsn_ie_buf == NULL) {
				wpa_printf(MSG_INFO, "ML: OOM for FT");
				return pos;
			}
			os_memcpy(rsn_ie_buf, rsne, rsne_len);
			res = wpa_insert_pmkid(rsn_ie_buf, &rsne_len,
					       sm->pmk_r1_name);
			if (res < 0) {
				wpa_printf(MSG_INFO, "ML: insert pmk for FT failed");
				os_free(rsn_ie_buf);
				return pos;
			}

			wpa_hexdump(MSG_DEBUG,
				    "ML: WPA IE after PMKID[PMKR1Name] addition into RSNE",
				    rsn_ie_buf, rsne_len);
			rsne = rsn_ie_buf;
		}
#endif /* CONFIG_IEEE80211R_AP */

		pos = ml_set_ml_link_kde(pos, link->link_id, link->addr,
			rsne, rsne_len, rsnxe, rsnxe_len);
		pos = ml_set_gtk_kde(sm, pos, link);
		pos = ml_set_ieee80211w_kde(sm, pos, link);

		os_free(rsn_ie_buf);
	}

	return pos;
}

int ml_process_m4_kde(struct wpa_state_machine *sm,
		const u8 *key_data, size_t key_data_len)
{
	struct wpa_eapol_ie_parse kde;

	if (wpa_parse_kde_ies(key_data, key_data_len, &kde) != 0 ||
	    !sm->dot11MultiLinkActivated)
		return 0;

	if (os_memcmp(sm->sta_ml_ie->ml_addr, kde.mac_addr, ETH_ALEN) != 0) {
		wpa_printf(MSG_INFO, "ML: EAPOL-Key 4/4 wrong ml addr");
		return -1;
	}

	return 0;
}

u8* ml_set_gtk_kde(struct wpa_state_machine *sm, u8 *pos,
		   struct wpa_ml_link *link)
{
	struct wpa_authenticator *auth =
		((struct hostapd_data *)link->ctx)->wpa_auth;
	struct wpa_group *gsm = auth->group;
	int gtkidx;
	u8 *gtk, dummy_gtk[32], *ori;
	size_t gtk_len;
	struct wpa_auth_config *conf = &sm->wpa_auth->conf;
	u8 hdr[7];

	if (sm->wpa != WPA_VERSION_WPA2)
		return pos;

	gtk = gsm->GTK[gsm->GN - 1];
	gtk_len = gsm->GTK_len;
	if (conf->disable_gtk ||
	    sm->wpa_key_mgmt == WPA_KEY_MGMT_OSEN) {
		/*
		 * Provide unique random GTK to each STA to prevent use
		 * of GTK in the BSS.
		 */
		if (random_get_bytes(dummy_gtk, gtk_len) < 0)
			goto done;
		gtk = dummy_gtk;
	}
	gtkidx = gsm->GN;

	os_memset(hdr, 0, 7);
	hdr[0] = (gtkidx & 0x03) | (link->link_id & 0x0f) << 4;
	ori = pos;
	pos = wpa_add_kde(pos, RSN_KEY_DATA_MLO_GTK, hdr, 7,
			  gtk, gtk_len);
	wpa_hexdump_key(MSG_DEBUG, "ML: GTK KDE", ori, pos - ori);
done:
	return pos;
}

static inline int ml_get_seqnum(struct wpa_authenticator *wpa_auth,
				      const u8 *addr, int idx, u8 *seq)
{
	int res;

	if (!wpa_auth->cb->get_seqnum)
		return -1;
	res = wpa_auth->cb->get_seqnum(wpa_auth->cb_ctx, addr, idx, seq);
	return res;
}

u8* ml_set_ieee80211w_kde(struct wpa_state_machine *sm, u8 *pos,
			  struct wpa_ml_link *link)
{
	struct wpa_authenticator *auth =
		((struct hostapd_data *)link->ctx)->wpa_auth;
	struct wpa_mlo_igtk_kde igtk;
	struct wpa_mlo_bigtk_kde bigtk;
	struct wpa_group *gsm = auth->group;
	u8 rsc[WPA_KEY_RSC_LEN], *ori;
	struct wpa_auth_config *conf = &sm->wpa_auth->conf;
	size_t len = wpa_cipher_key_len(conf->group_mgmt_cipher);

	if (!sm->mgmt_frame_prot)
		return pos;

	igtk.keyid[0] = gsm->GN_igtk;
	igtk.keyid[1] = 0;
	if (gsm->wpa_group_state != WPA_GROUP_SETKEYSDONE ||
	    ml_get_seqnum(sm->wpa_auth, NULL, gsm->GN_igtk, rsc) < 0)
		os_memset(igtk.pn, 0, sizeof(igtk.pn));
	else
		os_memcpy(igtk.pn, rsc, sizeof(igtk.pn));
	os_memcpy(igtk.igtk, gsm->IGTK[gsm->GN_igtk - 4], len);
	if (conf->disable_gtk || sm->wpa_key_mgmt == WPA_KEY_MGMT_OSEN) {
		/*
		 * Provide unique random IGTK to each STA to prevent use of
		 * IGTK in the BSS.
		 */
		if (random_get_bytes(igtk.igtk, len) < 0)
			return pos;
	}
	igtk.info = (link->link_id & 0x0f) << 4;
	ori = pos;
	pos = wpa_add_kde(pos, RSN_KEY_DATA_MLO_IGTK,
			  (const u8 *) &igtk, WPA_MLO_IGTK_KDE_PREFIX_LEN + len,
			  NULL, 0);
	wpa_hexdump_key(MSG_DEBUG, "ML: IGTK KDE", ori, pos - ori);

	if (!conf->beacon_prot)
		return pos;

	bigtk.keyid[0] = gsm->GN_bigtk;
	bigtk.keyid[1] = 0;
	if (gsm->wpa_group_state != WPA_GROUP_SETKEYSDONE ||
	    ml_get_seqnum(sm->wpa_auth, NULL, gsm->GN_bigtk, rsc) < 0)
		os_memset(bigtk.pn, 0, sizeof(bigtk.pn));
	else
		os_memcpy(bigtk.pn, rsc, sizeof(bigtk.pn));
	os_memcpy(bigtk.bigtk, gsm->BIGTK[gsm->GN_bigtk - 6], len);
	if (sm->wpa_key_mgmt == WPA_KEY_MGMT_OSEN) {
		/*
		 * Provide unique random BIGTK to each OSEN STA to prevent use
		 * of BIGTK in the BSS.
		 */
		if (random_get_bytes(bigtk.bigtk, len) < 0)
			return pos;
	}
	bigtk.info = (link->link_id & 0x0f) << 4;
	ori = pos;
	pos = wpa_add_kde(pos, RSN_KEY_DATA_MLO_BIGTK,
			  (const u8 *) &bigtk, WPA_MLO_BIGTK_KDE_PREFIX_LEN + len,
			  NULL, 0);
	wpa_hexdump_key(MSG_DEBUG, "ML: BIGTK KDE", ori, pos - ori);

	return pos;
}

u8* ml_add_1_of_2_kde(struct wpa_state_machine *sm, u8 *pos)
{
	struct wpa_ml_group *ml_group = NULL;
	struct wpa_ml_link *link;
	u8 i;

	if (!sm->dot11MultiLinkActivated)
		return pos;

	wpa_printf(MSG_INFO, "ML: Add GTK/IGTK/BIGTK into EAPOL-Key rekey");
	ml_group = STATE_MACHINE_ML_GROUP;

	for (i = 0; i < ml_group->ml_link_num; i++) {
		link = &ml_group->links[i];
		pos = ml_set_gtk_kde(sm, pos, link);
		pos = ml_set_ieee80211w_kde(sm, pos, link);
	}

	return pos;
}

int ml_rekey_gtk(struct wpa_state_machine *sm, struct wpa_eapol_ie_parse *kde)
{
	if (sm->dot11MultiLinkActivated &&
	    os_memcmp(kde->mac_addr, sm->sta_ml_ie->ml_addr, ETH_ALEN) == 0) {
		struct wpa_ml_group *ml_group;
		size_t i;

		wpa_auth_logger(sm->wpa_auth, sm->addr, LOGGER_INFO,
			"received EAPOL-Key Request for ML GTK rekeying");

		ml_group = STATE_MACHINE_ML_GROUP;
		for (i = 0; i < ml_group->ml_link_num; i++) {
			struct wpa_authenticator *wpa_auth =
				((struct hostapd_data *)ml_group->links[i].ctx)->wpa_auth;

			eloop_cancel_timeout(wpa_rekey_gtk, wpa_auth, NULL);
			wpa_rekey_gtk(wpa_auth,	NULL);
		}
	}
	return 0;
}

#ifdef CONFIG_SAE
int ml_sae_process_auth(struct sae_data *sae, u16 auth_transaction,
	const u8 *ies, size_t ies_len)
{
	struct ieee802_11_elems elems;
	struct wpa_ml_ie_parse ml;

	if (!sae)
		return -1;

	wpa_hexdump(MSG_DEBUG, "ML: SAE Possible elements at the end of the frame",
			    ies, ies_len);

	if (ieee802_11_parse_elems(ies, ies_len, &elems, 1) == ParseFailed) {
		wpa_printf(MSG_DEBUG, "ML: SAE failed to parse elements");
		return -1;
	}

	if (auth_transaction == 1) {
		/* ap or sta uses legacy connection */
		if (is_zero_ether_addr(sae->peer_ml_addr)) {
			if (!elems.ml) {
				wpa_printf(MSG_DEBUG, "ML: SAE disable ml");
				sae->dot11MultiLinkActivated = 0;
			} else {
				if (is_zero_ether_addr(sae->own_ml_addr)) {
					wpa_printf(MSG_DEBUG, "ML: SAE peer should not have ml ie");
					return -1;
				}

				if (ml_parse_ie(elems.ml, elems.ml_len,
						&ml, MSG_INFO) != 0) {
					wpa_printf(MSG_ERROR,
						"ML: SAE commit failed to parse ml ie");
					sae->dot11MultiLinkActivated = 0;
					return -1;
				} else {
					os_memcpy(sae->peer_ml_addr,
						ml.ml_addr, ETH_ALEN);
					sae->dot11MultiLinkActivated = 1;
				}
			}
		/* sta already decide to use ml connection */
		} else {
			if (!elems.ml) {
				wpa_printf(MSG_DEBUG, "ML: SAE peer should have ml ie");
				return -1;
			}
			if (ml_parse_ie(elems.ml, elems.ml_len,
					&ml, MSG_INFO) != 0) {
				wpa_printf(MSG_ERROR,
					"ML: SAE commit failed to parse ml ie");
				return -1;
			} else if (os_memcmp(sae->peer_ml_addr,
				ml.ml_addr, ETH_ALEN) != 0) {
				wpa_printf(MSG_DEBUG,
					"ML: SAE trans = %d, mismatch ML addr (peer="MACSTR", recv="MACSTR")",
					auth_transaction,
					MAC2STR(sae->peer_ml_addr),
					MAC2STR(ml.ml_addr));
				return -1;
			}
		}
	} else if (auth_transaction == 2) {
		if (sae->dot11MultiLinkActivated && !elems.ml) {
			wpa_printf(MSG_ERROR,
				"ML: SAE confirm should have ml ie");
			return -1;
		} else if (!sae->dot11MultiLinkActivated && elems.ml) {
			wpa_printf(MSG_ERROR,
				"ML: SAE confirm should not have ml ie");
			return -1;
		}

		if (elems.ml) {
			if (ml_parse_ie(elems.ml, elems.ml_len,
					&ml, MSG_INFO) != 0) {
				wpa_printf(MSG_ERROR,
					"ML: SAE confirm failed to parse ml ie");
				return -1;
			} else if (os_memcmp(sae->peer_ml_addr,
				ml.ml_addr, ETH_ALEN) != 0) {
				wpa_printf(MSG_DEBUG,
					"ML: SAE trans = %d, mismatch ML addr (peer="MACSTR", recv="MACSTR")",
					auth_transaction,
					MAC2STR(sae->peer_ml_addr),
					MAC2STR(ml.ml_addr));
				return -1;
			}
		}
	} else {
		wpa_printf(MSG_DEBUG,
		       "ML: unexpected SAE authentication transaction %u",
		       auth_transaction);
		return -1;
	}

	return 0;
}

int ml_sae_write_auth(struct sae_data *sae, struct wpabuf *buf)
{
	u16 ctrl = 0;

	if (!sae || !sae->dot11MultiLinkActivated) {
		wpa_printf(MSG_DEBUG, "ML: SAE no mlo ie");
		return 0;
	}

	if (!buf || wpabuf_resize(&buf, 12) != 0) {
		wpa_printf(MSG_DEBUG, "ML: SAE resize failed");
		return 0;
	}

	wpa_printf(MSG_DEBUG, "ML: write ml ie for sae auth");

	wpabuf_put_u8(buf, WLAN_EID_EXTENSION);
	/* extid: 1, common ctrl: 2, common info: 7(len:1, mac:6) */
	wpabuf_put_u8(buf, 10);
	wpabuf_put_u8(buf, WLAN_EID_EXT_MULTI_LINK);

	/* ml common control */
	ML_SET_CTRL_TYPE(ctrl, ML_CTRL_TYPE_BASIC);

	/* A Basic Multi-Link element in an Authentication frame:
	 * the STA shall include the MLD MAC address of the MLD
	 * the STA shall set all subfields in the Presence Bitmap subfield of
	 * the Multi-Link Control field of the element to 0
	 * the STA shall not include the Link Info field of the element.
	 */
	ML_SET_CTRL_PRESENCE(ctrl, 0);
	wpabuf_put_le16(buf, ctrl);

	/* len:1, mac:6 */
	wpabuf_put_u8(buf, 7);

	/* ml mac addr */
	wpabuf_put_data(buf, sae->own_ml_addr, ETH_ALEN);

	return 0;
}
#endif /* CONFIG_SAE */

/* STA */
#ifndef HOSTAPD

const u8 * ml_sm_spa(struct wpa_sm *sm, const u8 *own_addr)
{
	if(sm && own_addr && sm->dot11MultiLinkActivated) {
		if (os_memcmp(own_addr, sm->sta_ml_ie->ml_addr, ETH_ALEN) != 0) {
			wpa_printf(MSG_INFO,
				"ML: SPA[" MACSTR "] use ml addr[" MACSTR "]",
				MAC2STR(own_addr), MAC2STR(sm->sta_ml_ie->ml_addr));
			return sm->sta_ml_ie->ml_addr;
		}
	}

	return own_addr;
}

const u8 * ml_sm_aa(struct wpa_sm *sm, const u8 *bssid)
{
	if(sm && bssid && sm->dot11MultiLinkActivated) {
		if (os_memcmp(bssid, sm->bssid, ETH_ALEN) == 0) {
			if (os_memcmp(bssid, sm->ap_ml_ie->ml_addr, ETH_ALEN) != 0) {
				wpa_printf(MSG_INFO,
					"ML: AA[" MACSTR "] use ml addr[" MACSTR "]",
					MAC2STR(bssid), MAC2STR(sm->ap_ml_ie->ml_addr));
				return sm->ap_ml_ie->ml_addr;
			}
		} else {
			/* for preauth */
			struct wpa_supplicant *wpa_s = sm->ctx->ctx;
			struct wpa_bss *bss = wpa_bss_get_bssid_latest(wpa_s, bssid);

			if (bss && os_memcmp(bssid, bss->aa, ETH_ALEN) != 0) {
				wpa_printf(MSG_INFO,
					"ML: AA[" MACSTR "] use ml addr[" MACSTR "]",
					MAC2STR(bssid), MAC2STR(bss->aa));
				return bss->aa;
			}

		}
	}

	return bssid;
}

int ml_set_assoc_req_ml_ie(struct wpa_sm *sm, const u8 *ies, size_t ies_len)
{
	struct ieee802_11_elems elems;
	struct wpa_ml_ie_parse ml;

	if (sm == NULL)
		return -1;

	wpa_printf(MSG_INFO, "ML: new assoc req");

	if (ieee802_11_parse_elems(ies, ies_len, &elems, 1) == ParseFailed) {
		wpa_printf(MSG_DEBUG, "ML: Failed to parse elements");
		return -1;
	}

	os_free(sm->sta_ml_ie);
	if (!elems.ml) {
		goto err;
	} else {
		if (ml_parse_ie(elems.ml, elems.ml_len, &ml, MSG_INFO) != 0 ||
		    ml.prof_num > ML_MAX_LINK_NUM) {
			goto err;
		} else {
			sm->sta_ml_ie = os_memdup(&ml, sizeof(ml));
			if (sm->sta_ml_ie == NULL)
				goto err;

			sm->prof_num = ml.prof_num;
			sm->dot11MultiLinkActivated = 1;
		}
	}

	return 0;

err:
	wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG, "ML: clearing STA ML IE");
	sm->sta_ml_ie = NULL;
	sm->prof_num = 0;
	sm->dot11MultiLinkActivated = 0;
	return -1;
}

int ml_set_assoc_resp_ml_ie(struct wpa_sm *sm, const u8 *ies, size_t ies_len)
{
	struct ieee802_11_elems elems;
	struct wpa_ml_ie_parse ml;

	if (sm == NULL)
		return -1;

	wpa_printf(MSG_INFO, "ML: new assoc resp");

	if (ieee802_11_parse_elems(ies, ies_len, &elems, 1) == ParseFailed) {
		wpa_printf(MSG_DEBUG, "ML: Failed to parse elements");
		return -1;
	}

	os_free(sm->ap_ml_ie);
	if (!elems.ml) {
		goto err;
	} else {
		if(!sm->dot11MultiLinkActivated)
			goto err;

		if (ml_parse_ie(elems.ml, elems.ml_len, &ml, MSG_INFO) != 0 ||
		    ml.prof_num > ML_MAX_LINK_NUM) {
			goto err;
		} else {
			if (ml.prof_num != sm->prof_num)
				goto err;

			sm->ap_ml_ie = os_memdup(&ml, sizeof(ml));
			if (sm->ap_ml_ie == NULL)
				goto err;
		}
	}

	return 0;

err:
	if (sm->dot11MultiLinkActivated) {
		wpa_dbg(sm->ctx->msg_ctx, MSG_ERROR, "ML: clearing STA ML IE");
		if (sm->sta_ml_ie)
			os_free(sm->sta_ml_ie);
		sm->sta_ml_ie = NULL;
		sm->prof_num = 0;
		sm->dot11MultiLinkActivated = 0;
	}
	wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG, "ML: clearing AP ML IE");
	sm->ap_ml_ie = NULL;

	return -1;
}

size_t ml_add_m2_kde(struct wpa_sm *sm, u8 *pos)
{
	struct wpa_ml_ie_parse *ml = sm->sta_ml_ie;
	size_t i, count = 0;
	u8 *buf = pos;

	if (!sm->dot11MultiLinkActivated)
		return 0;

	wpa_printf(MSG_DEBUG, "ML: Add Mac into EAPOL-Key 2/4");
	pos = ml_set_mac_kde(pos, sm->sta_ml_ie->ml_addr);

	for (i = 0; i < sm->prof_num; i++) {
		struct per_sta_profile *sta = &ml->profiles[i];

		/* normally this won't happen, just in case sta carries
		 * sta profile for main link and it's for single link setup
		 */
		if (sta->link_id == sm->ap_ml_ie->link_id)
			continue;
		count++;
	}

	/* single link doesn't mlo link kde */
	if (count) {
		wpa_printf(MSG_DEBUG, "ML: Add Link into EAPOL-Key 2/4");

		for (i = 0; i < sm->prof_num; i++) {
			struct per_sta_profile *sta = &ml->profiles[i];

			if (sta->link_id == sm->ap_ml_ie->link_id)
				continue;

			pos = ml_set_ml_link_kde(pos, sta->link_id, sta->addr,
				NULL, 0, NULL, 0);
		}
	}

	return pos - buf;
}

static int ml_get_wpa_ie(struct wpa_supplicant *wpa_s, u8 *bssid,
			 struct wpa_ie_parse *wpa)
{
	int ret = 0;
	struct wpa_bss *curr = NULL, *bss;
	const u8 *ie;

	dl_list_for_each(bss, &wpa_s->bss, struct wpa_bss, list) {
		if (os_memcmp(bss->bssid, bssid, ETH_ALEN) != 0)
			continue;
		curr = bss;
		break;
	}

	if (!curr)
		return -1;

	os_memset(wpa, 0, sizeof(*wpa));

	ie = wpa_bss_get_ie(curr, WLAN_EID_RSN);
	if (ie) {
		wpa->ap_rsn_ie = ie;
		wpa->ap_rsn_ie_len = 2 + ie[1];
	}

	ie = wpa_bss_get_ie(curr, WLAN_EID_RSNX);
	if (ie) {
		wpa->ap_rsnxe = ie;
		wpa->ap_rsnxe_len = 2 + ie[1];
	}

	return 0;
}

int ml_validate_m3_kde(struct wpa_sm *sm, const struct wpa_eapol_key *key,
	struct wpa_eapol_ie_parse *ie)
{
	u16 key_info;
	size_t i, j;
	u8 found = 0;

	key_info = WPA_GET_BE16(key->key_info);

	if(!sm->dot11MultiLinkActivated) {
		if (ie->mlo_gtk.num == 0 && ie->mlo_igtk.num == 0 &&
		    ie->mlo_bigtk.num == 0 && ie->mlo_link.num == 0) {
			return 0;
		} else {
			wpa_printf(MSG_INFO, "ML: EAPOL-Key 3/4 inactive but "
				"with ml kde (gtk=%d, igtk=%d, bigtk=%d link=%d)",
				(int)ie->mlo_gtk.num, (int)ie->mlo_igtk.num,
				(int)ie->mlo_bigtk.num, (int)ie->mlo_link.num);
			return -1;
		}
	}

	/* mac addr */
	if (sm->ap_ml_ie &&
	    os_memcmp(sm->ap_ml_ie->ml_addr, ie->mac_addr, ETH_ALEN) != 0) {
		wpa_printf(MSG_INFO, "ML: EAPOL-Key 3/4 wrong ml addr");
		return -1;
	}

	/* mlo link */
	if (ie->mlo_link.num != sm->prof_num + 1) {
		wpa_printf(MSG_INFO,
			"ML: EAPOL-Key 3/4 wrong mlo link num=%d, expect=%d",
			(int)ie->mlo_link.num, sm->prof_num + 1);
		return -1;
	}

	if (ie->rsn_ie) {
		wpa_printf(MSG_INFO,
			"ML: EAPOL-Key 3/4 should not have Basic RSN IE");
		return -1;
	}

	if (ie->rsnxe) {
		wpa_printf(MSG_INFO,
			"ML: EAPOL-Key 3/4 should not have Basic RSNXE IE");
		return -1;
	}

	/* mlo link id & rsne & rsnxe */
	for (i = 0; i < ie->mlo_link.num; i++) {
		struct wpa_mlo_link_kde *mlo_link =
			(struct wpa_mlo_link_kde *) ie->mlo_link.kdes[i].data;
		size_t len = ie->mlo_link.kdes[i].len;
		u8 *rsne = NULL, *rsnxe = NULL;
		u8 rsne_len = 0, rsnxe_len = 0; /* including hdr */
		struct wpa_ie_parse wpa;

		if (ml_get_wpa_ie(sm->ctx->ctx, mlo_link->addr, &wpa) < 0) {
			wpa_printf(MSG_INFO,
				"ML: Could not find AP from "
				"the scan results");
			return -1;
		}

		if (len < sizeof(struct wpa_mlo_link_kde)) {
			wpa_printf(MSG_INFO, "ML: EAPOL-Key 3/4 error mlo link");
			return -1;
		}

		len -= sizeof(struct wpa_mlo_link_kde);
		if (mlo_link->info & BIT(4)) {
			if (len < 2 || len < mlo_link->var[1] + 2) {
				wpa_printf(MSG_INFO, "ML: EAPOL-Key 3/4 wrong mlo rsne len");
				return -1;
			} else {
				rsne = &mlo_link->var[0];
				rsne_len = mlo_link->var[1] + 2;
				len -= rsne_len;
			}
		}

		if (mlo_link->info & BIT(5)) {
			if (len < 2 || len < mlo_link->var[rsne_len + 1] + 2) {
				wpa_printf(MSG_INFO, "ML: EAPOL-Key 3/4 wrong mlo rsnxe len");
				return -1;
			} else {
				rsnxe = &mlo_link->var[rsne_len];
				rsnxe_len = mlo_link->var[rsne_len + 1] + 2;
				len -= rsnxe_len;
			}
		}

		if (len != 0) {
			wpa_printf(MSG_INFO,
				"ML: EAPOL-Key 3/4 (%d/%d) link id=%d wrong data len, rsne_len=%d, rsnxe_len=%d, left=%d",
					(int)i, (int)ie->mlo_link.num, mlo_link->info & 0xf,
					rsne_len, rsnxe_len, (int)len);
			return -1;
		}

		if (sm->ap_ml_ie) {
			found = 0;
			for (j = 0; j < sm->ap_ml_ie->prof_num; j++) {
				if (os_memcmp(sm->ap_ml_ie->profiles[j].addr,
						mlo_link->addr, ETH_ALEN) == 0 &&
				    sm->ap_ml_ie->profiles[j].link_id ==
						(mlo_link->info & 0xf)) {
					found = 1;
					break;
				}
			}

			if (!found) {
				if (os_memcmp(sm->bssid,
					mlo_link->addr, ETH_ALEN) != 0 ||
				    sm->ap_ml_ie->link_id != (mlo_link->info & 0xf)) {
					wpa_printf(MSG_INFO,
						"ML: EAPOL-Key 3/4 wrong link, expect["MACSTR", %d] input["MACSTR", %d]",
						MAC2STR(sm->bssid), sm->ap_ml_ie->link_id,
						MAC2STR(mlo_link->addr), mlo_link->info & 0xf);
					return -1;
				}
			}
		}

		/* mlo without rsn/rsx but beacon does or length not matched */
		if ((!(mlo_link->info & 0xf0) && (wpa.ap_rsn_ie || wpa.ap_rsnxe))) {
			wpa_printf(MSG_INFO, "ML: IE in 3/4 msg does not match "
					     "with IE in Beacon/ProbeResp (no IE?)");
			return -1;
		}

		/* rsne */
		if (rsne && wpa.ap_rsn_ie &&
		    wpa_compare_rsn_ie(wpa_key_mgmt_ft(sm->key_mgmt),
					wpa.ap_rsn_ie, wpa.ap_rsn_ie_len,
					rsne, rsne_len)) {
			wpa_printf(MSG_INFO, "ML: IE in 3/4 msg does not match "
					     "with IE in Beacon/ProbeResp (rsne)");
			return -1;
		}

		if (sm->proto == WPA_PROTO_WPA &&
		    rsne && wpa.ap_rsn_ie == NULL && sm->rsn_enabled) {
			wpa_printf(MSG_INFO, "ML: Possible downgrade attack "
					       "detected - RSN was enabled and RSN IE "
					       "was in msg 3/4, but not in "
					       "Beacon/ProbeResp");
			return -1;
		}

		if (sm->proto == WPA_PROTO_RSN &&
		    ((wpa.ap_rsnxe && !rsnxe) ||
		     (!wpa.ap_rsnxe && rsnxe) ||
		     (wpa.ap_rsnxe && rsnxe &&
		      (wpa.ap_rsnxe_len != rsnxe_len ||
		       os_memcmp(wpa.ap_rsnxe, rsnxe, wpa.ap_rsnxe_len) != 0)))) {
			wpa_printf(MSG_INFO, "ML: RSNXE mismatch between Beacon/ProbeResp and EAPOL-Key msg 3/4");
			wpa_hexdump(MSG_INFO, "RSNXE in Beacon/ProbeResp",
				    wpa.ap_rsnxe, wpa.ap_rsnxe_len);
			wpa_hexdump(MSG_INFO, "RSNXE in EAPOL-Key msg 3/4",
				    rsnxe, rsnxe_len);
			return -1;
		}
	}

	/* mlo gtk */
	if (ie->gtk) {
		wpa_printf(MSG_INFO,
			"ML: EAPOL-Key 3/4 should not have Basic GTK IE");
		return -1;
	}

	if (ie->mlo_gtk.num > 0 && !(key_info & WPA_KEY_INFO_ENCR_KEY_DATA)) {
		wpa_printf(MSG_INFO,
			"ML: EAPOL-Key 3/4 MLO GTK IE in unencrypted key data");
		return -1;
	}


	for (i = 0; i < ie->mlo_gtk.num; i++) {
		struct wpa_mlo_gtk_kde *mlo_gtk =
			(struct wpa_mlo_gtk_kde *) ie->mlo_gtk.kdes[i].data;
		u8 link_id = (mlo_gtk->info & 0xf0) >> 4;

		if (sm->ap_ml_ie) {
			found = 0;
			for (j = 0; j < sm->ap_ml_ie->prof_num; j++) {
				if (link_id == sm->ap_ml_ie->profiles[j].link_id) {
					found = 1;
					break;
				}
			}
			if (!found) {
				if (link_id != sm->ap_ml_ie->link_id) {
					wpa_printf(MSG_INFO, "ML: EAPOL-Key 3/4 wrong gtk link id, expect=%d input=%d",
						   sm->ap_ml_ie->link_id, link_id);
					return -1;
				}
			}
		}
	}


	/* mlo igtk */
	if (ie->igtk) {
		wpa_printf(MSG_INFO,
			"ML: EAPOL-Key 3/4 should not have Basic IGTK IE");
		return -1;
	}

	if (ie->mlo_igtk.num > 0 && !(key_info & WPA_KEY_INFO_ENCR_KEY_DATA)) {
		wpa_printf(MSG_INFO,
			"ML: EAPOL-Key 3/4 MLO IGTK IE in unencrypted key data");
		return -1;
	}

	for (i = 0; i < ie->mlo_igtk.num; i++) {
		struct wpa_mlo_igtk_kde *mlo_igtk =
			(struct wpa_mlo_igtk_kde *) ie->mlo_igtk.kdes[i].data;
		u8 link_id = (mlo_igtk->info & 0xf0) >> 4;
		size_t len = ie->mlo_igtk.kdes[i].len;

		if (sm->ap_ml_ie) {
			found = 0;
			for (j = 0; j < sm->ap_ml_ie->prof_num; j++) {
				if (link_id == sm->ap_ml_ie->profiles[j].link_id) {
					found = 1;
					break;
				}
			}
			if (!found) {
				if (link_id != sm->ap_ml_ie->link_id) {
					wpa_printf(MSG_INFO, "ML: EAPOL-Key 3/4 wrong igtk link id, expect=%d input=%d",
						   sm->ap_ml_ie->link_id, link_id);
					return -1;
				}
			}
		}

		if (sm->mgmt_group_cipher != WPA_CIPHER_GTK_NOT_USED &&
		    wpa_cipher_valid_mgmt_group(sm->mgmt_group_cipher) &&
		    len != WPA_MLO_IGTK_KDE_PREFIX_LEN +
		    (unsigned int) wpa_cipher_key_len(sm->mgmt_group_cipher)) {
			wpa_printf(MSG_INFO, "ML: Invalid IGTK KDE length %lu",
				(unsigned long) len);
			return -1;
		}
	}

	/* mlo bigtk */
	if (ie->bigtk) {
		wpa_printf(MSG_INFO,
			"ML: EAPOL-Key 3/4 should not have Basic BIGTK IE");
		return -1;
	}

	if (ie->mlo_bigtk.num > 0 && !sm->beacon_prot) {
		wpa_printf(MSG_INFO,
			"ML: EAPOL-Key 3/4 MLO BIGTK IE in unencrypted key data");
		return -1;
	}

	for (i = 0; i < ie->mlo_bigtk.num; i++) {
		struct wpa_mlo_bigtk_kde *mlo_bigtk =
			(struct wpa_mlo_bigtk_kde *) ie->mlo_bigtk.kdes[i].data;
		u8 link_id = (mlo_bigtk->info & 0xf0) >> 4;
		size_t len = ie->mlo_bigtk.kdes[i].len;

		if (sm->ap_ml_ie) {
			found = 0;
			for (j = 0; j < sm->ap_ml_ie->prof_num; j++) {
				if (link_id == sm->ap_ml_ie->profiles[j].link_id) {
					found = 1;
					break;
				}
			}
			if (!found) {
				if (link_id != sm->ap_ml_ie->link_id) {
					wpa_printf(MSG_INFO, "ML: EAPOL-Key 3/4 wrong bigtk link id, expect=%d input=%d",
						   sm->ap_ml_ie->link_id, link_id);
					return -1;
				}
			}
		}
		if (sm->mgmt_group_cipher != WPA_CIPHER_GTK_NOT_USED &&
		    wpa_cipher_valid_mgmt_group(sm->mgmt_group_cipher) &&
		    len != WPA_MLO_BIGTK_KDE_PREFIX_LEN +
		    (unsigned int) wpa_cipher_key_len(sm->mgmt_group_cipher)) {
			wpa_printf(MSG_INFO, "ML: Invalid BIGTK KDE length %lu",
				(unsigned long) len);
			return -1;
		}
	}

	return 0;
}

static int ml_rsc_relaxation(const struct wpa_sm *sm, const u8 *rsc)
{
	int rsclen;

	if (!sm->wpa_rsc_relaxation)
		return 0;

	rsclen = wpa_cipher_rsc_len(sm->group_cipher);

	/*
	 * Try to detect RSC (endian) corruption issue where the AP sends
	 * the RSC bytes in EAPOL-Key message in the wrong order, both if
	 * it's actually a 6-byte field (as it should be) and if it treats
	 * it as an 8-byte field.
	 * An AP model known to have this bug is the Sapido RB-1632.
	 */
	if (rsclen == 6 && ((rsc[5] && !rsc[0]) || rsc[6] || rsc[7])) {
		wpa_msg(sm->ctx->msg_ctx, MSG_WARNING,
			"RSC %02x%02x%02x%02x%02x%02x%02x%02x is likely bogus, using 0",
			rsc[0], rsc[1], rsc[2], rsc[3],
			rsc[4], rsc[5], rsc[6], rsc[7]);

		return 1;
	}

	return 0;
}


static int ml_gtk_tx_bit_workaround(const struct wpa_sm *sm,
						int tx)
{
	if (tx && sm->pairwise_cipher != WPA_CIPHER_NONE) {
		/* Ignore Tx bit for GTK if a pairwise key is used. One AP
		 * seemed to set this bit (incorrectly, since Tx is only when
		 * doing Group Key only APs) and without this workaround, the
		 * data connection does not work because wpa_supplicant
		 * configured non-zero keyidx to be used for unicast. */
		wpa_msg(sm->ctx->msg_ctx, MSG_INFO,
			"ML: Tx bit set for GTK, but pairwise "
			"keys are used - ignore Tx bit");
		return 0;
	}
	return tx;
}

static int ml_check_group_cipher(struct wpa_sm *sm,
					     int group_cipher,
					     int keylen, int maxkeylen,
					     int *key_rsc_len,
					     enum wpa_alg *alg)
{
	int klen;

	*alg = wpa_cipher_to_alg(group_cipher);
	if (*alg == WPA_ALG_NONE) {
		wpa_msg(sm->ctx->msg_ctx, MSG_WARNING,
			"ML: Unsupported Group Cipher %d",
			group_cipher);
		return -1;
	}
	*key_rsc_len = wpa_cipher_rsc_len(group_cipher);

	klen = wpa_cipher_key_len(group_cipher);
	if (keylen != klen || maxkeylen < klen) {
		wpa_msg(sm->ctx->msg_ctx, MSG_WARNING,
			"ML: Unsupported %s Group Cipher key length %d (%d)",
			wpa_cipher_txt(group_cipher), keylen, maxkeylen);
		return -1;
	}
	return 0;
}

static int ml_install_gtk(struct wpa_sm *sm,
			const struct wpa_eapol_key *key,
			struct wpa_eapol_ie_parse *ie, u8 wnm_sleep)
{
	static const u8 null_rsc[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	struct wpa_supplicant *wpa_s = sm->ctx->ctx;
	struct ml_gtk_data data, *gd = &data;
	const u8 *key_rsc, *gtk;
	size_t gtk_len, i;
	char cmd[32], buf[256];
	u8 gtk_buf[32], *_gtk;

	for (i = 0; i < ie->mlo_gtk.num; i++) {
		gtk = ie->mlo_gtk.kdes[i].data;
		gtk_len = ie->mlo_gtk.kdes[i].len;

		os_memset(gd, 0, sizeof(*gd));
		wpa_hexdump_key(MSG_DEBUG, "ML: received GTK in pairwise handshake",
				gtk, gtk_len);

		if (gtk_len < WPA_MLO_GTK_KDE_PREFIX_LEN ||
		    gtk_len - WPA_MLO_GTK_KDE_PREFIX_LEN > sizeof(gd->gtk))
			return -1;

		gd->link_id = (gtk[0] & 0xf0) >> 4;
		gd->keyidx = gtk[0] & 0x3;
		gd->tx = ml_gtk_tx_bit_workaround(sm, !!(gtk[0] & BIT(2)));
		gtk += WPA_MLO_GTK_KDE_PREFIX_LEN ;
		gtk_len -= WPA_MLO_GTK_KDE_PREFIX_LEN;

		os_memcpy(gd->gtk, gtk, gtk_len);
		gd->gtk_len = gtk_len;

		key_rsc = key->key_rsc;
		if (ml_rsc_relaxation(sm, key->key_rsc))
			key_rsc = null_rsc;


		if (ml_check_group_cipher(sm, sm->group_cipher,
				       gtk_len, gtk_len,
				       &gd->key_rsc_len, &gd->alg)) {
			wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG,
				"ML: Check group cipher failed");
			forced_memzero(gd, sizeof(*gd));
			return -1;
		}

		_gtk = gd->gtk;

		/* Detect possible key reinstallation */
		if ((sm->ml_gtk.gtks[i].gtk_len == (size_t) gd->gtk_len &&
		     os_memcmp(sm->ml_gtk.gtks[i].gtk, gd->gtk, sm->ml_gtk.gtks[i].gtk_len) == 0) ||
		    (sm->ml_gtk_wnm_sleep.gtks[i].gtk_len == (size_t) gd->gtk_len &&
		     os_memcmp(sm->ml_gtk_wnm_sleep.gtks[i].gtk, gd->gtk,
			       sm->ml_gtk_wnm_sleep.gtks[i].gtk_len) == 0)) {
			wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG,
				"ML: Not reinstalling already in-use GTK to the driver (keyidx=%d tx=%d len=%d)",
				gd->keyidx, gd->tx, gd->gtk_len);
			continue;
		}

		wpa_hexdump_key(MSG_DEBUG, "ML: Group Key", gd->gtk, gd->gtk_len);
		wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG,
			"ML: Installing GTK to the driver (keyidx=%d tx=%d len=%d)",
			gd->keyidx, gd->tx, gd->gtk_len);
		wpa_hexdump(MSG_DEBUG, "WPA: RSC", key_rsc, gd->key_rsc_len);
		if (sm->group_cipher == WPA_CIPHER_TKIP) {
			/* Swap Tx/Rx keys for Michael MIC */
			os_memcpy(gtk_buf, gd->gtk, 16);
			os_memcpy(gtk_buf + 16, gd->gtk + 24, 8);
			os_memcpy(gtk_buf + 24, gd->gtk + 16, 8);
			_gtk = gtk_buf;
		}

		// TODO: remove this when kernel is ready
		os_snprintf(cmd, sizeof(cmd), CMD_PRESET_LINKID " %d", gd->link_id);
		wpa_drv_driver_cmd(wpa_s, cmd, buf, sizeof(buf));

		if (sm->pairwise_cipher == WPA_CIPHER_NONE) {
			if (wpa_sm_set_key(sm, gd->alg, NULL,
					   gd->keyidx, 1, key_rsc, gd->key_rsc_len,
					   _gtk, gd->gtk_len,
					   KEY_FLAG_GROUP_RX_TX_DEFAULT) < 0) {
				wpa_msg(sm->ctx->msg_ctx, MSG_WARNING,
					"ML: Failed to set GTK to the driver "
					"(Group only)");
				forced_memzero(gtk_buf, sizeof(gtk_buf));
				return -1;
			}
		} else if (wpa_sm_set_key(sm, gd->alg, broadcast_ether_addr,
					  gd->keyidx, gd->tx, key_rsc, gd->key_rsc_len,
					  _gtk, gd->gtk_len, KEY_FLAG_GROUP_RX) < 0) {
			wpa_msg(sm->ctx->msg_ctx, MSG_WARNING,
				"ML: Failed to set GTK to "
				"the driver (alg=%d keylen=%d keyidx=%d)",
				gd->alg, gd->gtk_len, gd->keyidx);
			forced_memzero(gtk_buf, sizeof(gtk_buf));
			return -1;
		}

		if (wnm_sleep) {
			sm->ml_gtk_wnm_sleep.gtks[i].gtk_len = gd->gtk_len;
			os_memcpy(sm->ml_gtk_wnm_sleep.gtks[i].gtk, gd->gtk,
				  sm->ml_gtk_wnm_sleep.gtks[i].gtk_len);
		} else {
			sm->ml_gtk.gtks[i].gtk_len = gd->gtk_len;
			os_memcpy(sm->ml_gtk.gtks[i].gtk, gd->gtk,
				  sm->ml_gtk.gtks[i].gtk_len);
		}

		forced_memzero(gd, sizeof(*gd));
		forced_memzero(gtk_buf, sizeof(gtk_buf));
	}

	return 0;
}

static int ml_install_igtk(struct wpa_sm *sm, const struct wpa_eapol_key *key,
		struct wpa_eapol_ie_parse *ie, u8 wnm_sleep)
{
	struct wpa_supplicant *wpa_s = sm->ctx->ctx;
	char cmd[32], buf[256];
	size_t i;
	size_t len = wpa_cipher_key_len(sm->mgmt_group_cipher);
	struct wpa_mlo_igtk_kde *igtk;
	size_t igtk_len;
	u16 keyidx;
	u8 link_id;

	for (i = 0; i < ie->mlo_igtk.num; i++) {
		igtk = (struct wpa_mlo_igtk_kde *) ie->mlo_igtk.kdes[i].data;
		igtk_len = ie->mlo_igtk.kdes[i].len;
		keyidx = WPA_GET_LE16(igtk->keyid);
		link_id = (igtk->info & 0xf0) >> 4;

		if (igtk_len != WPA_MLO_IGTK_KDE_PREFIX_LEN + len)
			return -1;

		/* Detect possible key reinstallation */
		if ((sm->ml_igtk.igtks[i].igtk_len == len &&
		     os_memcmp(sm->ml_igtk.igtks[i].igtk, igtk->igtk,
			       sm->ml_igtk.igtks[i].igtk_len) == 0) ||
		    (sm->ml_igtk_wnm_sleep.igtks[i].igtk_len == len &&
		     os_memcmp(sm->ml_igtk_wnm_sleep.igtks[i].igtk, igtk->igtk,
			       sm->ml_igtk_wnm_sleep.igtks[i].igtk_len) == 0)){
			wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG,
				"ML: Not reinstalling already in-use IGTK to the driver (keyidx=%d)",
				keyidx);
			continue;
		}

		wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG,
			"ML: IGTK keyid %d pn " COMPACT_MACSTR,
			keyidx, MAC2STR(igtk->pn));
		wpa_hexdump_key(MSG_DEBUG, "ML: IGTK", igtk->igtk, len);
		if (keyidx > 4095) {
			wpa_msg(sm->ctx->msg_ctx, MSG_WARNING,
				"ML: Invalid IGTK KeyID %d", keyidx);
			return -1;
		}


		// TODO: remove this when kernel is ready
		os_snprintf(cmd, sizeof(cmd), CMD_PRESET_LINKID " %d", link_id);
		wpa_drv_driver_cmd(wpa_s, cmd, buf, sizeof(buf));

		if (wpa_sm_set_key(sm, wpa_cipher_to_alg(sm->mgmt_group_cipher),
				   broadcast_ether_addr,
				   keyidx, 0, igtk->pn, sizeof(igtk->pn),
				   igtk->igtk, len, KEY_FLAG_GROUP_RX) < 0) {
			if (keyidx == 0x0400 || keyidx == 0x0500) {
				/* Assume the AP has broken PMF implementation since it
				 * seems to have swapped the KeyID bytes. The AP cannot
				 * be trusted to implement BIP correctly or provide a
				 * valid IGTK, so do not try to configure this key with
				 * swapped KeyID bytes. Instead, continue without
				 * configuring the IGTK so that the driver can drop any
				 * received group-addressed robust management frames due
				 * to missing keys.
				 *
				 * Normally, this error behavior would result in us
				 * disconnecting, but there are number of deployed APs
				 * with this broken behavior, so as an interoperability
				 * workaround, allow the connection to proceed. */
				wpa_msg(sm->ctx->msg_ctx, MSG_INFO,
					"ML: Ignore IGTK configuration error due to invalid IGTK KeyID byte order");
			} else {
				wpa_msg(sm->ctx->msg_ctx, MSG_WARNING,
					"ML: Failed to configure IGTK to the driver");
				return -1;
			}
		}

		if (wnm_sleep) {
			sm->ml_igtk_wnm_sleep.igtks[i].igtk_len = len;
			os_memcpy(sm->ml_igtk_wnm_sleep.igtks[i].igtk, igtk->igtk, len);
		} else {
			sm->ml_igtk.igtks[i].igtk_len = len;
			os_memcpy(sm->ml_igtk.igtks[i].igtk, igtk->igtk, len);
		}
	}

	return 0;
}

static int ml_install_bigtk(struct wpa_sm *sm, const struct wpa_eapol_key *key,
		struct wpa_eapol_ie_parse *ie, u8 wnm_sleep)
{
	struct wpa_supplicant *wpa_s = sm->ctx->ctx;
	char cmd[32], buf[256];
	size_t i;
	size_t len = wpa_cipher_key_len(sm->mgmt_group_cipher);
	struct wpa_mlo_bigtk_kde *bigtk;
	size_t bigtk_len;
	u16 keyidx;
	u8 link_id;

	for (i = 0; i < ie->mlo_bigtk.num; i++) {
		bigtk = (struct wpa_mlo_bigtk_kde *) ie->mlo_bigtk.kdes[i].data;
		bigtk_len = ie->mlo_igtk.kdes[i].len;
		keyidx = WPA_GET_LE16(bigtk->keyid);
		link_id = (bigtk->info & 0xf0) >> 4;

		if (bigtk_len != WPA_MLO_BIGTK_KDE_PREFIX_LEN + len)
			return -1;

		/* Detect possible key reinstallation */
		if ((sm->ml_bigtk.bigtks[i].bigtk_len == len &&
		     os_memcmp(sm->ml_bigtk.bigtks[i].bigtk, bigtk->bigtk,
			       sm->ml_bigtk.bigtks[i].bigtk_len) == 0) ||
		    (sm->ml_bigtk_wnm_sleep.bigtks[i].bigtk_len == len &&
		     os_memcmp(sm->ml_bigtk_wnm_sleep.bigtks[i].bigtk, bigtk->bigtk,
			       sm->ml_bigtk_wnm_sleep.bigtks[i].bigtk_len) == 0)) {
			wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG,
				"ML: Not reinstalling already in-use BIGTK to the driver (keyidx=%d)",
				keyidx);
			return  0;
		}

		wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG,
			"ML: BIGTK keyid %d pn " COMPACT_MACSTR,
			keyidx, MAC2STR(bigtk->pn));
		wpa_hexdump_key(MSG_DEBUG, "ML: BIGTK", bigtk->bigtk, len);
		if (keyidx < 6 || keyidx > 7) {
			wpa_msg(sm->ctx->msg_ctx, MSG_WARNING,
				"ML: Invalid BIGTK KeyID %d", keyidx);
			return -1;
		}

		// TODO: remove this when kernel is ready
		os_snprintf(cmd, sizeof(cmd), CMD_PRESET_LINKID " %d", link_id);
		wpa_drv_driver_cmd(wpa_s, cmd, buf, sizeof(buf));

		if (wpa_sm_set_key(sm, wpa_cipher_to_alg(sm->mgmt_group_cipher),
				   broadcast_ether_addr,
				   keyidx, 0, bigtk->pn, sizeof(bigtk->pn),
				   bigtk->bigtk, len, KEY_FLAG_GROUP_RX) < 0) {
			wpa_msg(sm->ctx->msg_ctx, MSG_WARNING,
				"WPA: Failed to configure BIGTK to the driver");
			return -1;
		}

		if (wnm_sleep) {
			sm->ml_bigtk_wnm_sleep.bigtks[i].bigtk_len = len;
			os_memcpy(sm->ml_bigtk_wnm_sleep.bigtks[i].bigtk, bigtk->bigtk,
				  sm->ml_bigtk_wnm_sleep.bigtks[i].bigtk_len);
		} else {
			sm->ml_bigtk.bigtks[i].bigtk_len = len;
			os_memcpy(sm->ml_bigtk.bigtks[i].bigtk, bigtk->bigtk,
				  sm->ml_bigtk.bigtks[i].bigtk_len);
		}
	}

	return 0;
}

int ml_process_m1_kde(struct wpa_sm *sm,
	const unsigned char *src_addr, struct wpa_eapol_ie_parse *ie)
{
	if (sm->dot11MultiLinkActivated) {
		if (os_memcmp(sm->bssid, src_addr, ETH_ALEN) != 0 &&
		    os_memcmp(sm->ap_ml_ie->ml_addr, src_addr, ETH_ALEN) != 0) {
			wpa_printf(MSG_INFO,
				"ML: EAPOL-Key 1/4 from wrong link, src="
				MACSTR " expected=" MACSTR " AA[" MACSTR "]",
				MAC2STR(src_addr), MAC2STR(sm->bssid),
				MAC2STR(sm->ap_ml_ie->ml_addr));
			return -1;
		}

		if (ie->mac_addr) {
			wpa_hexdump(MSG_DEBUG, "ML: MAC from "
			    "Authenticator", ie->mac_addr, ie->mac_addr_len);
			if (os_memcmp(ie->mac_addr, sm->ap_ml_ie->ml_addr, ETH_ALEN) != 0) {
				wpa_dbg(sm->ctx->msg_ctx, MSG_ERROR,
				"ML: ML MAC Addr from M1 is different");
				return -1;
			}
		} else {
			wpa_dbg(sm->ctx->msg_ctx, MSG_ERROR,
				"ML: ML MAC Addr should be in M1");
			return -1;
		}
	}
	return 0;
}

int ml_process_m3_kde(struct wpa_sm *sm, const struct wpa_eapol_key *key,
	struct wpa_eapol_ie_parse *ie)
{
	u16 key_info;
	size_t i, j;
	u8 found = 0;

	key_info = WPA_GET_BE16(key->key_info);

	if(!sm->dot11MultiLinkActivated)
		return 0;

	/* mlo gtk */
	if (sm->group_cipher == WPA_CIPHER_GTK_NOT_USED) {
		/* No GTK to be set to the driver */
	} else if (ie->mlo_gtk.num > 0 &&
		ml_install_gtk(sm, key, ie, 0) < 0) {
		    wpa_msg(sm->ctx->msg_ctx, MSG_INFO,
			    "ML: Failed to configure GTK");
		return -1;
	}

	if (!wpa_cipher_valid_mgmt_group(sm->mgmt_group_cipher) ||
	    sm->mgmt_group_cipher == WPA_CIPHER_GTK_NOT_USED) {
		/* No IGTK to be set to the driver */
	} else if (ie->mlo_igtk.num > 0 &&
		ml_install_igtk(sm, key, ie, 0) < 0) {
		    wpa_msg(sm->ctx->msg_ctx, MSG_INFO,
			    "ML: Failed to configure IGTK");
		return -1;
	}

	if (!sm->beacon_prot) {
		/* No BIGTK to be set to the driver */
	} else if (ie->mlo_bigtk.num > 0 &&
		ml_install_bigtk(sm, key, ie, 0) < 0) {
		    wpa_msg(sm->ctx->msg_ctx, MSG_INFO,
			    "ML: Failed to configure BIGTK");
		return -1;
	}

	return 0;
}

int ml_process_1_of_2(struct wpa_sm *sm, const struct wpa_eapol_key *key,
	const u8 *key_data, size_t key_data_len, u16 key_info)
{
	struct wpa_eapol_ie_parse parse;
	struct wpa_eapol_ie_parse *ie = &parse;

	if(!sm->dot11MultiLinkActivated)
		return 0;

	wpa_hexdump(MSG_DEBUG, "ML: Group 1/2 IE KeyData", key_data, key_data_len);
	if (wpa_supplicant_parse_ies(key_data, key_data_len, ie) < 0)
		return -1;

	/* mlo gtk */
	if (sm->group_cipher == WPA_CIPHER_GTK_NOT_USED) {
		/* No GTK to be set to the driver */
	} else if (ie->mlo_gtk.num > 0 &&
		ml_install_gtk(sm, key, ie, 0) < 0) {
		    wpa_msg(sm->ctx->msg_ctx, MSG_INFO,
			    "ML: Failed to configure GTK");
		return -1;
	}

	if (!wpa_cipher_valid_mgmt_group(sm->mgmt_group_cipher) ||
	    sm->mgmt_group_cipher == WPA_CIPHER_GTK_NOT_USED) {
		/* No IGTK to be set to the driver */
	} else if (ie->mlo_igtk.num > 0 &&
		ml_install_igtk(sm, key, ie, 0) < 0) {
		    wpa_msg(sm->ctx->msg_ctx, MSG_INFO,
			    "ML: Failed to configure IGTK");
		return -1;
	}

	if (!sm->beacon_prot) {
		/* No BIGTK to be set to the driver */
	} else if (ie->mlo_bigtk.num > 0 &&
		ml_install_bigtk(sm, key, ie, 0) < 0) {
		    wpa_msg(sm->ctx->msg_ctx, MSG_INFO,
			    "ML: Failed to configure BIGTK");
		return -1;
	}

	return 0;
}

size_t ml_add_key_request_kde(struct wpa_sm *sm, u8 *pos)
{
	struct wpa_ml_ie_parse *ml = sm->sta_ml_ie;
	u8 i;

	if (!sm->dot11MultiLinkActivated)
		return 0;

	wpa_printf(MSG_DEBUG, "ML: Add Mac into Key Request");
	return ml_set_mac_kde(pos, sm->sta_ml_ie->ml_addr) - pos;
}

size_t ml_add_m4_kde(struct wpa_sm *sm, u8 *pos)
{
	struct wpa_ml_ie_parse *ml = sm->sta_ml_ie;
	u8 i;

	if (!sm->dot11MultiLinkActivated)
		return 0;

	wpa_printf(MSG_DEBUG, "ML: Add Mac into EAPOL-Key 4/4");
	return ml_set_mac_kde(pos, sm->sta_ml_ie->ml_addr) - pos;
}

size_t ml_add_2_of_2_kde(struct wpa_sm *sm, u8 *pos)
{
	struct wpa_ml_ie_parse *ml = sm->sta_ml_ie;
	u8 i;

	if (!sm->dot11MultiLinkActivated)
		return 0;

	wpa_printf(MSG_DEBUG, "ML: Add Mac into EAPOL-Key Group 2/2");
	return ml_set_mac_kde(pos, sm->sta_ml_ie->ml_addr) - pos;
}

#ifdef CONFIG_IEEE80211R

int ml_ft_process_gtk_subelem_impl(struct wpa_sm *sm, const u8 *gtk_elem,
				      size_t gtk_elem_len)
{
	struct wpa_supplicant *wpa_s = sm->ctx->ctx;
	char cmd[32], buf[256];
	u8 link_id;
	u8 gtk[32];
	int keyidx;
	enum wpa_alg alg;
	size_t gtk_len, keylen, rsc_len;
	const u8 *kek;
	size_t kek_len;

	if (wpa_key_mgmt_fils(sm->key_mgmt)) {
		kek = sm->ptk.kek2;
		kek_len = sm->ptk.kek2_len;
	} else {
		kek = sm->ptk.kek;
		kek_len = sm->ptk.kek_len;
	}

	if (gtk_elem == NULL) {
		wpa_printf(MSG_DEBUG, "ML: No GTK included in FTIE");
		return 0;
	}

	wpa_hexdump_key(MSG_DEBUG, "ML: Received GTK in Reassoc Resp",
			gtk_elem, gtk_elem_len);

	if (gtk_elem_len < 12 + 24 || (gtk_elem_len - 12) % 8 ||
	    gtk_elem_len - 20 > sizeof(gtk)) {
		wpa_printf(MSG_DEBUG, "ML: Invalid GTK sub-elem "
			   "length %lu", (unsigned long) gtk_elem_len);
		return -1;
	}
	gtk_len = gtk_elem_len - 20;
	if (aes_unwrap(kek, kek_len, gtk_len / 8, gtk_elem + 12, gtk)) {
		wpa_printf(MSG_WARNING, "ML: AES unwrap failed - could not "
			   "decrypt GTK");
		return -1;
	}

	keylen = wpa_cipher_key_len(sm->group_cipher);
	rsc_len = wpa_cipher_rsc_len(sm->group_cipher);
	alg = wpa_cipher_to_alg(sm->group_cipher);
	if (alg == WPA_ALG_NONE) {
		wpa_printf(MSG_WARNING, "ML: Unsupported Group Cipher %d",
			   sm->group_cipher);
		return -1;
	}

	if (gtk_len < keylen) {
		wpa_printf(MSG_DEBUG, "ML: Too short GTK in FTIE");
		return -1;
	}

	/* Key Info[2] | Link Info[1] | Key Length[1] | RSC[8] | Key[5..32]. */

	keyidx = WPA_GET_LE16(gtk_elem) & 0x03;
	link_id = gtk_elem[2] >> 4;

	if (gtk_elem[3] != keylen) {
		wpa_printf(MSG_DEBUG, "ML: GTK length mismatch: received %d "
			   "negotiated %lu",
			   gtk_elem[3], (unsigned long) keylen);
		return -1;
	}

	wpa_hexdump_key(MSG_DEBUG, "ML: GTK from Reassoc Resp", gtk, keylen);
	if (sm->group_cipher == WPA_CIPHER_TKIP) {
		/* Swap Tx/Rx keys for Michael MIC */
		u8 tmp[8];
		os_memcpy(tmp, gtk + 16, 8);
		os_memcpy(gtk + 16, gtk + 24, 8);
		os_memcpy(gtk + 24, tmp, 8);
	}

	wpa_printf(MSG_DEBUG, "ML: Set Link %d GTK", link_id);

	// TODO: remove this when kernel is ready
	os_snprintf(cmd, sizeof(cmd), CMD_PRESET_LINKID " %d", link_id);
	wpa_drv_driver_cmd(wpa_s, cmd, buf, sizeof(buf));

	if (wpa_sm_set_key(sm, alg, broadcast_ether_addr, keyidx, 0,
			   gtk_elem + 3, rsc_len, gtk, keylen,
			   KEY_FLAG_GROUP_RX) < 0) {
		wpa_printf(MSG_WARNING, "ML: Failed to set GTK to the "
			   "driver.");
		return -1;
	}

	return 0;
}

int ml_ft_process_gtk_subelem(struct wpa_sm *sm, const u8 **elem,
			      size_t *len, size_t num)
{
	u8 i;

	if (!sm->dot11MultiLinkActivated)
		return 0;

	for (i = 0; i < num; i++) {
		if (ml_ft_process_gtk_subelem_impl(sm, elem[i], len[i]) < 0) {
			wpa_printf(MSG_INFO, "ML: %s i=%d failed", __func__, i);
			return -1;
		}
	}

	return 0;
}

int ml_ft_process_igtk_subelem_impl(struct wpa_sm *sm, const u8 *igtk_elem,
				      size_t igtk_elem_len)
{
	struct wpa_supplicant *wpa_s = sm->ctx->ctx;
	char cmd[32], buf[256];
	u8 link_id;
	u8 igtk[WPA_IGTK_MAX_LEN];
	size_t igtk_len;
	u16 keyidx;
	const u8 *kek;
	size_t kek_len;

	if (wpa_key_mgmt_fils(sm->key_mgmt)) {
		kek = sm->ptk.kek2;
		kek_len = sm->ptk.kek2_len;
	} else {
		kek = sm->ptk.kek;
		kek_len = sm->ptk.kek_len;
	}

	if (sm->mgmt_group_cipher != WPA_CIPHER_AES_128_CMAC &&
	    sm->mgmt_group_cipher != WPA_CIPHER_BIP_GMAC_128 &&
	    sm->mgmt_group_cipher != WPA_CIPHER_BIP_GMAC_256 &&
	    sm->mgmt_group_cipher != WPA_CIPHER_BIP_CMAC_256)
		return 0;

	if (igtk_elem == NULL) {
		wpa_printf(MSG_DEBUG, "ML: No IGTK included in FTIE");
		return 0;
	}

	wpa_hexdump_key(MSG_DEBUG, "ML: Received IGTK in Reassoc Resp",
			igtk_elem, igtk_elem_len);

	igtk_len = wpa_cipher_key_len(sm->mgmt_group_cipher);
	if (igtk_elem_len != 2 + 6 + + 1 + 1 + igtk_len + 8) {
		wpa_printf(MSG_DEBUG, "ML: Invalid IGTK sub-elem "
			   "length %lu", (unsigned long) igtk_elem_len);
		return -1;
	}
	if (igtk_elem[9] != igtk_len) {
		wpa_printf(MSG_DEBUG, "ML: Invalid IGTK sub-elem Key Length "
			   "%d", igtk_elem[9]);
		return -1;
	}

	if (aes_unwrap(kek, kek_len, igtk_len / 8, igtk_elem + 10, igtk)) {
		wpa_printf(MSG_WARNING, "ML: AES unwrap failed - could not "
			   "decrypt IGTK");
		return -1;
	}

	/* KeyID[2] | IPN[6] | Link Info[1] | Key Length[1] | Key[16+8] */

	keyidx = WPA_GET_LE16(igtk_elem);
	link_id = igtk_elem[8] >> 4;

	wpa_hexdump_key(MSG_DEBUG, "FT: IGTK from Reassoc Resp", igtk,
			igtk_len);

	wpa_printf(MSG_DEBUG, "ML: Set Link %d IGTK", link_id);

	// TODO: remove this when kernel is ready
	os_snprintf(cmd, sizeof(cmd), CMD_PRESET_LINKID " %d", link_id);
	wpa_drv_driver_cmd(wpa_s, cmd, buf, sizeof(buf));

	if (wpa_sm_set_key(sm, wpa_cipher_to_alg(sm->mgmt_group_cipher),
			   broadcast_ether_addr, keyidx, 0,
			   igtk_elem + 2, 6, igtk, igtk_len,
			   KEY_FLAG_GROUP_RX) < 0) {
		wpa_printf(MSG_WARNING, "ML: Failed to set IGTK to the "
			   "driver.");
		forced_memzero(igtk, sizeof(igtk));
		return -1;
	}
	forced_memzero(igtk, sizeof(igtk));

	return 0;
}

int ml_ft_process_igtk_subelem(struct wpa_sm *sm, const u8 **elem,
			      size_t *len, size_t num)
{
	u8 i;

	if (!sm->dot11MultiLinkActivated)
		return 0;

	for (i = 0; i < num; i++) {
		if (ml_ft_process_igtk_subelem_impl(sm, elem[i], len[i]) < 0) {
			wpa_printf(MSG_INFO, "ML: %s i=%d failed", __func__, i);
			return -1;
		}
	}

	return 0;
}

int ml_ft_process_bigtk_subelem_impl(struct wpa_sm *sm, const u8 *bigtk_elem,
				      size_t bigtk_elem_len)
{
	struct wpa_supplicant *wpa_s = sm->ctx->ctx;
	char cmd[32], buf[256];
	u8 link_id;
	u8 bigtk[WPA_BIGTK_MAX_LEN];
	size_t bigtk_len;
	u16 keyidx;
	const u8 *kek;
	size_t kek_len;

	if (!sm->beacon_prot || !bigtk_elem ||
	    (sm->mgmt_group_cipher != WPA_CIPHER_AES_128_CMAC &&
	     sm->mgmt_group_cipher != WPA_CIPHER_BIP_GMAC_128 &&
	     sm->mgmt_group_cipher != WPA_CIPHER_BIP_GMAC_256 &&
	     sm->mgmt_group_cipher != WPA_CIPHER_BIP_CMAC_256))
		return 0;

	if (wpa_key_mgmt_fils(sm->key_mgmt)) {
		kek = sm->ptk.kek2;
		kek_len = sm->ptk.kek2_len;
	} else {
		kek = sm->ptk.kek;
		kek_len = sm->ptk.kek_len;
	}

	wpa_hexdump_key(MSG_DEBUG, "ML: Received BIGTK in Reassoc Resp",
			bigtk_elem, bigtk_elem_len);

	bigtk_len = wpa_cipher_key_len(sm->mgmt_group_cipher);
	if (bigtk_elem_len != 2 + 6 + 1 + 1 + bigtk_len + 8) {
		wpa_printf(MSG_DEBUG,
			   "ML: Invalid BIGTK sub-elem length %lu",
			   (unsigned long) bigtk_elem_len);
		return -1;
	}
	if (bigtk_elem[9] != bigtk_len) {
		wpa_printf(MSG_DEBUG,
			   "FT: Invalid BIGTK sub-elem Key Length %d",
			   bigtk_elem[9]);
		return -1;
	}

	if (aes_unwrap(kek, kek_len, bigtk_len / 8, bigtk_elem + 10, bigtk)) {
		wpa_printf(MSG_WARNING,
			   "FT: AES unwrap failed - could not decrypt BIGTK");
		return -1;
	}

	/* KeyID[2] | IPN[6] | Link Info[1] | Key Length[1] | Key[16+8] */

	keyidx = WPA_GET_LE16(bigtk_elem);
	link_id = bigtk_elem[8] >> 4;

	wpa_hexdump_key(MSG_DEBUG, "FT: BIGTK from Reassoc Resp", bigtk,
			bigtk_len);

	wpa_printf(MSG_DEBUG, "ML: Set Link %d IGTK", link_id);

	// TODO: remove this when kernel is ready
	os_snprintf(cmd, sizeof(cmd), CMD_PRESET_LINKID " %d", link_id);
	wpa_drv_driver_cmd(wpa_s, cmd, buf, sizeof(buf));

	if (wpa_sm_set_key(sm, wpa_cipher_to_alg(sm->mgmt_group_cipher),
			   broadcast_ether_addr, keyidx, 0,
			   bigtk_elem + 2, 6, bigtk, bigtk_len,
			   KEY_FLAG_GROUP_RX) < 0) {
		wpa_printf(MSG_WARNING,
			   "ML: Failed to set BIGTK to the driver");
		forced_memzero(bigtk, sizeof(bigtk));
		return -1;
	}
	forced_memzero(bigtk, sizeof(bigtk));

	return 0;

}

int ml_ft_process_bigtk_subelem(struct wpa_sm *sm, const u8 **elem,
			        size_t *len, size_t num)
{
	u8 i;

	if (!sm->dot11MultiLinkActivated)
		return 0;

	for (i = 0; i < num; i++) {
		if (ml_ft_process_bigtk_subelem_impl(sm, elem[i], len[i]) < 0) {
			wpa_printf(MSG_INFO, "ML: %s i=%d failed", __func__, i);
			return -1;
		}
	}

	return 0;
}

#endif /* CONFIG_IEEE80211R */

int ml_p2p_is_ml_capa(struct p2p_data *p2p)
{
	struct wpa_supplicant *wpa_s = p2p->cfg->cb_ctx;
	char cmd[32], buf[256];

	/* 1 means p2p mode */
	os_snprintf(cmd, sizeof(cmd), CMD_GET_ML_CAPA " %d", 1);
	if (wpa_drv_driver_cmd(wpa_s, cmd, buf, sizeof(buf)) >= 0 &&
	    os_strstr(buf, "1")) {
		wpa_printf(MSG_INFO, "ML: P2P is ml capab %s", buf);
		return 1;
	} else {
		wpa_printf(MSG_INFO, "ML: P2P is ml capab %s", buf);
		return 0;
	}
}

void ml_p2p_buf_add_ml_capa(struct wpabuf *buf)
{
#ifdef CONFIG_MTK_IEEE80211BE_ML_CAPCA
	wpabuf_put_u8(buf, P2P_ATTR_VENDOR_SPECIFIC);
	wpabuf_put_le16(buf, 5);
	wpabuf_put_be24(buf, OUI_MTK);
	wpabuf_put_u8(buf, MTK_VENDOR_ATTR_P2P_ML_CAPA);
	wpabuf_put_u8(buf, 1);

	wpa_printf(MSG_DEBUG, "ML: Add ml capability");
#endif
}

void ml_p2p_buf_add_ml_prefer_freq_list(
	struct wpabuf *buf,
	struct p2p_data *p2p)
{
	struct wpa_supplicant *wpa_s = p2p->cfg->cb_ctx;
	char cmd[256];
	unsigned int freq = 0;

	if (wpa_drv_driver_cmd(wpa_s,
		CMD_GET_ML_PREFER_FREQ_LIST,
		cmd, sizeof(cmd)) >= 0) {
		freq = strtoul(cmd, NULL, 10);
	}

	wpabuf_put_u8(buf, P2P_ATTR_VENDOR_SPECIFIC);
	wpabuf_put_le16(buf, 6);
	wpabuf_put_be24(buf, OUI_MTK);
	wpabuf_put_u8(buf, MTK_VENDOR_ATTR_P2P_ML_FREQ_LIST);
	wpabuf_put_le16(buf, freq);

	wpa_printf(MSG_DEBUG, "ML: Add ml freq %u", freq);
}

int ml_p2p_get_2nd_freq(struct p2p_data *p2p, u16 freq)
{
	struct wpa_supplicant *wpa_s = p2p->cfg->cb_ctx;
	char cmd[32], buf[256];
	unsigned int f = 0;

	os_snprintf(cmd, sizeof(cmd),
		CMD_GET_ML_2ND_FREQ " %d %d",
		freq, p2p->ml_peer_freq);

	if (wpa_drv_driver_cmd(wpa_s, cmd, buf, sizeof(buf)) >= 0)
		f = strtoul(buf, NULL, 10);

	wpa_printf(MSG_DEBUG, "ML: Get 2nd freq %u", f);

	return f;
}

#endif /* HOSTAPD */
