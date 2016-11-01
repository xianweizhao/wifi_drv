/*
 * wifi server intferce
 * Copyright (c) 2016-2019, xianweizhao <xianwei.zhao@spreadtrum.com>
 *
 * wifi server intferce is client of wpa supplicant through msgq
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wifi_server_intf.h"

#include "../../wpa_supplicant/wpa_supplicant_i.h"
#include "../../wpa_supplicant/driver_i.h"
#include "common/ieee802_11_defs.h"
#include "common/wpa_common.h"
#include "common.h"
#include "../../wpa_supplicant/config.h"
#include "../../wpa_supplicant/bss.h"
#include "../../wpa_supplicant/scan.h"
#include "../rsn_supp/wpa.h"
#include "crypto/sha1.h"
#include "drivers/driver.h"
#include "eloop.h"
#include "wifi_manager.h"

static struct wpa_intf_data intf_data;
static struct host_intf_data hostif_data;

static inline void checkout_wpas_init(int timeout)
{
	while (intf_data.inited == 0 && timeout--)
		SCI_Sleep(1000);
}
static int wpas_freq_to_channel(int freq)
{
	/* see 802.11 17.3.8.3.2 and Annex J */
	if (freq == 2484)
		return 14;
	else if (freq < 2484)
		return (freq - 2407) / 5;
	else if (freq >= 4910 && freq <= 4980)
		return (freq - 4000) / 5;
	else if (freq <= 45000) /* DMG band lower limit */
		return (freq - 5000) / 5;
	else if (freq >= 58320 && freq <= 64800)
		return (freq - 56160) / 2160;
	else
		return 0;
}

int wpas_channel_to_freq(int chan)
{
	if (chan <= 0)
		return 0; /* not supported */

	if (chan == 14)
		return 2484;
	else if (chan < 14)
		return 2407 + chan * 5;

	if (chan >= 182 && chan <= 196)
		return 4000 + chan * 5;
	else
		return 5000 + chan * 5;

	return 0; /* not supported */
}

/*WEP SHARD is  what*/
static wifi_conn_sectype_t wpas_get_security_for_yunos(const struct wpa_scan_res *bss)
{
	const u8 *rsn_ie;
	const u8 *wpa_ie;
	struct wpa_ie_data ie;
	u8 wpa_ie_len, rsn_ie_len;

	wpa_ie = wpa_scan_get_vendor_ie(bss, WPA_IE_VENDOR_TYPE);
	wpa_ie_len = wpa_ie ? wpa_ie[1] : 0;

	rsn_ie = wpa_scan_get_ie(bss, WLAN_EID_RSN);
	rsn_ie_len = rsn_ie ? rsn_ie[1] : 0;

	rsn_ie = wpa_scan_get_ie(bss, WLAN_EID_RSN);
	if (rsn_ie) {
		if (wpa_parse_wpa_ie(rsn_ie, 2 + rsn_ie[1], &ie))
			return WIFI_CONN_SEC_UNKNOWN;
		if (ie.pairwise_cipher == WPA_CIPHER_CCMP)
			return WIFI_CONN_SEC_WPA2_AES_PSK;
		if (ie.pairwise_cipher == WPA_CIPHER_TKIP)
			return WIFI_CONN_SEC_WPA2_TKIP_PSK;
		if (ie.pairwise_cipher == (WPA_CIPHER_TKIP | WPA_CIPHER_CCMP))
			return WIFI_CONN_SEC_WPA2_MIXED_PSK;
		return WIFI_CONN_SEC_UNKNOWN;
	}

	wpa_ie = wpa_scan_get_vendor_ie(bss, WPA_IE_VENDOR_TYPE);
	if (wpa_ie) {
		if (wpa_parse_wpa_ie(wpa_ie, 2 + wpa_ie[1], &ie)) {
			wpa_printf(MSG_DEBUG, "skip WPA IE - parse failed");
			return WIFI_CONN_SEC_UNKNOWN;
		}
		if (ie.pairwise_cipher == WPA_CIPHER_CCMP)
			return WIFI_CONN_SEC_WPA_AES_PSK;
		if (ie.pairwise_cipher == WPA_CIPHER_TKIP)
			return WIFI_CONN_SEC_WPA_TKIP_PSK;
		return WIFI_CONN_SEC_UNKNOWN;
	}
	if (bss->caps & IEEE80211_CAP_PRIVACY)
		return WIFI_CONN_SEC_WEP_PSK;

	return WIFI_CONN_SEC_OPEN;
}
#if 0
static void wpas_only_scan_handler(struct wpa_supplicant *wpa_s,
			       struct wpa_scan_results *scan_res)
{
	    wpa_printf(MSG_DEBUG, "scan result done: %d APs", scan_res->num);
}
#endif

static void wpas_scan_handler(struct wpa_supplicant *wpa_s,
			       struct wpa_scan_results *scan_res)
{
	wifi_scan_ap_t *info;
	int num = 0;
	int i = 0;

	info = (wifi_scan_ap_t *)intf_data.scan_user;
	intf_data.scan_user = NULL;
	num = intf_data.scan_num;
	if (num > scan_res->num)
		num = scan_res->num;

	if (info == NULL) {
	    wpa_printf(MSG_DEBUG, "yunos scanning is timeout return");
	    return;
	}

	for (i = 0; i < num; i++) {
		struct wpa_scan_res *res = scan_res->res[i];
		const u8 *ie, *ssid;
		u8 ssid_len;

		if (res == NULL)
			continue;

		ie = wpa_scan_get_ie(res, WLAN_EID_SSID);
		ssid = ie ? ie + 2 : (u8 *)"";
		ssid_len = ie ? ie[1] : 0;
		if (ssid_len)
			os_memcpy(&info->ssid, ssid, ssid_len);

		os_memcpy(info->bssid, res->bssid, ETH_ALEN);
		info->channel = wpas_freq_to_channel(res->freq);

		info->security = wpas_get_security_for_yunos(res);
		info->rssi = res->level;
		info++;
	}
	intf_data.scan_num = num;

	SCI_PutSemaphore(intf_data.scan_done);
}

static void wpas_security_to_proto(wifi_conn_sectype_t security, struct connect_proto *proto)
{
	switch (security) {
	case  WIFI_CONN_SEC_OPEN:
		proto->proto = 0;
		proto->pairse_cipher = WPA_CIPHER_NONE;
		proto->group_cipher = WPA_CIPHER_NONE;
		proto->key_mgmt = WPA_KEY_MGMT_NONE;
		break;
	case  WIFI_CONN_SEC_WPA_AES_PSK:
		proto->proto = WPA_PROTO_WPA;
		proto->pairse_cipher = WPA_CIPHER_CCMP;
		proto->group_cipher = (WPA_CIPHER_CCMP | WPA_CIPHER_TKIP |
				WPA_CIPHER_WEP104 | WPA_CIPHER_WEP40);
		proto->key_mgmt = WPA_KEY_MGMT_PSK;
		break;
	case  WIFI_CONN_SEC_WPA2_AES_PSK:
		proto->proto = WPA_PROTO_RSN;
		proto->pairse_cipher = WPA_CIPHER_CCMP;
		proto->group_cipher = (WPA_CIPHER_CCMP | WPA_CIPHER_TKIP |
				WPA_CIPHER_WEP104 | WPA_CIPHER_WEP40);
		proto->key_mgmt = WPA_KEY_MGMT_PSK;
		break;
	case  WIFI_CONN_SEC_WEP_PSK:
		proto->proto = 0;
		proto->pairse_cipher = WPA_CIPHER_WEP104 | WPA_CIPHER_WEP40;
		proto->group_cipher = WPA_CIPHER_WEP104 | WPA_CIPHER_WEP40;
		proto->key_mgmt = WPA_KEY_MGMT_PSK;
		break;
	case  WIFI_CONN_SEC_WEP_SHARED:
		proto->proto = 0;
		proto->pairse_cipher = WPA_CIPHER_WEP104 | WPA_CIPHER_WEP40;
		proto->group_cipher = WPA_CIPHER_WEP104 | WPA_CIPHER_WEP40;
		proto->key_mgmt = WPA_KEY_MGMT_PSK;
		break;
	case  WIFI_CONN_SEC_WPA_TKIP_PSK:
		proto->proto = WPA_PROTO_WPA;
		proto->pairse_cipher = WPA_CIPHER_TKIP;
		proto->group_cipher = WPA_CIPHER_TKIP | WPA_CIPHER_WEP104 |
				WPA_CIPHER_WEP40;
		proto->key_mgmt = WPA_KEY_MGMT_PSK;
		break;
	case  WIFI_CONN_SEC_WPA2_TKIP_PSK:
		proto->proto = WPA_PROTO_RSN;
		proto->pairse_cipher = WPA_CIPHER_TKIP;
		proto->group_cipher = WPA_CIPHER_TKIP | WPA_CIPHER_WEP104 |
				WPA_CIPHER_WEP40;
		proto->key_mgmt = WPA_KEY_MGMT_PSK;
		break;
	case  WIFI_CONN_SEC_WPA2_MIXED_PSK:
		proto->proto = WPA_PROTO_RSN;
		proto->pairse_cipher = WPA_CIPHER_CCMP | WPA_CIPHER_TKIP;
		proto->group_cipher = (WPA_CIPHER_CCMP | WPA_CIPHER_TKIP |
				WPA_CIPHER_WEP104 | WPA_CIPHER_WEP40);
		proto->key_mgmt = WPA_KEY_MGMT_PSK;
		break;
	case  WIFI_CONN_SEC_UNKNOWN:
	default:
		proto->proto = WPA_PROTO_RSN | WPA_PROTO_WPA;
		proto->pairse_cipher = WPA_CIPHER_CCMP | WPA_CIPHER_TKIP;
		proto->group_cipher = (WPA_CIPHER_CCMP | WPA_CIPHER_TKIP |
				WPA_CIPHER_WEP104 | WPA_CIPHER_WEP40);
		proto->key_mgmt = WPA_KEY_MGMT_PSK;
		break;
	}
}



int wifi_get_mac_address(wifi_mac_addr_t mac_addr)
{
	struct wpa_supplicant *wpa_s = NULL;
	const unsigned char *addr = mac_addr;

	wpa_s = intf_data.wpa_s;
	addr = wpa_drv_get_mac_addr(wpa_s);
	if (addr != NULL)
		os_memcpy(mac_addr, addr, 6);

	return 0;
}



int wpas_notify_connect_change(int new_state, int old_state)
{
	if (intf_data.inited == 0)
		return 0;

	if (new_state == WPA_COMPLETED) {
		if (intf_data.cmd_state == WPAS_CMD_CONNECT)
			SCI_PutSemaphore(intf_data.connect_done);
	}
	else if (new_state == WPA_DISCONNECTED ) {
		if (intf_data.cmd_state == WPAS_CMD_DISCONNECT)
			SCI_PutSemaphore(intf_data.disconnect_done);
	}
	return 0;
}

wifi_conn_sectype_t wpas_get_current_ap_security(void)
{
	struct wpa_supplicant *wpa_s = intf_data.wpa_s;
	struct wpa_ssid *ssid = NULL;

	if (wpa_s->wpa_state != WPA_COMPLETED)
		return -1;
	ssid = wpa_s->current_ssid;
	if (ssid->proto == WPA_PROTO_RSN) {
		if (wpa_s->pairwise_cipher == WPA_CIPHER_CCMP)
			return WIFI_CONN_SEC_WPA2_AES_PSK;
		if (wpa_s->pairwise_cipher == WPA_CIPHER_TKIP)
			return WIFI_CONN_SEC_WPA2_TKIP_PSK;
	}
	if (ssid->proto == WPA_PROTO_WPA) {
		if (wpa_s->pairwise_cipher == WPA_CIPHER_TKIP)
			return WIFI_CONN_SEC_WPA_TKIP_PSK;
	}
	if (wpa_s->current_bss->caps & IEEE80211_CAP_PRIVACY)
		return WIFI_CONN_SEC_WEP_PSK;

	return WIFI_CONN_SEC_OPEN;
}

static struct wpa_ssid *wpas_wpa_ssid_save(struct wpa_supplicant *wpa_s,
					   struct msgq_cmd_buf  *con)
{
	struct wpa_ssid *wpa_ssid = NULL;
	struct connect_proto *proto =  NULL;
	int pwd_len = 0;
	proto = &con->proto;
	wpa_ssid = wpa_config_find_network(wpa_s->conf, (char *)con->ssid);
	if (wpa_ssid == NULL)
		return NULL;
	if (con->cmd_type == CMD_CONNECT){
		/* set only ssid and password param */
		return wpa_ssid;
	}
	if (con->password != NULL)
		pwd_len = os_strlen(con->password);

	if (proto->proto == 1 || proto->proto == 2) {
		if (pwd_len < 8 || pwd_len > 63)
			return NULL;
		wpa_ssid->passphrase = (char *)con->password;
		pbkdf2_sha1(con->password, con->ssid, wpa_ssid->ssid_len, 4096,
			    wpa_ssid->psk, PMK_LEN);
		wpa_ssid->psk_set = 1;
	} else if ((proto->proto == 0)&&(proto->pairse_cipher != WPA_CIPHER_NONE)) {
		if (pwd_len < 10)
			return NULL;
		os_memcpy(wpa_ssid->wep_key[0], con->password, pwd_len);
		wpa_ssid->wep_key_len[0] = pwd_len;
		wpa_ssid->wep_tx_keyidx = 0;
	}

	if (con->bssid[0] || con->bssid[1] || con->bssid[2]
	    || con->bssid[3] || con->bssid[5] || con->bssid[6] ) {
		os_memcpy(wpa_ssid->bssid, con->bssid, ETH_ALEN);
		wpa_ssid->bssid_set = 1;
	}
	wpa_ssid->proto = proto->proto;
	wpa_ssid->pairwise_cipher =proto->pairse_cipher;
	wpa_ssid->group_cipher = proto->group_cipher;
	wpa_ssid->key_mgmt = proto->key_mgmt;

	if (con->channel != 0) {
		wpa_ssid->freq_list = os_malloc(sizeof(int)*1);
		*wpa_ssid->freq_list = wpas_channel_to_freq(con->channel);
	}
	return wpa_ssid;
}

static void wpas_wifi_scan_cb(struct wpa_supplicant *wpa_s)
{
	wpa_s->scan_res_handler = wpas_scan_handler;
	wpa_s->scan_req = 2;
	wpa_supplicant_req_scan(wpa_s, 0, 0);

}

static void wpas_wifi_connect_cb(struct wpa_supplicant *wpa_s, struct msgq_cmd_buf  *buf)
{
	struct wpa_ssid *wpa_ssid;

	wpa_ssid = wpas_wpa_ssid_save(wpa_s,  buf);
	if (!wpa_ssid)
	    return;

	wpa_supplicant_enable_network(wpa_s, wpa_ssid);
}

static void wpas_wifi_disconnect_cb(struct wpa_supplicant *wpa_s)
{
	wpa_supplicant_disable_network(wpa_s, wpa_s->current_ssid);
}

static int wpas_user_cmd_cb(void *udata,  char* msg_buf)
{
	struct wpa_supplicant *wpa_s = NULL;
	struct msgq_cmd_buf  *buf = NULL;

	wpa_s = (struct wpa_supplicant *)udata;
	buf = (struct msgq_cmd_buf  *)msg_buf;
	switch (buf->cmd_type) {
		case CMD_SCAN:
			wpas_wifi_scan_cb(intf_data.wpa_s);
			break;
		case CMD_CONNECT:
		case CMD_CONNECT_EXT:
			wpas_wifi_connect_cb(intf_data.wpa_s, buf);
			break;
		case CMD_DISCONNECT:
			wpas_wifi_disconnect_cb(intf_data.wpa_s);
			break;
		case CMD_ELOOP_STOP:
			eloop_terminate();
			break;
		default:
			break;
	}
	return 0;
}

void wpas_wifi_simple_scan(void)
{
	struct msgq_cmd_buf  buf;

	os_memset(&buf,0,sizeof(buf));
	buf.hd.type = MSG_TYPE_USER;
	buf.cmd_type = CMD_SCAN;

	SCI_SendMsg(intf_data.msg_q, (const char *)&buf, 0xffffffff);
}

int wpas_wifi_scan(wifi_scan_ap_t * info, uint32_t size)
{
	int ret = 0;

	checkout_wpas_init(10);
	if(intf_data.inited == 0) {
		wpa_printf(MSG_INFO,"wpa_s not init\n");
		return -1;
	}

	if (intf_data.scan_user != NULL) {
		wpa_printf(MSG_DEBUG,"yunos is scanning\n");
		return 0;
	}
	intf_data.scan_num = size;
	intf_data.scan_user= info;
	wpas_wifi_simple_scan();
	ret = SCI_GetSemaphore(intf_data.scan_done, SCAN_TIMEOUT_MS);
	intf_data.scan_user= NULL;
	if (ret < 0)
		return -1;

	return intf_data.scan_num;
}

int wpas_wifi_connect_ext(const char *ssid, const char *password,
			       const wifi_mac_addr_t bssid, uint8_t channel,
			       wifi_conn_sectype_t security)
{
	struct msgq_cmd_buf  buf;
	int ret = 0;

	checkout_wpas_init(3);
	if(intf_data.inited == 0) {
		wpa_printf(MSG_INFO,"wpa_s not init\n");
		return -1;
	}

	if (ssid == NULL) {
		wpa_printf(MSG_INFO,"connect ssid is NULL\n");
		return -1;
	}

	intf_data.cmd_state = WPAS_CMD_CONNECT;

	os_memset(&buf,0,sizeof(buf));
	buf.hd.type = MSG_TYPE_USER;

	buf.cmd_type = CMD_CONNECT_EXT;
	buf.channel = channel;
	if(bssid != NULL)
	    os_memcpy(buf.bssid, bssid, ETH_ALEN);
	buf.password = password;
	buf.ssid = (u8 *)ssid;

	wpas_security_to_proto(security, &buf.proto);

	SCI_SendMsg(intf_data.msg_q, (const char *)&buf, 0xffffffff);


	ret = SCI_GetSemaphore(intf_data.connect_done, CONNECT_TIMEOUT_MS);
	if (ret != SCI_SUCCESS)
		ret = -1;
	intf_data.cmd_state = WPAS_CMD_DONE;
	return ret;
}

int wpas_wifi_connect(const char *ssid, const char *password)
{
	struct msgq_cmd_buf  buf;
	int ret = 0;

	checkout_wpas_init(3);
	if(intf_data.inited == 0) {
		wpa_printf(MSG_INFO,"wpa_s not init\n");
		return -1;
	}
	if (ssid == NULL) {
		wpa_printf(MSG_INFO,"connect ssid is NULL\n");
		return -1;
	}

	intf_data.cmd_state = WPAS_CMD_CONNECT;

	os_memset(&buf,0,sizeof(buf));
	buf.hd.type = MSG_TYPE_USER;

	buf.cmd_type = CMD_CONNECT;
	buf.password = password;
	buf.ssid = (u8 *)ssid;

	SCI_SendMsg(intf_data.msg_q, (const char *)&buf, 0xffffffff);

	ret = SCI_GetSemaphore(intf_data.connect_done, CONNECT_TIMEOUT_MS);
	if (ret != SCI_SUCCESS)
		ret = -1;
	intf_data.cmd_state = WPAS_CMD_DONE;
	return ret;
}

int wpas_wifi_disconnect(int sync)
{
	struct msgq_cmd_buf  buf;
	int ret = 0;

	checkout_wpas_init(1);
	if(intf_data.inited == 0) {
		wpa_printf(MSG_INFO,"wpa_s not init\n");
		return -1;
	}
	intf_data.cmd_state = WPAS_CMD_DISCONNECT;
	buf.hd.type = MSG_TYPE_USER;
	buf.cmd_type = CMD_DISCONNECT;

	ret = SCI_SendMsg(intf_data.msg_q, (const char *)&buf, 0xffffffff);

	if (sync && ret == SCI_SUCCESS) {
		ret = SCI_GetSemaphore(intf_data.disconnect_done, CONNECT_TIMEOUT_MS);
		if (ret != SCI_SUCCESS)
			ret = -1;
	}
	intf_data.cmd_state = WPAS_CMD_DONE;
	return ret;
}

int wpas_wifi_get_rssi(void)
{
	struct wpa_signal_info si;
	struct wpa_supplicant *wpa_s = intf_data.wpa_s;

	if (wpa_s->wpa_state != WPA_COMPLETED)
		return -1;
	wpa_drv_signal_poll(wpa_s, &si);

	return si.current_signal;
}

int wpas_wifi_get_rate(void)
{
	struct wpa_signal_info si;
	struct wpa_supplicant *wpa_s = intf_data.wpa_s;

	if (wpa_s->wpa_state != WPA_COMPLETED)
		return -1;

	wpa_drv_signal_poll(wpa_s, &si);

	return si.current_txrate;
}

int wpas_get_current_ap_bssid(wifi_mac_addr_t mac_addr)
{
	struct wpa_bss *bss = NULL;

	if (intf_data.wpa_s->wpa_state != WPA_COMPLETED)
		return -1;
	bss = intf_data.wpa_s->current_bss;
	os_memcpy(mac_addr, bss->bssid, ETH_ALEN);

	return 0;
}

int wpas_get_current_ap_channel(void)
{
	struct wpa_supplicant *wpa_s = intf_data.wpa_s;
	struct wpa_bss *bss = NULL;

	if (wpa_s->wpa_state != WPA_COMPLETED)
		return -1;
	bss = wpa_s->current_bss;
	return wpas_freq_to_channel(bss->freq);
}

int wpas_eloop_exit_thread(void)
{
	struct msgq_cmd_buf  buf;
	int ret = 0;

	buf.hd.type = MSG_TYPE_USER;
	buf.cmd_type = CMD_ELOOP_STOP;

	ret = SCI_SendMsg(intf_data.msg_q, (const char *)&buf, 0xffffffff);

	return 0;
}
/* for hostapd */

static int hostapd_user_cmd_cb(void *udata,  char* msg_buf)
{
	struct hostapd_iface *host_if = NULL;
	struct msgq_cmd_buf  *buf = NULL;

	host_if = (struct hostapd_iface *)udata;
	buf = (struct msgq_cmd_buf  *)msg_buf;
	switch (buf->cmd_type) {
		case CMD_ELOOP_STOP:
			eloop_terminate();
			break;
		default:
			break;
	}
	return 0;
}

int hostapd_eloop_exit_thread(void)
{
	struct msgq_cmd_buf  buf;
	int ret = 0;

	buf.hd.type = MSG_TYPE_USER;
	buf.cmd_type = CMD_ELOOP_STOP;

	ret = SCI_SendMsg(hostif_data.msg_q, (const char *)&buf, 0xffffffff);

	return 0;
}

int hostapd_priv_data_init(struct hostapd_iface *host_if)
{
	hostif_data.msg_q = eloop_register_msg_q(MSG_TYPE_USER, host_if, hostapd_user_cmd_cb);
	hostif_data.host_if = host_if;
	hostif_data.inited = 1;

	return 0;
}

int hostapd_priv_data_deinit(void)
{
	eloop_unregister_msg_q(MSG_TYPE_USER);
	hostif_data.msg_q = NULL;
	hostif_data.host_if = NULL;
	hostif_data.inited = 0;

	return 0;
}
int hostapd_wifi_softap_start(const wifi_ap_param_t * param)
{
	return hostapd_main();
}

int hostapd_wifi_softap_stop(void)
{
	wpas_change_wifi_mode(WIFI_MODE_NONE, 1);
	return 0;
}

/* for wpa_supplicant */
int wpas_priv_data_init(struct wpa_supplicant *wpa_s)
{
	intf_data.wpa_s = wpa_s;
	intf_data.scan_done = SCI_CreateSemaphore("wpa_scan", 0);
	intf_data.connect_done = SCI_CreateSemaphore("wpa_connect", 0);
	intf_data.disconnect_done = SCI_CreateSemaphore("wpa_disconnect", 0);
	intf_data.msg_q = eloop_register_msg_q(MSG_TYPE_USER, wpa_s, wpas_user_cmd_cb);
	intf_data.cmd_state = WPAS_CMD_NONE;

	intf_data.inited = 1;
	printf("%s: exit success\n",__func__);
	return 0;
}

int wpas_priv_data_deinit(void)
{
	SCI_DeleteSemaphore(intf_data.scan_done);
	SCI_DeleteSemaphore(intf_data.connect_done);
	SCI_DeleteSemaphore(intf_data.disconnect_done);
	eloop_unregister_msg_q(MSG_TYPE_USER);
	intf_data.msg_q = NULL;
	intf_data.wpa_s = NULL;

	intf_data.inited = 0;
	return 0;
}


int wpas_supplicant_start(void)
{
	wpa_supplicant_main();
	return 0;
}

int wpas_supplicant_stop(void)
{
	wpas_change_wifi_mode(WIFI_MODE_NONE, 1);
	return 0;
}

int wpas_get_current_mode(void)
{
	return wifi_work_mode;
}
/* wifi mode init  not wpa_s  or hostapd init*/

int wpas_wifi_init(void)
{
	wifi_manager_init();
	return 0;
}
