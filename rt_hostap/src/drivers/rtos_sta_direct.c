#include "includes.h"
#include "common.h"
#include "eloop.h"
#include "common/ieee802_11_defs.h"
#include "common/wpa_common.h"
#include "driver.h"
#include "rtos_sta_direct.h"
#include "rtos_drv_sc2331.h"

#include "../wpa_supplicant/wpa_supplicant_i.h"


static int wpa_driver_rtos_event(void *ctx, char *buf);
 int wpa_driver_direct_flush_pmkid(void *priv)
{	
	struct wpa_driver_direct_data *drv = priv;
	/*low level not support */
	return 0;
}
int wpa_driver_direct_add_pmkid(void *priv, const u8 *bssid,
			      const u8 *pmkid)
{
	struct wpa_driver_direct_data *drv = priv;
	/*low level not support */
	return 0;
}

int wpa_driver_direct_remove_pmkid(void *priv, const u8 *bssid,
		 		 const u8 *pmkid)
{
	struct wpa_driver_direct_data *drv = priv;
	/*low level not support */
	return 0;
}
int wpa_driver_direct_get_capa(void *priv, struct wpa_driver_capa *capa)
{
	struct wpa_driver_direct_data *drv = priv;
	if (!drv->has_capability)
		return -1;
	os_memcpy(capa, &drv->capa, sizeof(*capa));
	return 0;
}
static void wpa_driver_direct_disconnect(struct wpa_driver_direct_data *drv)
	
{
}
int wpa_driver_direct_set_mode(void *priv, int mode)
{

}
static int wpa_driver_direct_get_range(void *priv)
{	
	return 0;
}
static  unsigned int if_nametoindex(const char* ifname)
{
	return 0;
}
static int wpa_driver_direct_finish_drv_init(struct wpa_driver_direct_data *drv)
{
		/*
	 * Make sure that the driver does not have any obsolete PMKID entries.
	 */
	wpa_driver_direct_flush_pmkid(drv);

	if (wpa_driver_direct_set_mode(drv, 0) < 0) {
		wpa_printf(MSG_DEBUG, "Could not configure driver to use "
			   "managed mode");
		/* Try to use it anyway */
	}

	wpa_driver_direct_get_range(drv);

	/*
	 * Unlock the driver's BSSID and force to a random SSID to clear any
	 * previous association the driver might have when the supplicant
	 * starts up.
	 */
	wpa_driver_direct_disconnect(drv);

	drv->ifindex = if_nametoindex(drv->ifname);
	
	char ifname2[IFNAMSIZ + 1];
	os_memcpy(ifname2, "wifi", 4);
	drv->ifindex2 = if_nametoindex(ifname2);
	return 0;
}
static int wpa_driver_direct_set_auth_alg(void *priv, int auth_alg)
{
	struct wpa_driver_direct_data *drv = priv;
	int auth = 0, ret;

	if (auth_alg & WPA_AUTH_ALG_SHARED)
		auth = 1;
	if (auth_alg & WPA_AUTH_ALG_LEAP){
		wpa_printf(MSG_ERROR, "not support LEAP auth\n");
		return -1;
	}
	
	ret = sprdwl_cmd_set_auth_type(drv->drv_priv, auth);
	return ret;
}

static int wpa_driver_direct_set_gen_ie(void *priv, const u8 *ie,
				      size_t ie_len)
{
	int ret = 0;
	/* driver not send ie to cp */

	return ret;
}
static int wpa_driver_direct_cipher2cp(int cipher)
{
	switch (cipher) {
	case WPA_CIPHER_NONE:
		return AUTH_CIPHER_NONE;
	case WPA_CIPHER_WEP40:
		return AUTH_CIPHER_WEP40;
	case WPA_CIPHER_TKIP:
		return AUTH_CIPHER_TKIP;
	case WPA_CIPHER_CCMP:
		return AUTH_CIPHER_CCMP;
	case WPA_CIPHER_WEP104:
		return AUTH_CIPHER_WEP104;
	default:
		return 0;
	}
}
int wpa_driver_direct_keymgmt2cp(int keymgmt)
{
	switch (keymgmt) {
	case KEY_MGMT_802_1X:
	case KEY_MGMT_802_1X_NO_WPA:
		return AUTH_KEY_MGMT_802_1X;
	case KEY_MGMT_PSK:
		return AUTH_KEY_MGMT_PSK;
	default:
		return AUTH_KEY_MGMT_NONE;
	}
}

static int wpa_driver_direct_set_psk(struct wpa_driver_direct_data *drv,
				   const u8 *psk)
{

	int ret;

	if (!(drv->capa.flags & WPA_DRIVER_FLAGS_4WAY_HANDSHAKE))
		return 0;
	if (!psk)
		return 0;
	
	ret = sprdwl_cmd_set_psk(drv->drv_priv, psk, PMK_LEN);
	if (ret < 0)
		wpa_printf(MSG_ERROR, "ioctl[SIOCSIWENCODEEXT] PMK");

	return ret;
}

static int wpa_driver_direct_set_auth_param(struct wpa_driver_direct_data *drv,
				  unsigned int value)
{
	return sprdwl_cmd_set_wpa_version(drv->drv_priv, value);
}
int wpa_driver_direct_set_ssid(void *priv, const u8 *ssid, size_t ssid_len)
{
	struct wpa_driver_direct_data *drv = priv;

	if (ssid_len > 32)
		return -1;

	return sprdwl_cmd_set_essid(drv->drv_priv, ssid, ssid_len);
}
int wpa_driver_direct_set_bssid(void *priv, const u8 *bssid)
{
	struct wpa_driver_direct_data *drv = priv;
	static const u8 any[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
	static const u8 off[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	int ret = 0;

	if (!os_memcmp(any, bssid, 6) ||
	    !os_memcmp(off, bssid, 6)) {
		return 0;
	}
	
	return sprdwl_cmd_set_bssid(drv->drv_priv, bssid);
}

int wpa_driver_direct_associate(void *priv,
			      struct wpa_driver_associate_params *params)
{
	struct wpa_driver_direct_data *drv = priv;
	int ret = 0;
	int allow_unencrypted_eapol;
	int value;

	wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);

	if (wpa_driver_direct_set_auth_alg(drv, params->auth_alg) < 0)
		ret = -1;
	if (wpa_driver_direct_set_mode(drv, params->mode) < 0)
		ret = -1;

	if (!params->bssid &&
	    wpa_driver_direct_set_bssid(drv, NULL) < 0)
		ret = -1;


	if (wpa_driver_direct_set_gen_ie(drv, params->wpa_ie, params->wpa_ie_len)
	    < 0)
		ret = -1;
	if (params->wpa_ie == NULL || params->wpa_ie_len == 0)
		value = 0; /*disable */
	else if (params->wpa_ie[0] == WLAN_EID_RSN)
		value = 2; /*wpa2 */
	else
		value = 1; /*wpa */
	ret = wpa_driver_direct_set_auth_param(drv, value);	

	value = wpa_driver_direct_cipher2cp(params->pairwise_suite);
	
	ret = sprdwl_cmd_set_pairwise_cipher(drv->drv_priv, value);
	
	value = wpa_driver_direct_cipher2cp(params->group_suite);
	ret = sprdwl_cmd_set_group_cipher(drv->drv_priv, value);

	value = wpa_driver_direct_keymgmt2cp(params->key_mgmt_suite);
	ret = sprdwl_cmd_set_key_management(drv->drv_priv, value);
	

	value = params->key_mgmt_suite != KEY_MGMT_NONE ||
		params->pairwise_suite != CIPHER_NONE ||
		params->group_suite != CIPHER_NONE ||
		params->wpa_ie_len;
	/* set priv is not support */
	
	if (wpa_driver_direct_set_psk(drv, params->psk) < 0)
		ret = -1;

	if (!drv->cfg80211 &&
	    wpa_driver_direct_set_ssid(drv, params->ssid, params->ssid_len) < 0)
		ret = -1;
	if (params->bssid &&
	    wpa_driver_direct_set_bssid(drv, params->bssid) < 0)
		ret = -1;
	if (drv->cfg80211 &&
	    wpa_driver_direct_set_ssid(drv, params->ssid, params->ssid_len) < 0)
		ret = -1;

	return ret;
}
int wpa_driver_direct_deauthenticate(void *priv, const u8 *addr,
					  int reason_code)
{
	struct wpa_driver_direct_data *drv = priv;
	int ret = 0;

	wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);
	sprdwl_cmd_disconnect(drv->drv_priv, reason_code);
	wpa_driver_direct_disconnect(drv);
	return ret;
}

void *wpa_driver_direct_init(void *ctx, const char *ifname)
{
	struct wpa_driver_direct_data *drv;
	printf("%s enter\n",__func__);
	drv = os_zalloc(sizeof(*drv));
	if (drv == NULL)
		return NULL;
	drv->ctx = ctx;
	os_strlcpy(drv->ifname, ifname, sizeof(drv->ifname));

	drv->msg_q = eloop_register_msg_q(MSG_TYPE_DRIVER, drv,
				     wpa_driver_rtos_event);
	if (drv->msg_q == NULL){
		wpa_printf(MSG_ERROR, "%s : register_msg_q failed\n", __func__);
		return NULL;
	}
	drv->drv_priv = sprdwl_init(drv); /*here default set station */
	sc2331_ifup(drv->drv_priv);
	if (wpa_driver_direct_finish_drv_init(drv) < 0) {
	
		os_free(drv);
		return NULL;
	}

	return drv;
}
void wpa_driver_direct_scan_timeout(void *eloop_ctx, void *timeout_ctx)
{
	wpa_printf(MSG_DEBUG, "Scan timeout - try to get results");
	wpa_supplicant_event(timeout_ctx, EVENT_SCAN_RESULTS, NULL);
}

void wpa_driver_direct_deinit(void *priv)
{
	struct wpa_driver_direct_data *drv = priv;

	/* unregister massage queue handler */
	eloop_unregister_msg_q(MSG_TYPE_DRIVER);


	eloop_cancel_timeout(wpa_driver_direct_scan_timeout, drv, drv->ctx);

	/*
	 * Clear possibly configured driver parameters in order to make it
	 * easier to use the driver after wpa_supplicant has been terminated.
	 */
	wpa_driver_direct_disconnect(drv);

	sc2331_ifdown(drv->drv_priv);

	os_free(drv->assoc_req_ies);
	os_free(drv->assoc_resp_ies);
	os_free(drv);
}

int wpa_driver_direct_send_eapol(void *priv, const u8 *dest, u16 proto,
			  const u8 *data, size_t data_len)
{
	struct eth_data_packet *packet = NULL;
	struct wpa_driver_direct_data *drv = priv;
	size_t len = sizeof(struct eth_data_packet) + data_len;
	int ret = 0;
	
	packet = os_malloc(len);
	if (packet == NULL)
		return -1;
	
	os_memcpy(packet->dest, dest, ETH_ALEN);
	/* memcpy ownaddr*/  /** !!!! softap mac? ***/
	os_memcpy(packet->src, drv->drv_priv->d_mac.ether_addr_octet, ETH_ALEN);

	packet->proto = htons(proto);
	os_memcpy(packet->data, data, data_len);
	ret = sprdwl_wifi_tx_data(packet, len);
	os_free(packet);
	return ret;
}
const u8 * wpa_driver_direct_get_mac_addr(void *priv)
{
	struct wpa_driver_direct_data *drv = priv;
	return drv->drv_priv->d_mac.ether_addr_octet;
}
int wpa_driver_direct_scan(void *priv, struct wpa_driver_scan_params *params)
{
	struct wpa_driver_direct_data *drv = priv;
	int ret = 0, timeout;
	const u8 *ssid = params->ssids[0].ssid;
	size_t ssid_len = params->ssids[0].ssid_len;
	unsigned char *channel = NULL; /* default full chanel  do it in driver */


	if (ssid_len > WLAN_MAX_KEY_LEN) {
		wpa_printf(MSG_DEBUG, "%s: too long SSID (%lu)",
			   __FUNCTION__, (unsigned long) ssid_len);
		return -1;
	}
	/* here need change freq to chan */
	
	ret = sprdwl_cmd_scan(drv->drv_priv, ssid, channel, ssid_len);

	timeout = 30;

	wpa_printf(MSG_DEBUG, "Scan requested (ret=%d) - scan timeout %d "
		   "seconds", ret, timeout);
	eloop_cancel_timeout(wpa_driver_direct_scan_timeout, drv, drv->ctx);
	eloop_register_timeout(timeout, 0, wpa_driver_direct_scan_timeout, drv,
			       drv->ctx);
	return ret;
}
int wpa_driver_direct_set_countermeasures(void *priv,
					       int enabled)
{
	struct wpa_driver_direct_data *drv = priv;
	/*low level not support */
	return 0;
}
int wpa_driver_direct_get_ssid(void *priv, u8 *ssid)
{
	struct wpa_driver_direct_data *drv = priv;
	int ret = 0;
	
	/* get from driver priv conn */
	return ret;
}

int wpa_driver_direct_get_bssid(void *priv, u8 *bssid)
{
	struct wpa_driver_direct_data *drv = priv;
	int ret = 0;
	
	/* get from driver priv conn */
	return ret;
}


/* need check ?????? */
int wpa_driver_direct_set_key(const char *ifname, void *priv, enum wpa_alg alg,
			    const u8 *addr, int key_idx,
			    int set_tx, const u8 *seq, size_t seq_len,
			    const u8 *key, size_t key_len)
{
	struct wpa_driver_direct_data *drv = priv;
	struct sprdwl_conn_param *conn = NULL;	
	const u8 *sa_addr = NULL;
	int pairwise = 1;
	int ret = 0;

	if (set_tx) {
		ret = sprdwl_cmd_set_key(drv->drv_priv, key_idx);
		if(!ret)
			conn->default_key = key_idx;
		return ret;
	}
	
	conn = &drv->drv_priv->conn;
	if (addr == NULL || os_memcmp(addr, "\xff\xff\xff\xff\xff\xff", ETH_ALEN) == 0){
		pairwise = 0;
		sa_addr = NULL;
	}else 
		sa_addr = addr;


	switch (alg) {
	case WPA_ALG_NONE:
		conn->cipher = 0;
		if (!conn->key_len[pairwise][key_idx])
			return 0;
		conn->key_len[pairwise][key_idx] = 0;
		conn->cipher = 0;
		if (!pairwise)
			conn->group_cipher = AUTH_CIPHER_NONE;
		else
			conn->pairwise_cipher = AUTH_CIPHER_NONE;
		if (key_idx == conn->default_key)
			conn->default_key = -1;
		ret = sprdwl_cmd_del_key(drv->drv_priv, key_idx, sa_addr);
		return ret;
	case WPA_ALG_WEP:
		if (key_len == 5)
			conn->cipher = SPRDWL_CIPHER_WEP40;
		else if (key_len == 13)
			conn->cipher = SPRDWL_CIPHER_WEP104;
		break;
	case WPA_ALG_TKIP:
		conn->cipher = SPRDWL_CIPHER_TKIP;
		break;
	case WPA_ALG_CCMP:
		conn->cipher = SPRDWL_CIPHER_CCMP;

		break;
	case WPA_ALG_PMK:
		if (key_len == PMK_LEN){
			conn->psk_len= key_len;
			os_memcpy(conn->psk, key, key_len);
			ret = sprdwl_cmd_set_psk(drv->drv_priv, conn->psk, conn->psk_len);
			return ret;
		}
		break;
	default:
		wpa_printf(MSG_DEBUG, "%s: Unknown algorithm %d",
			   __FUNCTION__, alg);
		return -1;
	}
	if (key_len){		
		conn->key_len[pairwise][key_idx] = key_len;
		os_memcpy(conn->key[pairwise][key_idx], key, key_len);
	}

	
	ret = sprdwl_cmd_add_key(drv->drv_priv, conn->key[pairwise][key_idx],
				   conn->key_len[pairwise][key_idx],
				   pairwise, key_idx, seq,
				   conn->cipher, sa_addr);

	return ret;
}


struct wpa_scan_results * wpa_driver_direct_get_scan_results(void *priv)
{
	struct wpa_driver_direct_data *drv = priv;
	struct wpa_scan_results *res;
	int  i = 0, numbss = 0, bss_len = 0;

	res = os_zalloc(sizeof(*res));
	if (res == NULL) {
		goto fail;
	}
	/* get number of bss */
	numbss = sprdwl_get_scan_results(drv->drv_priv, 0xff, NULL, 0);
	res->res = os_zalloc(sizeof (struct wpa_scan_res *) * numbss);
	if (res->res == NULL){
		goto fail;		
	}
	
	for (i = 0; i < numbss; i++) {
		bss_len = sprdwl_get_scan_results(drv->drv_priv,  i, NULL, 0);
		res->res[i] = os_zalloc(bss_len);
		if (res->res[i] == NULL)
			return res;
		sprdwl_get_scan_results(drv->drv_priv, i, res->res[i], bss_len);
		res->num++;		
	}

	return res;
fail:
	if (res){
		if (res->res){
			os_free(res->res);
		}			
		os_free(res);
	}
	return NULL;
}
static void rtos_drv_send_message(struct wpa_driver_direct_data *drv, u8 cmd, u8 *data, u32 len)
{
	u32 millsec = SCI_WAIT_FOREVER;
	struct msg_dscr dscr;

	os_memset(&dscr, 0, sizeof(struct msg_dscr));
	
	dscr.hd.type = MSG_TYPE_DRIVER;
	dscr.evts.evt_type= EVT_TYPE_WIRELESS;
	dscr.evts.evt_subtype = cmd;

	if (SCI_SendMsg(drv->msg_q, (const char *)&dscr, millsec)) {
		wpa_printf(MSG_ERROR, "%s send message failed\n", __func__);
	}
}

void rtos_drv_send_scan_complete(struct wpa_driver_direct_data *drv)
{
	rtos_drv_send_message(drv, DRV_SCAN_DONE, NULL, 0);
}

void rtos_drv_rx_eapol(struct wpa_driver_direct_data *drv, const u8 *data, u32 len)
{
	struct msg_dscr dscr;
	u32 millsec = SCI_WAIT_FOREVER;
	
	os_memset(&dscr, 0, sizeof(struct msg_dscr));
	dscr.evts.data = os_zalloc(len);
	if (dscr.evts.data == NULL)
		return;
	
	dscr.hd.type = MSG_TYPE_DRIVER;
	dscr.evts.evt_type = EVT_TYPE_EAPOL;	

	os_memcpy(dscr.evts.data, data, len);

	if (SCI_SendMsg(drv->msg_q, (const char *)&dscr, millsec)) {
		wpa_printf(MSG_ERROR, "%s send message failed\n", __func__);
	}

	return;
}
static void wpa_driver_direct_event_wireless(struct wpa_driver_direct_data *drv, int subtype,
					   char *data, int len)
{
		switch (subtype) {

		case DRV_SCAN_DONE:
			eloop_cancel_timeout(wpa_driver_direct_scan_timeout,
					     drv, drv->ctx);
			wpa_supplicant_event(drv->ctx, EVENT_SCAN_RESULTS,
					     NULL);
			break;
		default:
			break;
		}

}
static int wpa_driver_rtos_event(void *ctx, char *buf)
{
#define ETH_HEAD_LEN		(ETH_ALEN + ETH_ALEN + 2)
	struct wpa_driver_direct_data *drv = ctx;
	struct msg_dscr *dscr = (struct msg_dscr *)buf;


	switch (dscr->evts.evt_type) {
	case EVT_TYPE_WIRELESS:
		wpa_driver_direct_event_wireless(drv,  dscr->evts.evt_subtype, dscr->evts.data,
					       dscr->evts.dlen);
		break;
	case EVT_TYPE_EAPOL:
		/* @buf: EAPOL data starting from the EAPOL header */
		wpa_supplicant_rx_eapol(drv->ctx, (const u8 *)(dscr->evts.data) + ETH_ALEN,
					(const u8 *)(dscr->evts.data) + ETH_HEAD_LEN,
					dscr->evts.dlen - ETH_HEAD_LEN);
		break;
	default:
		wpa_printf(MSG_WARNING, "Warning: Invalid event 0x%x!\n",
			   dscr->evts.evt_type);
		return -1;
	}
	return 0;
}
const struct wpa_driver_ops wpa_driver_direct_ops = {
	.name = "direct",
	.desc = " rtos direct access cp (generic)",
	.set_key = wpa_driver_direct_set_key,

	.get_bssid = wpa_driver_direct_get_bssid,
	.get_ssid = wpa_driver_direct_get_ssid,
	.set_countermeasures = wpa_driver_direct_set_countermeasures,
	.scan2 = wpa_driver_direct_scan,
	.get_scan_results2 = wpa_driver_direct_get_scan_results,
	.deauthenticate = wpa_driver_direct_deauthenticate,
	.associate = wpa_driver_direct_associate,
	.init = wpa_driver_direct_init,
	.deinit = wpa_driver_direct_deinit,
	.add_pmkid = wpa_driver_direct_add_pmkid,
	.remove_pmkid = wpa_driver_direct_remove_pmkid,
	.flush_pmkid = wpa_driver_direct_flush_pmkid,
	.get_capa = wpa_driver_direct_get_capa,
	.send_eapol = wpa_driver_direct_send_eapol,
	.get_mac_addr = wpa_driver_direct_get_mac_addr,
};
