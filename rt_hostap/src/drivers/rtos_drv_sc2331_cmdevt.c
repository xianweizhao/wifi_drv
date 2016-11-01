#include <string.h>
#include "rtos_drv_sc2331.h"
#include "rtos_drv_sc2331_cmdevt.h"

#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "rtos_drv_intf_common.h"
#include "utils/list.h"

#define  CMD_WAIT_TIMEOUT  (3000)

static bool cmd_is_waiting = false;
static SCI_SEMAPHORE_PTR cmd_sem;
static struct sprdwl_send_buf send_buf;
static unsigned short recv_len;
static unsigned char recv_buf[RECV_BUF_SIZE];
static wifi_recv_mon_cb_t mon_cb;
static struct sprdwl_send_buf send_buf;

static struct sprdwl_priv g_priv;
/* send cmd */
static int sprdwl_cmd_wait_rsp(unsigned int timeout)
{
	if (cmd_sem == NULL) {
		pr_error("%s NULL pointer.\n", __func__);
		return -1;
	}
	cmd_is_waiting = true;

	if (SCI_ERROR == SCI_GetSemaphore(cmd_sem, timeout)) {
		pr_error("%s wait command timeout(%d ms).\n",
				__func__, timeout);

		cmd_is_waiting = false;
		return -1;
	}

	cmd_is_waiting = false;

	return 0;
}

static int sprdwl_cmd_send_recv(unsigned char vif_id, unsigned char *pData, int len,
			 int subtype, int timeout)
{
	struct sprdwl_priv *priv = sprdwl_get_priv();
	struct sprdwl_tx_big_hdr *big_hdr;
	struct sprdwl_msg_hdr *msg_hdr;
	int send_len = 0;
	int ret;
	int *state;

	big_hdr = &(send_buf.big_hdr);
	msg_hdr = &(big_hdr->msg[0]);

	msg_hdr->mode = vif_id;
	msg_hdr->type = HOST_SC2331_CMD;
	msg_hdr->subtype = subtype;
	msg_hdr->len = len;

	big_hdr->mode = vif_id;
	big_hdr->msg_num = 1;
	big_hdr->tx_cnt = priv->tx_cnt;

	/* rewrite msg hdr */
	os_memcpy(&(send_buf.msg_hdr), msg_hdr, sizeof(*msg_hdr));

	send_len = sizeof(struct sprdwl_tx_big_hdr) +
		sizeof(struct sprdwl_msg_hdr) + len;

	big_hdr->len = send_len;

	pr_info("%s send cmd (%d) to cp2, vif(%d) len(%d), timeout(%d ms).\n",
			__func__, subtype, vif_id, send_len, timeout);

	ret = sprdwl_intf_tx((unsigned char *)&send_buf, send_len);
	if (ret)
		return -1;
    
	ret = sprdwl_cmd_wait_rsp(timeout);
	if (ret)
		return -1;

	msg_hdr = (struct sprdwl_msg_hdr *)recv_buf;
	if (msg_hdr->type != SC2331_HOST_RSP || msg_hdr->subtype != subtype) {
		pr_error("%s recv invalid msg header type(%d), subtype(%d)",
				__func__, msg_hdr->type, msg_hdr->subtype);
		return -1;
	}

	priv->tx_cnt++;

	state = (int *)(&recv_buf[sizeof(struct sprdwl_msg_hdr)]);
	pr_info("%s recv cmd response, status: %d.\n", __func__, *state);

	if (WIFI_CMD_SET_SCAN == subtype) {
		state = (int *)(&recv_buf[sizeof(struct sprdwl_msg_hdr)]);
		return *state;
	}

	return 0;
}



static int sprdwl_cmd_mac_open(unsigned char vif_id, unsigned char mode,
		      unsigned char *mac_addr)
{
	int ret;
	struct wlan_cmd_mac_open *mac_open = (void *)send_buf.cmd;

	mac_open->mode = mode;
	if (NULL != mac_addr)
		os_memcpy((unsigned char *)(&(mac_open->mac[0])), mac_addr, 6);

	ret =
	    sprdwl_cmd_send_recv(vif_id, (unsigned char *)mac_open,
				 sizeof(struct wlan_cmd_mac_open),
				 WIFI_CMD_SET_DEV_OPEN, 10000);
	return ret;
}

static int sprdwl_cmd_mac_close(unsigned char vif_id, unsigned char mode)
{
	struct wlan_cmd_mac_close *mac_close = (void *)send_buf.cmd;

	mac_close->mode = mode;
	sprdwl_cmd_send_recv(vif_id, (unsigned char *)(mac_close),
			     sizeof(struct wlan_cmd_mac_close),
			     WIFI_CMD_SET_DEV_CLOSE, CMD_WAIT_TIMEOUT);
	return 0;
}

int sprdwl_cmd_scan(struct sprdwl_priv *priv, const unsigned char *ssid,
		  const unsigned char *channels, int len)
{
	int dataLen;
	struct wlan_cmd_scan *scan;
	unsigned char *mac_send = (void *)send_buf.cmd;
	unsigned char *psend = mac_send;
	u8 ch_default[14] = {13,1,2,3,4,5,6,7,8,9,10,11,12,13};

	unsigned char ch_num = 0;
	/* default channel full */
	if (channels == NULL){
		ch_num = ch_default[0] + 1;
		os_memcpy(mac_send, ch_default, ch_num);
		mac_send += ch_num;
	} else {
		ch_num = channels[0] + 1;
		os_memcpy(mac_send, channels, ch_num);
		mac_send += ch_num;
	}
	
	dataLen = sizeof(struct wlan_cmd_scan) + len + ch_num;

	if (len > 0) {
		scan = (struct wlan_cmd_scan *)mac_send;
		os_memcpy(scan->ssid, ssid, len);
		scan->len = len;
	}
	priv->scan_state.state = SCAN_IN_PROGRESS;
	sprdwl_cmd_send_recv(priv->vif_id, (unsigned char *)psend, dataLen,
			     WIFI_CMD_SET_SCAN, 20*1000);
	return 0;
}

int sprdwl_cmd_disassoc(struct sprdwl_priv *priv, const unsigned char *mac_addr,
		unsigned short reason_code)
{
	int dataLen = 0;
	struct wlan_cmd_disassoc *ptr = (void *)send_buf.cmd;

	dataLen = sizeof(struct wlan_cmd_disassoc);

	os_memcpy(&(ptr->mac[0]), mac_addr, 6);
	ptr->reason_code = reason_code;

	sprdwl_cmd_send_recv(priv->vif_id, (unsigned char *)ptr, dataLen,
			WIFI_CMD_DISASSOC, CMD_WAIT_TIMEOUT);

	return 0;
}

int sprdwl_cmd_disconnect(struct sprdwl_priv *priv, unsigned short reason_code)
{

	int dataLen;
	struct wlan_cmd_disconnect *ptr = (void *)send_buf.cmd;

	dataLen = sizeof(struct wlan_cmd_disconnect);

	ptr->reason_code = reason_code;

	sprdwl_cmd_send_recv(priv->vif_id, (unsigned char *)ptr, dataLen,
			WIFI_CMD_SET_DISCONNECT, CMD_WAIT_TIMEOUT);

	return 0;
}


int sprdwl_cmd_set_wpa_version(struct sprdwl_priv *priv,  unsigned int wpa_version)
{
	int dataLen;
	struct wlan_cmd_set_wpa_version *ptr = (void *)send_buf.cmd;

	dataLen = sizeof(struct wlan_cmd_set_wpa_version);

	ptr->wpa_version = wpa_version;

	sprdwl_cmd_send_recv(priv->vif_id, (unsigned char *)ptr, dataLen,
			WIFI_CMD_SET_WPA_VERSION, CMD_WAIT_TIMEOUT);

	return 0;
}

int sprdwl_cmd_set_auth_type(struct sprdwl_priv *priv, unsigned int type)
{
	int dataLen;
	struct wlan_cmd_set_auth_type *ptr = (void *)send_buf.cmd;

	dataLen = sizeof(struct wlan_cmd_set_auth_type);

	ptr->type = type;

	sprdwl_cmd_send_recv(priv->vif_id, (unsigned char *)ptr, dataLen,
			WIFI_CMD_SET_AUTH_TYPE, CMD_WAIT_TIMEOUT);

	return 0;
}

int sprdwl_cmd_set_pairwise_cipher(struct sprdwl_priv *priv, unsigned int cipher)
{
	int dataLen;
	struct wlan_cmd_set_cipher *ptr = (void *)send_buf.cmd;

	dataLen = sizeof(struct wlan_cmd_set_cipher);

	ptr->cipher = cipher;

	sprdwl_cmd_send_recv(priv->vif_id, (unsigned char *)ptr, dataLen,
			WIFI_CMD_SET_PAIRWISE_CIPHER, CMD_WAIT_TIMEOUT);

	return 0;
}

int sprdwl_cmd_set_group_cipher(struct sprdwl_priv *priv, unsigned int cipher)
{
	int dataLen;
	struct wlan_cmd_set_cipher *ptr = (void *)send_buf.cmd;

	dataLen = sizeof(struct wlan_cmd_set_cipher);

	ptr->cipher = cipher;

	sprdwl_cmd_send_recv(priv->vif_id, (unsigned char *)ptr, dataLen,
			WIFI_CMD_SET_GROUP_CIPHER, CMD_WAIT_TIMEOUT);

	return 0;
}

int sprdwl_cmd_set_key_management(struct sprdwl_priv *priv, unsigned char key_mgmt)
{
	int dataLen;
	struct wlan_cmd_set_key_management *ptr = (void *)send_buf.cmd;

	dataLen = sizeof(struct wlan_cmd_set_key_management);

	ptr->key_mgmt = key_mgmt;

	sprdwl_cmd_send_recv(priv->vif_id, (unsigned char *)ptr, dataLen,
			WIFI_CMD_SET_AKM_SUITE, CMD_WAIT_TIMEOUT);

	return 0;
}

int sprdwl_cmd_set_psk(struct sprdwl_priv *priv, const unsigned char *key,
		unsigned int key_len)
{
	int dataLen;
	struct wlan_cmd_set_psk *ptr = (void *)send_buf.cmd;

	dataLen = sizeof(struct wlan_cmd_set_psk) + key_len;

	ptr->len = key_len;
	os_memcpy(ptr->key,  key, key_len);

	sprdwl_cmd_send_recv(priv->vif_id, (unsigned char *)ptr, dataLen,
			WIFI_CMD_SET_PSK, CMD_WAIT_TIMEOUT);

	return 0;
}

int sprdwl_cmd_set_channel(unsigned char vif_id, unsigned int channel)
{
	int dataLen;
	struct wlan_cmd_set_channel *ptr = (void *)send_buf.cmd;

	dataLen = sizeof(struct wlan_cmd_set_channel);

	ptr->channel = channel;

	sprdwl_cmd_send_recv(vif_id, (unsigned char *)ptr, dataLen,
			WIFI_CMD_SET_CHANNEL, CMD_WAIT_TIMEOUT);

	return 0;
}

int sprdwl_cmd_set_bssid(struct sprdwl_priv *priv, const unsigned char *addr)
{
	int dataLen;
	struct wlan_cmd_set_bssid *ptr = (void *)send_buf.cmd;

	dataLen = sizeof(struct wlan_cmd_set_bssid);

	os_memcpy(&(ptr->addr[0]),  addr,  6);

	sprdwl_cmd_send_recv(priv->vif_id, (unsigned char *)ptr, dataLen,
			WIFI_CMD_SET_BSSID, CMD_WAIT_TIMEOUT);

	return 0;
}

int sprdwl_cmd_set_essid(struct sprdwl_priv *priv, const unsigned char *essid,
		int essid_len)
{

	int dataLen;
	struct wlan_cmd_set_essid *ptr = (void *)send_buf.cmd;

	dataLen = sizeof(struct wlan_cmd_set_essid) + essid_len;

	ptr->len = essid_len;
	os_memcpy(ptr->essid,  essid,  essid_len);

	return sprdwl_cmd_send_recv(priv->vif_id, (unsigned char *)ptr,
			dataLen, WIFI_CMD_SET_ESSID, CMD_WAIT_TIMEOUT);
}

int sprdwl_cmd_add_key(struct sprdwl_priv *priv,
		const unsigned char *key_data,
		unsigned char key_len,
		unsigned char pairwise,
		unsigned char key_index,
		const unsigned char *key_seq,
		unsigned char cypher_type,
		const unsigned char *pmac)
{

	int dataLen;
	struct wlan_cmd_add_key *ptr = (void *)send_buf.cmd;

	dataLen = sizeof(struct wlan_cmd_add_key)+key_len;

	os_memset(ptr, 0, dataLen);

	ptr->cypher_type = cypher_type;
	if (key_seq != NULL)
		os_memcpy(ptr->keyseq, key_seq, 8);
	ptr->key_index = key_index;
	ptr->key_len = key_len;
	if (pmac != NULL)
		os_memcpy(ptr->mac, pmac, 6);
	ptr->pairwise = pairwise;
	if (NULL != key_data)
		os_memcpy(ptr->value, key_data, key_len);

	sprdwl_cmd_send_recv(priv->vif_id, (unsigned char *)ptr, dataLen,
			WIFI_CMD_KEY_ADD, CMD_WAIT_TIMEOUT);

	return 0;
}

int sprdwl_cmd_del_key(struct sprdwl_priv *priv, unsigned short key_index,
		const unsigned char *mac_addr)
{
	int dataLen = 0;
	struct wlan_cmd_del_key *ptr = (void *)send_buf.cmd;

	dataLen = sizeof(struct wlan_cmd_del_key);

	os_memset(ptr, 0, dataLen);
	ptr->key_index = key_index;
	if (NULL != mac_addr)
		os_memcpy(&(ptr->mac[0]),  mac_addr,  6);

	sprdwl_cmd_send_recv(priv->vif_id, (unsigned char *)ptr, dataLen,
			WIFI_CMD_KEY_DEL, CMD_WAIT_TIMEOUT);

	return 0;
}

int sprdwl_cmd_set_key(struct sprdwl_priv *priv, unsigned char key_index)
{

	int dataLen;
	struct wlan_cmd_set_key *ptr = (void *)send_buf.cmd;

	dataLen = sizeof(struct wlan_cmd_set_key);

	ptr->key_index = key_index;

	sprdwl_cmd_send_recv(priv->vif_id, (unsigned char *)ptr, dataLen,
			WIFI_CMD_KEY_SET, CMD_WAIT_TIMEOUT);

	return 0;
}

int sprdwl_cmd_set_ie(struct sprdwl_priv *priv, unsigned char type,
		      const unsigned char *ie, unsigned short len)
{
	int ret;
	int dataLen;
	struct wlan_cmd_set_ie *ptr = (void *)send_buf.cmd;
#if 1
	return 0;
#else
	dataLen = sizeof(struct wlan_cmd_set_ie) + len;

	ptr->type = type;
	ptr->len = len;
	os_memcpy(ptr->data, ie, len);

	ret = sprdwl_cmd_send_recv(priv->vif_id, (unsigned char *)ptr, dataLen,
			WIFI_CMD_P2P_IE, CMD_WAIT_TIMEOUT);

	return ret;
#endif
}

int sprdwl_cmd_start_ap(unsigned char vif_id, unsigned char *beacon,
		unsigned short len)
{
	int ret;
	int dataLen;
	struct wlan_cmd_beacon *ptr = (void *)send_buf.cmd;

	SCI_Sleep(1000);

	dataLen = sizeof(struct wlan_cmd_beacon) + len;

	ptr->len = len;
	os_memcpy(ptr->data, beacon, len);

	ret = sprdwl_cmd_send_recv(vif_id, (unsigned char *)ptr, dataLen,
			WIFI_CMD_START_BEACON, CMD_WAIT_TIMEOUT);

	return ret;
}

int sprdwl_cmd_send_common_data(unsigned char vif_id, unsigned char *data,
		int len)
{
	int dataLen;
	void *ptr = (void *)send_buf.cmd;

	if (data == NULL || len == 0) {
		pr_error("%s data is NULL\n", __func__);
		return -1;
	}

	os_memcpy(ptr, data, len);
	dataLen = len;

	sprdwl_cmd_send_recv(vif_id, (unsigned char *)ptr, dataLen,
			WIFI_CMD_COMMON_DATA, CMD_WAIT_TIMEOUT);

	return 0;
}

int sprdwl_monitor_register_cb(wifi_recv_mon_cb_t cb)
{
	mon_cb = cb;

	return 0;
}

int sprdwl_cmd_set_monitor_mode(unsigned char vif_id, unsigned char flag)
{
	struct wlan_send_common_data common_data;

	os_memset(&common_data, 0, sizeof(common_data));
	common_data.type = flag ? COMMON_TYPE_MONITOR_START :
		COMMON_TYPE_MONITOR_STOP;

	if (common_data.type == COMMON_TYPE_MONITOR_STOP)
		sprdwl_monitor_register_cb(NULL);

	return sprdwl_cmd_send_common_data(vif_id, &common_data,
			sizeof(common_data));
}

int sprdwl_cmd_npi(unsigned char *in_buf, unsigned short in_len, unsigned char *out_buf, unsigned short *out_len)
{
	void *ptr = (void *)send_buf.cmd;
	int dataLen = in_len;

	os_memcpy(ptr, in_buf, in_len);

	sprdwl_cmd_send_recv(0, ptr, dataLen,
			WIFI_CMD_NPI_MSG, CMD_WAIT_TIMEOUT);

	pr_info("npi recv resp buf: %p, len: %d.\n", recv_buf, recv_len);
	*out_len = recv_len - sizeof(struct sprdwl_msg_hdr);
	os_memcpy(out_buf, recv_buf + sizeof(struct sprdwl_msg_hdr), *out_len);

	return 0;
}


int sprdwl_wifi_tx_data(unsigned char *data, unsigned short len)
{
	static unsigned int seq;
	int send_len;
	struct sprdwl_tx_big_hdr *big_hdr;
	struct sprdwl_msg_hdr *msg_hdr;
	//pr_info("%s tx data len: %d\n", __func__, len);

	if(len > SEND_BUF_SIZE) {
		pr_error("invalid data len %d!\n", len);
		return -1;
	}

	big_hdr = &(send_buf.big_hdr);
	msg_hdr = &(big_hdr->msg[0]);

	msg_hdr->mode = 0;
	msg_hdr->type = HOST_SC2331_PKT;
	msg_hdr->subtype = 0;
	msg_hdr->len = len;
	os_memcpy(send_buf.cmd + 34 , data, len);
	os_memcpy(send_buf.cmd, &seq, 4);
	seq++;

	big_hdr->mode = 0;
	big_hdr->msg_num = 1;

	/* rewrite msg hdr */
	os_memcpy(&(send_buf.msg_hdr), msg_hdr, sizeof(*msg_hdr));

	send_len = sizeof(struct sprdwl_tx_big_hdr) +
	sizeof(struct sprdwl_msg_hdr) + len + 34;

	big_hdr->len = send_len;

	return sprdwl_intf_tx((unsigned char *)&send_buf, send_len);
}
unsigned short sprdwl_rx_rsp_process(struct sprdwl_priv *priv,
				     unsigned char *data, unsigned short len)
{
	int count;

	if (len > RECV_BUF_SIZE) {
		pr_error("%s invalid data len %d.\n", __func__, len);
		return -1;
	}

	if (!cmd_is_waiting) {
		pr_error("cmd is not SYNC! Which means timeout in driver is less than in CP!\n");
		return -1;
	}

	os_memcpy(recv_buf, data, len);
	recv_len = len;

	if (cmd_sem == NULL) {
		pr_error("%s NULL pointer.\n", __func__);
		return -1;
	}
	count = sxr_SemaphoreGetValue(cmd_sem);
	if (count < 0)
		SCI_PutSemaphore(cmd_sem);

	return 0;
}

static int sprdwl_store_scan_results(struct sprdwl_priv *priv, unsigned short signal,
					void *data, unsigned int len)
{
	struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *)data;
	struct sprdwl_bss_info *bss;
	struct ieee802_11_elems elems;
	size_t offset = offsetof(struct ieee80211_mgmt, u.beacon.variable);
	size_t ie_len = len - offset;
	int channel;
	u8 ssid_tmp[32];	
	u8 i;

	/* check probe respose & beacon mgmt ies */
	if(ieee802_11_parse_elems((void *)mgmt + offset, ie_len, &elems, 1))
		return -1;

	for (i = 0; i < priv->bss_count; i++) {
		if (!os_memcmp(priv->bss[i].res.bssid, mgmt->bssid, ETH_ALEN)) {
			bss = &priv->bss[i];
			goto store_result;
		}
	}

	if (priv->bss_count < MAX_BSS_ENTRIES) {
		bss = &priv->bss[priv->bss_count];
		priv->bss_count++;

	} else {
		pr_error("%s no enough bss space\n", __func__);
		return -2;
	}

store_result:
	
	os_memset(ssid_tmp, 0, 32);
	os_memcpy(ssid_tmp, elems.ssid, elems.ssid_len);
	wpa_printf(MSG_INFO, "store scan ap: %s \n", ssid_tmp);
	

	/* BSSID */
	os_memcpy(bss->res.bssid, mgmt->bssid, ETH_ALEN);
	/* signal */		
	bss->res.level = signal;

	/* Channel */
	extern int wpas_channel_to_freq(int chan);
	if (elems.ds_params) {
		os_memcpy(&channel, elems.ds_params, elems.ds_params_len);
		bss->res.freq = wpas_channel_to_freq(channel);
	}
	/* cap_info */
	bss->res.caps = mgmt->u.beacon.capab_info;
	
	/* beacon_intval */
	bss->res.beacon_int =  mgmt->u.beacon.beacon_int;
	
	ie_len = 0;
	/* ssid & support rate & wpa & rsn */
	if (elems.rsn_ie_len) {
		os_memcpy((bss->ie + ie_len), (elems.ssid - 2), (elems.ssid_len + 2));
		ie_len += elems.ssid_len +2;
	}
	
	if (elems.wpa_ie_len) {
		os_memcpy((bss->ie + ie_len), (elems.wpa_ie - 2), (elems.wpa_ie_len + 2));
		ie_len += elems.wpa_ie_len +2;
	}

	if (elems.rsn_ie_len) {
		if ((ie_len + elems.wpa_ie_len +2) > MAX_IE_LEN) 
			wpa_printf(MSG_ERROR, "ie mem not enough failed \n");
		os_memcpy((bss->ie + ie_len), (elems.rsn_ie - 2), (elems.rsn_ie_len + 2));
		ie_len += elems.wpa_ie_len +2;
	}

	return 0;
}

  
int sprdwl_get_scan_results(struct sprdwl_priv *priv, int  index, void *data,  int dlen)

{
	struct sprdwl_bss_info *bss = NULL;
	int len = 0;
	int i = 0;
	
	/* supplicant get number bss */
	if (index == 0xff)
		return priv->bss_count;
	
	if (index < 0 || index >= priv->bss_count){
		wpa_printf(MSG_ERROR, "inval index\n");
		return  -1;
	}

	/* supplciant get ie_len  for malloc mem*/
	bss = &priv->bss[index];
	len += sizeof (struct sprdwl_wpas_scanres);
	len += bss->ie_len;
	if (data == NULL)
		return len;
	
	if (dlen < len)
		return -1;
	
	len = 0;
	os_memcpy(data + len, &bss->res, sizeof (struct sprdwl_wpas_scanres));
	len += sizeof (struct sprdwl_wpas_scanres);
	os_memcpy(data + len, &bss->ie, bss->ie_len);
	len += bss->ie_len;	

	return len;

}
int sprdwl_process_scan_event(struct sprdwl_priv *priv,
				     void *data, unsigned int len)
{
	struct sprdwl_scan_result_event *event =
		(struct sprdwl_scan_result_event *)data;
	size_t offset = offsetof(struct sprdwl_scan_result_event, mgmt);

	if (priv->scan_state.state != SCAN_IN_PROGRESS) {
		pr_error("%s Invalid scan result report\n", __func__);
		return -1;
	}
	if (event->type == SPRDWL_SCAN_FRAME) {
		sprdwl_store_scan_results(priv, event->signal, data + offset, event->len);
		return 0;
	}

	if (event->type == SPRDWL_SCAN_DONE) {
		priv->scan_state.state = SCAN_IN_DONE;
		rtos_drv_send_scan_complete(priv->drv);
	}

	return 0;
}
int sprdwl_process_connect_event(struct sprdwl_priv *priv,
				     void *data, unsigned int len)
{
#if 0
	struct sprdwl_conn_param *conn = &priv->conn;
	/*
	 * byte[0]: status code len
	 * byte[1]: reassociate rsp flag
	 * byte[2]: status code
	 * byte[3-4]: bssid len
	 * byte[5-10]: bssid
	 * byte[11]: req ie len
	 * req ie
	 * resp ie len
	 * resp ie
	 * */
	u32 left = len;
	const char *pos = data;
	const char *bssid = NULL;
	const char *req_ie, *resp_ie;
	u8 req_ie_len, resp_ie_len;
	/* unsigned char reassoc = pos[1]; */
	unsigned char status = pos[2];

	/* skip status, status len, bssid len*/
	pos += 5;
	left -= 5;

	/* bssid */
	if (left >= ETH_ALEN) {
		bssid = pos;
		/* skip bssid*/
		pos += ETH_ALEN;
		left -= ETH_ALEN;
	}

	/* req ie stuff */
	if (left > 0) {
		/* req ie len */
		req_ie_len = *pos;
		/* skip req ie len */
		pos += 1;
		left -= 1;
		/* req ie */
		req_ie = pos;
		if (req_ie && status == WLAN_STATUS_SUCCESS) {
			wireless_send_event(wireless, IWEVASSOCREQIE, &wrqu, req_ie);
		}
		/* skip req ie len */
		pos += req_ie_len;
		left -= req_ie_len;
	}

	/* resp ie stuff */
	if (left > 0) {
		/* resq ie len */
		resp_ie_len = *pos;

		/* skip resp ie len */
		pos += 1;
		left -= 1;
		/* resp ie */
		resp_ie = pos;
		if (resp_ie && status == WLAN_STATUS_SUCCESS) {
			os_memset(&wrqu, 0, sizeof(wrqu));
			wrqu.data.length = resp_ie_len;
			wpa_driver_direct_event_wireless_assocrespie(
				drv, resp_ie, resp_ie_len);
			wireless_send_event(wireless, IWEVASSOCRESPIE, &wrqu, resp_ie);
		}
	}

	/* send connect event */
	os_memset(&wrqu, 0, sizeof(wrqu));

	wrqu.ap_addr.sa_family = ARPHRD_ETHER;
	if (bssid && status == WLAN_STATUS_SUCCESS) {
		os_memcpy(wrqu.ap_addr.sa_data, bssid, ETH_ALEN);
		if (os_memcmp(conn->bssid, bssid, ETH_ALEN))
			pr_info("Warning FW conn AP not same as wpa supp!\n");
		os_memcpy(conn->bssid, bssid, ETH_ALEN);
		iprv->current_bss = conn->bssid;
		pr_info("%s connection success!\n", __func__);
	} else {
		pr_info("%s connection failed, status %d!\n", __func__, status);
	}

	wireless_send_event(wireless, SIOCGIWAP, &wrqu, NULL);
#endif
	return 0;
}

int sprdwl_process_disconnect_event(struct sprdwl_priv *priv,
				     void *data, unsigned int len)
{
	return 0;

}
unsigned short sprdwl_rx_event_process(struct sprdwl_priv *priv,
				       unsigned char event, unsigned char *data,
				       unsigned short len)
{
	switch (event) {
	case WIFI_EVENT_CONNECT:
		sprdwl_process_connect_event(priv, data, len);
		break;
	case WIFI_EVENT_DISCONNECT:
		sprdwl_process_disconnect_event(priv,
				     data, len);
		break;
	case WIFI_EVENT_REPORT_FRAME:
		if (data && len > 4) {
			data += 4;
			len -= 4;
			/* data_dump(data, len); */
			if (mon_cb != NULL)
				mon_cb(data, len, NULL);
		}
		break;
	case WIFI_EVENT_REPORT_SCAN_FRAME:
		sprdwl_process_scan_event(priv,
				  data, len);

		break;
	default:
		break;
	}
	return 0;
}

struct sprdwl_if_ops *sprdwl_get_if_ops(void)
{
	return g_priv.if_ops;
}

struct sprdwl_priv *sprdwl_get_priv(void)
{
	return &g_priv;
}

int sc2331_set_mode(int mode)
{
	if ((mode != ITM_STATION_MODE) &&
		(mode != ITM_AP_MODE)) {
		pr_error("sc2331 unsupported mode: %d\n", mode);
		return -1;
	}

	g_priv.mode = mode;

	return 0;
}

int sc2331_ifup(struct sprdwl_priv *priv)
{
    int ret;

     if (priv->mode == ITM_NONE_MODE) {
		pr_error("invalid wifi mode: %d.\n", priv->mode);
		return -1;
     }

    ret = sprdwl_cmd_mac_open(priv->vif_id, priv->mode,
	    priv->d_mac.ether_addr_octet);

	if(0 == ret)
		IFF_SET_UP(priv->d_flags);
    return 0;
}

int sc2331_ifdown(struct sprdwl_priv *priv)
{
	int ret;

	pr_info("%s taking down sc2331, mode: %d.\n", __func__, priv->mode);

       ret = sprdwl_cmd_mac_close(priv->vif_id, priv->mode);

	if(0 == ret)
		IFF_CLR_UP(priv->d_flags);

    return 0;
}

UINT8* wifi_get_localMac(void)
{
  printf("%s enter\n",__func__);
  struct sprdwl_priv *priv = sprdwl_get_priv();
  return priv->d_mac.ether_addr_octet;
}
struct sprdwl_priv * sprdwl_init(struct wpa_driver_direct_data *drv)
{
	struct sprdwl_priv *priv = &g_priv;
	int ret = 0;
	printf("%s enter\n",__func__);	
	os_memset(&send_buf, 0, sizeof(struct sprdwl_send_buf));
	os_memset(recv_buf, 0, RECV_BUF_SIZE);
	os_memset(priv, 0, sizeof(*priv));

	priv->vif_id = 0;
	priv->mode = ITM_STATION_MODE;

	/* Register data recv interface to SDIO */
	sprdwl_intf_init(priv);

	ret = sprdwl_rx_init();
	/* Set MAC address to priv */
	priv->d_mac.ether_addr_octet[0] = 0x40;
	priv->d_mac.ether_addr_octet[1] = 0x45;
	priv->d_mac.ether_addr_octet[2] = 0xDA;
	priv->d_mac.ether_addr_octet[3] = 0x13;
	priv->d_mac.ether_addr_octet[4] = 0x14;
	priv->d_mac.ether_addr_octet[5] = 0x15;

	priv->wiphy = register_wireless_device((void *)priv);
	if (!priv->wiphy)
		return NULL;
	priv->drv = drv;
    	ret = sprdwl_cmd_mac_open(priv->vif_id, priv->mode,
	    priv->d_mac.ether_addr_octet);
	return priv;
}

