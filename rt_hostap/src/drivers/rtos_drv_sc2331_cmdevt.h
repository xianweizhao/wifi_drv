#ifndef __RTOS_DRV_SC2331_CMDEVT_H__
#define __RTOS_DRV_SC2331_CMDEVT_H__
#include "rtos_direct_drv.h"
#include "rtos_drv_sc2331_cp_defs.h"

/* used to send data/cmd to sdio */
#define SEND_BUF_SIZE	(1024 * 2)

struct sprdwl_priv;

struct sprdwl_msg_hdr {
	unsigned char type:7;	/* CMD/RSP/USER DATA */
	unsigned char mode:1;	/* message dest mode: 1 STA, 2 softAP, 3 P2P */
	unsigned char subtype;	/* SEARCH/ ATTACH/DETACH */
	unsigned short len;	/* Length not include common header */
};

struct sprdwl_tx_big_hdr {
	unsigned char mode;
	unsigned char msg_num;
	unsigned short len;
	struct sprdwl_msg_hdr msg[14];
	unsigned int tx_cnt;
};

struct sprdwl_send_buf {
	struct sprdwl_tx_big_hdr big_hdr;
	struct sprdwl_msg_hdr	msg_hdr;
	unsigned char cmd[SEND_BUF_SIZE];
};

enum wlan_mode {
	ITM_NONE_MODE,
	ITM_STATION_MODE,
	ITM_AP_MODE,
	ITM_NPI_MODE,
	ITM_P2P_CLIENT_MODE,
	ITM_P2P_GO_MODE,
};

enum ITM_HOST_TROUT3_CMD_TYPE {
	HOST_SC2331_CMD = 0, /* cp to host driver event */
	SC2331_HOST_RSP, 	/*cmd rsp */
	HOST_SC2331_PKT,	/* cp to host driver data packet */
	HOST_SC2331_WAPI,
};

enum ITM_HOST_TROUT3_CMD_LIST {
	WIFI_CMD_GET_MODE = 1,
	WIFI_CMD_GET_RSSI,
	WIFI_CMD_GET_TXRATE_TXFAILED,
	WIFI_CMD_SET_SCAN,
	WIFI_CMD_SET_AUTH_TYPE,
	WIFI_CMD_SET_WPA_VERSION,
	WIFI_CMD_SET_PAIRWISE_CIPHER,
	WIFI_CMD_SET_GROUP_CIPHER,
	WIFI_CMD_SET_AKM_SUITE,
	WIFI_CMD_SET_CHANNEL,	/*10-0xA */
	WIFI_CMD_SET_BSSID,
	WIFI_CMD_SET_ESSID,
	WIFI_CMD_KEY_ADD,
	WIFI_CMD_KEY_DEL,
	WIFI_CMD_KEY_SET,
	WIFI_CMD_SET_DISCONNECT,
	WIFI_CMD_SET_RTS_THRESHOLD,
	WIFI_CMD_SET_FRAG_THRESHOLD,
	WIFI_CMD_SET_PMKSA,
	WIFI_CMD_DEL_PMKSA,	/*20--0x14 */
	WIFI_CMD_FLUSH_PMKSA,
	WIFI_CMD_SET_DEV_OPEN,
	WIFI_CMD_SET_DEV_CLOSE,
	WIFI_CMD_SET_PSK,
	WIFI_CMD_START_BEACON,
	WIFI_CMD_SET_WPS_IE,
	WIFI_CMD_TX_MGMT,
	WIFI_CMD_REMAIN_CHAN,
	WIFI_CMD_CANCEL_REMAIN_CHAN,
	WIFI_CMD_P2P_IE,	/*30---0x1e */
	WIFI_CMD_CHANGE_BEACON,
	WIFI_CMD_REGISTER_FRAME,
	WIFI_CMD_NPI_MSG,
	WIFI_CMD_NPI_GET,
	WIFI_CMD_SET_FT_IE,
	WIFI_CMD_UPDATE_FT_IE,
	WIFI_CMD_ASSERT,
	WIFI_CMD_SLEEP,
	WIFI_CMD_ADD_SOFTAP_BLACKLIST,
	WIFI_CMD_DEL_SOFTAP_BLACKLIST,
	WIFI_CMD_SCAN_NOR_CHANNELS,
	WIFI_CMD_GET_IP,
	WIFI_CMD_REQ_LTE_CONCUR,
	WIFI_CMD_SET_CQM_RSSI,
	WIFI_CMD_MULTICAST_FILTER,
	WIFI_CMD_DISASSOC,
	WIFI_CMD_SDIO_CHN_FLUSH = 47,
	WIFI_CMD_COMMON_DATA,
	WIFI_CMD_ADD_WHITELIST,
	WIFI_CMD_DEL_WHITELIST,
	WIFI_CMD_ENABLE_WHITELIST,
	WIFI_CMD_DISABLE_WHITELIST,
	WIFI_CMD_SET_QOS_MAP = 54,
	WIFI_CMD_MAX,

	WIFI_EVENT_CONNECT = 128,
	WIFI_EVENT_DISCONNECT,
	WIFI_EVENT_SCANDONE,
	WIFI_EVENT_MGMT_DEAUTH,
	WIFI_EVENT_MGMT_DISASSOC,
	WIFI_EVENT_REMAIN_ON_CHAN_EXPIRED,
	WIFI_EVENT_NEW_STATION,
	WIFI_EVENT_REPORT_FRAME,
	WIFI_EVENT_CONNECT_AP,
	WIFI_EVENT_SDIO_SEQ_NUM,
	WIFI_EVENT_REPORT_SCAN_FRAME,
	WIFI_EVENT_REPORT_MIC_FAIL,
	WIFI_EVENT_REPORT_CQM_RSSI_LOW,
	WIFI_EVENT_REPORT_CQM_RSSI_HIGH,
	WIFI_EVENT_REPORT_CQM_RSSI_LOSS_BEACON,
	WIFI_EVENT_MLME_TX_STATUS,
	WIFI_EVENT_REPORT_VERSION,
	WIFI_EVENT_MAX,
};

/* The reason code is defined by CP2 */
enum wlan_cmd_disconnect_reason {
	AP_LEAVING = 0xc1,
	AP_DEAUTH = 0xc4,
};

struct wlan_cmd_add_key {
	unsigned char mac[6];
	unsigned char keyseq[8];
	unsigned char pairwise;
	unsigned char cypher_type;
	unsigned char key_index;
	unsigned char key_len;
	unsigned char value[0];
} __attribute__ ((packed));

struct wlan_cmd_del_key {
	unsigned char key_index;
	unsigned char pairwise;	/* unicase or group */
	unsigned char mac[6];
} __attribute__ ((packed));

struct wlan_cmd_beacon {
	unsigned short len;
	unsigned char data[0];
} __attribute__ ((packed));

struct wlan_cmd_mac_open {
	unsigned short mode;	/* AP or STATION mode */
	unsigned char mac[6];
} __attribute__ ((packed));

struct wlan_cmd_mac_close {
	unsigned char mode;	/* AP or STATION mode */
} __attribute__ ((packed));

struct wlan_cmd_set_wpa_version {
	unsigned int wpa_version;
} __attribute__ ((packed));

struct wlan_cmd_scan_ssid {
	unsigned char len;
	unsigned char ssid[0];
} __attribute__ ((packed));

struct wlan_cmd_set_key {
	unsigned int key_index;
} __attribute__ ((packed));

struct wlan_cmd_disconnect {
	unsigned short reason_code;
} __attribute__ ((packed));

struct wlan_cmd_set_essid {
	unsigned short len;
	unsigned char essid[0];
} __attribute__ ((packed));

struct wlan_cmd_set_bssid {
	unsigned char addr[6];
} __attribute__ ((packed));

struct wlan_cmd_set_channel {
	unsigned int channel;
} __attribute__ ((packed));

struct wlan_cmd_set_key_management {
	unsigned int key_mgmt;

} __attribute__ ((packed));

struct wlan_cmd_set_cipher {
	unsigned int cipher;
} __attribute__ ((packed));

struct wlan_cmd_set_auth_type {
	unsigned int type;

} __attribute__ ((packed));

struct wlan_cmd_set_psk {
	unsigned short len;
	unsigned char key[0];
} __attribute__ ((packed));

struct wlan_cmd_scan {
	/*
	   unsigned char channel_num;
	   unsigned char channel[15];
	 */
	unsigned int len;
	unsigned char ssid[0];
} __attribute__ ((packed));

/*
typedef struct {
	unsigned char ops;
	unsigned short channel;
	signed short signal;
	unsigned short frame_len;
} wlan_event_scan_rsp_t;
*/

/* wlan_sipc wps ie struct */
struct wlan_cmd_set_ie {
	unsigned char  type;
	unsigned short len;
	unsigned char data[0];
}  __attribute__ ((packed));

struct wlan_event_mic_failure {
	unsigned char key_id;
	unsigned char is_mcast;
} __attribute__ ((packed));

struct wlan_cmd_disassoc {
	unsigned char mac[6];
	unsigned short reason_code;
} __attribute__ ((packed));


#define SPRDWL_SCAN_FRAME	0
#define SPRDWL_SCAN_DONE	1
struct sprdwl_scan_result_event {
	unsigned char type;
	unsigned short channel;
	signed short signal;
	/* frame len  min:37*/
	unsigned short  len;
	/* here is scan frame */
	u8 mgmt[0];
};
enum common_data_type {
	COMMON_TYPE_LTE_3WRE = 1,
	COMMON_TYPE_GO_NOA,
	COMMON_TYPE_GO_OPPS,
	COMMON_TYPE_SET_MAX_STA,
	COMMON_TYPE_SCAN_FLAGS,
	COMMON_TYPE_VOWIFI_FLAG,
	COMMON_TYPE_MONITOR_START,
	COMMON_TYPE_MONITOR_STOP,
};

struct wlan_send_common_data {
	unsigned short type;
	unsigned short len;
	unsigned char data[0];
} __attribute__ ((packed));


typedef int (*wifi_recv_mon_cb_t)(uint8_t *pdata, uint16_t len, int arg);

int sprdwl_rx_init(void);

int sprdwl_cmd_scan(struct sprdwl_priv *priv, const unsigned char *ssid,
		  const unsigned char *channels, int len);
int sprdwl_cmd_disassoc(struct sprdwl_priv *priv, const unsigned char *mac_addr,
		unsigned short reason_code);
int sprdwl_cmd_disconnect(struct sprdwl_priv *priv, unsigned short reason_code);
int sprdwl_cmd_set_wpa_version(struct sprdwl_priv *priv,  unsigned int wpa_version);
int sprdwl_cmd_set_auth_type(struct sprdwl_priv *priv, unsigned int type);
int sprdwl_cmd_set_pairwise_cipher(struct sprdwl_priv *priv, unsigned int cipher);
int sprdwl_cmd_set_group_cipher(struct sprdwl_priv *priv, unsigned int cipher);
int sprdwl_cmd_set_key_management(struct sprdwl_priv *priv, unsigned char key_mgmt);
int sprdwl_cmd_set_psk(struct sprdwl_priv *priv,
		const unsigned char *key,
		unsigned int key_len);
int sprdwl_cmd_set_channel(unsigned char vif_id, unsigned int channel);
int sprdwl_cmd_set_bssid(struct sprdwl_priv *priv, const unsigned char *addr);
int sprdwl_cmd_set_essid(struct sprdwl_priv *priv,
		const unsigned char *essid,
		int essid_len);
int sprdwl_cmd_add_key(struct sprdwl_priv *priv,
		const unsigned char *key_data,
		unsigned char key_len,
		unsigned char pairwise,
		unsigned char key_index,
		const unsigned char *key_seq,
		unsigned char cypher_type,
		const unsigned char *pmac);
int sprdwl_cmd_del_key(struct sprdwl_priv *priv,
		unsigned short key_index,
		const unsigned char *mac_addr);
int sprdwl_cmd_set_key(struct sprdwl_priv *priv, unsigned char key_index);
int sprdwl_cmd_set_ie(struct sprdwl_priv *priv, unsigned char type,
	 	      const unsigned char *ie, unsigned short len);
int sprdwl_cmd_start_ap(unsigned char vif_id, unsigned char *beacon,
		unsigned short len);
int sprdwl_cmd_npi(unsigned char *in_buf, unsigned short in_len,
		unsigned char *out_buf, unsigned short *out_len);
int sprdwl_cmd_send_common_data(unsigned char vif_id, unsigned char *data,
		int len);
int sprdwl_cmd_set_monitor_mode(unsigned char vif_id, unsigned char flag);

unsigned short sprdwl_rx_rsp_process(struct sprdwl_priv *priv,
				     unsigned char *data, unsigned short len);
unsigned short sprdwl_rx_event_process(struct sprdwl_priv *priv,
				       unsigned char event, unsigned char *data,
				       unsigned short len);
#endif /*__RTOS_DRV_SC2331_CMDEVT_H__ */

