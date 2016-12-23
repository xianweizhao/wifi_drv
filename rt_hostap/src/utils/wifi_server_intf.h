#ifndef WIFI_SERVER_INTF
#define WIFI_SERVER_INTF

#include "eloop.h"
#include "common.h"
#include "wifi_manager.h"

#define SCAN_TIMEOUT_MS 15*1000
#define CONNECT_TIMEOUT_MS 6*1000

#define CMD_SCAN		    1
#define CMD_CONNECT		    2
#define CMD_CONNECT_EXT		    3
#define CMD_DISCONNECT		    4

#define CMD_ELOOP_STOP		    21
#define MAX_PWD_LEN                      16
#ifndef MAX_SSID_LEN
#define MAX_SSID_LEN                       32
#endif
enum wifi_conn_sectype
{
	WPAS_SEC_OPEN = 0,
	WPAS_SEC_WPA_AES_PSK = 1,
	WPAS_SEC_WPA2_AES_PSK = 2,
	WPAS_SEC_WEP_PSK = 3,
	WPAS_SEC_WEP_SHARED = 4,
	WPAS_SEC_WPA_TKIP_PSK = 5,
	WPAS_SEC_WPA2_TKIP_PSK = 6,
	WPAS_SEC_WPA2_MIXED_PSK = 7,
	WPAS_SEC_UNKNOWN  =0xffffffff
};

struct wifi_scan_ap
{
	char ssid[MAX_SSID_LEN];
	char *bssid;
	int channel;
	enum wifi_conn_sectype security;
	int rssi;
};

struct wifi_ap_param
{
	char ssid[MAX_SSID_LEN];
	char password[MAX_PWD_LEN];
	enum wifi_conn_sectype security;
	char *bssid;
	int channel;	
};
enum cmd_state {
	WPAS_CMD_NONE,
	WPAS_CMD_DONE,
	WPAS_CMD_CONNECT,
	WPAS_CMD_DISCONNECT,
	WPAS_CMD_SCAN
};

struct connect_proto {
	int proto;
	int pairse_cipher;
	int group_cipher;
	int key_mgmt;
};

struct  msgq_cmd_buf {
	struct msg_buf_hd hd;
	u8 cmd_type;
	u16 channel;
	u8 *ssid;
	const char *password;
	u8 bssid[ETH_ALEN];
	struct connect_proto proto;
};

struct wpa_intf_data {
	SCI_MSG_QUEUE_PTR  msg_q;
	struct wpa_supplicant *wpa_s;
	SCI_SEMAPHORE_PTR scan_done;
	SCI_SEMAPHORE_PTR connect_done;
	SCI_SEMAPHORE_PTR disconnect_done;
	int inited;
	enum  cmd_state cmd_state;
	int scan_num;
	void *scan_user;
};

struct host_intf_data {
	SCI_MSG_QUEUE_PTR  msg_q;
	int inited;
	struct hostapd_iface *host_if;
};
extern int wpa_supplicant_main(void);
extern int hostapd_main(void);
/* for hal level */
void wpas_wifi_simple_scan(void);
int wpas_wifi_scan(struct wifi_scan_ap * info, uint32_t size);
int wpas_wifi_connect_ext(const char *ssid, const char *password,
			       const u8* bssid, uint8_t channel,
			       enum wifi_conn_sectype security);
int wpas_wifi_connect(const char *ssid, const char *password);
int wpas_wifi_disconnect(int sync);
int wpas_wifi_get_rssi(void);
int wpas_wifi_get_rate(void);
int wpas_get_current_ap_channel(void);
int wpas_get_current_ap_bssid(u8 *mac_addr);
int wifi_get_mac_address(u8* mac_addr);
enum wifi_conn_sectype  wpas_get_current_ap_security(void);

int hostapd_wifi_softap_start(const struct wifi_ap_param * param);
int hostapd_wifi_softap_stop(void);
int wpas_supplicant_start(void);
int wpas_supplicant_stop(void);

int wpas_get_current_mode(void);
/* wifi module init */
int wpas_wifi_init(void);

/* for supplicant */
int wpas_priv_data_init(struct wpa_supplicant *wpa_s);
int wpas_priv_data_deinit(void);
int wpas_notify_connect_change(int new_state, int old_state);

/* for hostapd */
int hostapd_priv_data_deinit(void);
int hostapd_priv_data_init(struct hostapd_iface *host_if);

/* for wifi_manager */
int wpas_eloop_exit_thread(void);
int hostapd_eloop_exit_thread(void);
#endif
