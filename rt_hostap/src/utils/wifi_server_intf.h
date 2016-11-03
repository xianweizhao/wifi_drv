#ifndef WIFI_SERVER_INTF
#define WIFI_SERVER_INTF

#include "yunos_bsp_wifi.h"
#include "os_adp.h"
#include "common.h"
#include "wifi_manager.h"
#include "eloop.h"

#define SCAN_TIMEOUT_MS 15*1000
#define CONNECT_TIMEOUT_MS 6*1000

#define CMD_SCAN		    1
#define CMD_CONNECT		    2
#define CMD_CONNECT_EXT		    3
#define CMD_DISCONNECT		    4

#define CMD_ELOOP_STOP		    21

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
int wpas_wifi_scan(wifi_scan_ap_t * info, uint32_t size);
int wpas_wifi_connect_ext(const char *ssid, const char *password,
			       const wifi_mac_addr_t bssid, uint8_t channel,
			       wifi_conn_sectype_t security);
int wpas_wifi_connect(const char *ssid, const char *password);
int wpas_wifi_disconnect(int sync);
int wpas_wifi_get_rssi(void);
int wpas_wifi_get_rate(void);
int wpas_get_current_ap_channel(void);
int wpas_get_current_ap_bssid(wifi_mac_addr_t mac_addr);
int wifi_get_mac_address(wifi_mac_addr_t mac_addr);
wifi_conn_sectype_t wpas_get_current_ap_security(void);

int hostapd_wifi_softap_start(const wifi_ap_param_t * param);
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
