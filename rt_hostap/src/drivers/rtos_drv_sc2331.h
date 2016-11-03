#ifndef __RTOS_DRV_SC2331_H__
#define __RTOS_DRV_SC2331_H__

#include "cs_types.h"
#include "cos.h"
#include "event.h"
#include "ts.h"
#include "os_adp.h"
#include "stdio.h"
#include "common/ieee802_11_defs.h"
#include "rtos_drv_sc2331_cp_defs.h"
#include "rtos_direct_drv.h"

#define MAX_BSS_ENTRIES		(40)

/* inlcude ssid ie rate ie  wpa or rsn ie */
#define MAX_IE_LEN     (150) 
#define ALIGN_4BYTE(a)	((((a)+3)&(~3)))
/* used to transfer data to/from kernel */
#define DATA_BUF_LEN	(1024 * 13)
/* used to read data from sdio */
#define RX_BUF_LEN		(1024 * 13)
/* used to process cp event and cmd respose */
#define RECV_BUF_SIZE	(512)

#define WLAN_MAX_IE_LEN			(100)

#define WLAN_MAX_KEY_LEN     (32)

#define pr_fmt(fmt) "[sc2331] " fmt

#define pr_info(fmt, ...)			\
	printf(pr_fmt(fmt), ##__VA_ARGS__)
#define pr_error(fmt, ...)			\
	printf(pr_fmt(fmt), ##__VA_ARGS__)



struct ether_addr
{
      uint8_t ether_addr_octet[6];            /* 48-bit Ethernet address */
};
/* need the same with wpa_supplicant scan_res */
struct sprdwl_wpas_scanres {
	unsigned int flags;
	u8 bssid[ETH_ALEN];
	int freq;
	u16 beacon_int;
	u16 caps;
	int qual;
	int noise;
	int level;
	u64 tsf;
	/* not used only for alig */
	unsigned int age;
	size_t ie_len;
	size_t beacon_ie_len;
};

struct sprdwl_bss_info {
		struct sprdwl_wpas_scanres res;
		int ie_len;
		u8 ie[MAX_IE_LEN]; /* inlcude ssid ie rate ie  wpa or rsn ie */
};
struct sprdwl_conn_param {
	le32 wpa_version;
	u8 bssid[ETH_ALEN];
	u8 channel;
	u8 auth_type;
	u8 key_mgmt;
	u8 mfp_enable;
	u8 psk_len;
	u8 psk[WLAN_MAX_KEY_LEN];
	u8 ssid_len;
	u8 ssid[WLAN_MAX_SSID_LEN];
	/* encryption stuff */
	u8 pairwise_cipher;
	u8 group_cipher;
	u32 cipher;
	u8 default_key;
	u8 key_index[2];
	u8 key[2][4][WLAN_MAX_KEY_LEN];
	u8 key_len[2][4];
	/* u8 key_txrsc[2][WLAN_MAX_KEY_LEN]; */ /* WAPI */
	u8 ie[WLAN_MAX_IE_LEN];
	u8 ie_len;

} __packed;


#define SCAN_IN_IDEL		0
#define SCAN_IN_PROGRESS	1
#define SCAN_IN_DONE		2
struct sprdwl_scan_state {
	u8 filter_ssid[WLAN_MAX_SSID_LEN];
	u8 filter_channel[14];
	u8 state;
};

struct sprdwl_priv {
	struct sprdwl_if_ops *if_ops;
	/* Drivers interface flags.  See IFF_* definitions in include/net/if.h */
  	uint8_t d_flags;
	unsigned char vif_id;
	unsigned char mode;
	struct ether_addr d_mac;      /* Device MAC address */
#ifdef CONFIG_NETDEV
	struct net_device *dev;
#endif
	struct wiphy *wiphy;
	unsigned int tx_cnt;
	struct sprdwl_conn_param conn;
	struct sprdwl_scan_state scan_state;

	struct sprdwl_bss_info bss[MAX_BSS_ENTRIES];
	u32 bss_count;
	struct wpa_driver_direct_data * drv;
};

struct sprdwl_priv *sprdwl_get_priv(void);
struct sprdwl_if_ops *sprdwl_get_if_ops(void);
#endif /*__RTOS_DRV_SC2331_H__ */

