#ifndef __RTOS_DRV_SC2331_CP_DEFS_H__
#define __RTOS_DRV_SC2331_CP_DEFS_H__
/* cipher type */
#define SPRDWL_CIPHER_NONE		0
#define SPRDWL_CIPHER_WEP40		1
#define SPRDWL_CIPHER_WEP104		2
#define SPRDWL_CIPHER_TKIP		3
#define SPRDWL_CIPHER_CCMP		4
#define SPRDWL_CIPHER_AP_TKIP		5
#define SPRDWL_CIPHER_AP_CCMP		6
#define SPRDWL_CIPHER_WAPI		7
#define SPRDWL_CIPHER_AES_CMAC		8
;

#define AUTH_KEY_MGMT_NONE	0x00
#define AUTH_KEY_MGMT_PSK	0x01
#define AUTH_KEY_MGMT_802_1X	0x02

#define AUTH_CIPHER_NONE	0x00
#define AUTH_CIPHER_WEP40	0x01
#define AUTH_CIPHER_WEP104	0x02
#define AUTH_CIPHER_TKIP	0x03
#define AUTH_CIPHER_CCMP	0x04

struct msg_hdr {
	unsigned char type:7;/* CMD/RSP/USER DATA */
	unsigned char mode:1;/* message dest mode: 1 STA, 2 softAP, 3 P2P */
	unsigned char subtype;/* SEARCH/ ATTACH/DETACH */
	unsigned short len;/* Length not include common header */
};

#endif /* __DRIVERS_WIRELESS_SC2331_UTILS_H */
