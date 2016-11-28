#ifndef RTOS_DIRECT_DRV_H
#define RTOS_DIRECT_DRV_H
#include "eloop.h" 
#define IFLA_WIRELESS 1
#define IFLA_RX_EAPOL 2
enum evt_type_t{
	EVT_TYPE_WIRELESS = 1,
	EVT_TYPE_EAPOL
};

enum evt_subtyp_t{
	DRV_SCAN_DONE = 1
};

struct drv_event {
	u8    evt_type;
	u8    evt_subtype;
	u16  dlen;
	u8*  data;
};

struct msg_dscr {
	struct msg_buf_hd hd;
	struct drv_event evts;
};

struct eth_data_packet {
       u8 dest[6];
       u8 src[6];
       u16 proto;
       u8 data[0];
};
#define PROTO_8021X	0x888E
#define WLAN_MAX_SSID_LEN   (32)

#define IFF_DOWN           (1 << 0) /* Interface is down */
#define IFF_UP             (1 << 1) /* Interface is up */
#define IFF_RUNNING        (1 << 2) /* Carrier is available */
#define IFF_IPv6           (1 << 3) /* Configured for IPv6 packet (vs ARP or IPv4) */
#define IFF_NOARP          (1 << 7) /* ARP is not required for this packet */

#define IFF_SET_DOWN(f)    do { (f) |= IFF_DOWN; } while (0)
#define IFF_SET_UP(f)      do { (f) |= IFF_UP; } while (0)
#define IFF_SET_RUNNING(f) do { (f) |= IFF_RUNNING; } while (0)
#define IFF_SET_NOARP(f)   do { (f) |= IFF_NOARP; } while (0)

#define IFF_CLR_DOWN(f)    do { (f) &= ~IFF_DOWN; } while (0)
#define IFF_CLR_UP(f)      do { (f) &= ~IFF_UP; } while (0)
#define IFF_CLR_RUNNING(f) do { (f) &= ~IFF_RUNNING; } while (0)
#define IFF_CLR_NOARP(f)   do { (f) &= ~IFF_NOARP; } while (0)

#define IFF_IS_DOWN(f)     (((f) & IFF_DOWN) != 0)
#define IFF_IS_UP(f)       (((f) & IFF_UP) != 0)
#define IFF_IS_RUNNING(f)  (((f) & IFF_RUNNING) != 0)
#define IFF_IS_NOARP(f)    (((f) & IFF_NOARP) != 0)


#endif
