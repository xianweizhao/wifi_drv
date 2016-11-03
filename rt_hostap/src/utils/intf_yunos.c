/****************************************************************************
* HAL interface for YunOS
*
* Copyright (C) 2015 The YunOS Open Source Project
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
****************************************************************************/

/****************************************************************************
* Include Definitions
****************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wifi_server_intf.h"



/****************************************************************************
* Pre-processor Definitions
****************************************************************************/
#ifdef IL_BIGENDIAN
#define MK_CNTRY( a, b, rev )  (((unsigned char)(b)) + (((unsigned char)(a))<<8) + (((unsigned char)(rev))<<24) )
#else				/* ifdef IL_BIGENDIAN */
#define MK_CNTRY( a, b, rev )  (((unsigned char)(a)) + (((unsigned char)(b))<<8) + (((unsigned char)(rev))<<24) )
#endif				/* ifdef IL_BIGENDIAN */

#define STA_HB_TIMEOUT 30000	//ms

/****************************************************************************
* Private Type Definitions
****************************************************************************/
typedef enum {
	WICED_COUNTRY_CHINA = MK_CNTRY('C', 'N', 0),	/* CN China */
} wiced_country_code_t;

/****************************************************************************
 * Private Data Definitions
 ****************************************************************************/

static wifi_recv_eth_cb_t g_wifi_recv_eth_cb = NULL;
static wifi_recv_mon_cb_t g_wifi_recv_mon_cb = NULL;

static const uint8_t g_monitor_filter[] = {
	//type, fc, duration(1), duration(2), mac_dst(6), mac_src(6), mac_bssid(6)
#if 1
	10,			//size = 10
	//filter: broadcast frame & data/Qos data, fromDs
	0x7C, 0x01, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,	//mask
	0x08, 0x00, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,	//value
#endif
	22,			//size = 22
	//filter: broadcast frame & data/Qos data, toDs
	0x7C, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,	//mask
	0x08, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,	//value
#if 1
	1,			//size = 1
	//filter: MGMT frame: probe req
	0xFC,			//mask
	0x40,			//value

	1,			//size = 1
	//filter: MGMT frame: probe response
	0xFC,			//mask
	0x50,			//value

	1,			//size = 1
	//filter: MGMT frame: beacon
	0xFC,			//mask
	0x80,			//value

	1,			//size = 1
	//filter: MGMT frame: action
	0xFC,			//mask
	0xd0,			//value
#endif
	0			//end
};


/****************************************************************************
 * Public Function Define
 ****************************************************************************/

//4.1.
/****************************************************************************
 * Name: yunos_bsp_wifi_init
 *
 * Description:
 *   wifi module init
 *
 * Parameters:
 *   void
 *
 * Return:
 *   0 on success; <0 on failure
 *
 ****************************************************************************/
int yunos_bsp_wifi_init(void)
{
	wpas_wifi_init();

	/* fisrt we default star sta mode */
	return  wpas_supplicant_start();
}

//4.2.
/****************************************************************************
 * Name: yunos_bsp_wifi_get_version
 *
 * Description:
 *   Get wifi module soft version
 *
 * Parameters:
 *   void
 *
 * Return:
 *   version string
 *
 ****************************************************************************/
char *yunos_bsp_wifi_get_version(void)
{
	return NULL;
}

/****************************************************************************
 * Name: yunos_bsp_wifi_get_mac_address
 *
 * Description:
 *   Get wifi module mac address
 *
 * Parameters:
 *   addr  The location to return the MAC address
 *
 * Return:
 *   0 on success; < 0 on failure
 *
 ****************************************************************************/
int yunos_bsp_wifi_get_mac_address(wifi_mac_addr_t mac_addr)
{
	return  wifi_get_mac_address(mac_addr);
}

/****************************************************************************
 * Name: yunos_bsp_wifi_get_mode
 *
 * Description:
 *   get current wifi run mode
 *
 * Parameters:
 *   void
 *
 * Return:
 *   wifi run mode
 *
 ****************************************************************************/
wifi_mode_t yunos_bsp_wifi_get_mode(void)
{
/* here mode define is the same with ali so do not need transform */
	return wpas_get_current_mode();
}

//4.3.
/****************************************************************************
 * Name: yunos_bsp_output_data
 *
 * Description:
 *   send data to wifi module
 *
 * Parameters:
 *   arg     user define data
 *   pdata   data context, 802.3 ignore Preamble and SFD, |dest mac|src mac|....
 *   length  data length
 *
 * Return:
 *   0 on success; <0 on failure
 *
 ****************************************************************************/
int yunos_bsp_output_data(void *arg, uint8_t * pdata, uint16_t length)
{
	/*FIXME*/
	/*return wifidrv_output(arg, (void *)pdata, length);*/
    extern int sprdwl_wifi_tx_data(unsigned char *data, unsigned short len);
    return sprdwl_wifi_tx_data(pdata, length);

}

/****************************************************************************
 * Name: yunos_bsp_wifi_add_multicast_address
 *
 * Description:
 *   add socket multicast group need call this funtion
 *
 * Parameters:
 *   multicast_mac   multicast mac address
 *
 * Return:
 *   0 on success; -1 on failure
 *
 ****************************************************************************/
int yunos_bsp_wifi_add_multicast_address(const wifi_mac_addr_t multicast_mac)
{
	/*FIXME*/
	/*return wwd_wifi_register_multicast_address(multicast_mac);*/
	return 0;
}

/****************************************************************************
 * Name: yunos_bsp_wifi_remove_multicast_address
 *
 * Description:
 *   remove socket multicast group need call this funtion
 *
 * Parameters:
 *   multicast_mac   multicast mac address
 *
 * Return:
 *   0 on success; -1 on failure
 *
 ****************************************************************************/
int yunos_bsp_wifi_remove_multicast_address(const wifi_mac_addr_t multicast_mac)
{
	/*FIXME*/
	/*return wwd_wifi_unregister_multicast_address(multicast_mac);*/
	return 0;
}

/****************************************************************************
 * Name: yunos_bsp_wifi_regsiter_input_cb
 *
 * Description:
 *   register callback function, for recv data and process by ip stack
 *
 * Parameters:
 *   recv_cb     recv callback funtion
 *
 * Return:
 *   0 on success; <0 on failure
 *
 ****************************************************************************/
int yunos_bsp_wifi_regsiter_input_cb(wifi_recv_eth_cb_t recv_cb)
{
	g_wifi_recv_eth_cb = recv_cb;
	return 0;
}

//4.4.
/****************************************************************************
 * Name: yunos_bsp_wifi_connect
 *
 * Description:
 *   connect to ap by ssid and pssword
 *
 * Parameters:
 *   ssid   ap ssid
 *   password ap password
 *  
 * Return:
 *   0 on success; <0 on failure
 *
 ****************************************************************************/
int yunos_bsp_wifi_connect(const char *ssid, const char *password)
{
	return wpas_wifi_connect(ssid, password);
}

/****************************************************************************
 * Name: yunos_bsp_wifi_connect_ext
 *
 * Description:
 *   connect to ap by more detial info
 *
 * Parameters:
 *   ssid   ap ssid
 *   password ap password
 *   bssid  ap macaddr
 *   channel  ap channel 1~13, 0 ignore
 *   secrity  
 *  
 * Return:
 *   0 on success; <0 on failure
 *
 ****************************************************************************/
int yunos_bsp_wifi_connect_ext(const char *ssid, const char *password,
			       const wifi_mac_addr_t bssid, uint8_t channel,
			       wifi_conn_sectype_t security)
{
	return  wpas_wifi_connect_ext(ssid, password, bssid, channel, security);
}

/****************************************************************************
 * Name: yunos_bsp_wifi_disconnect
 *
 * Description:
 *   disconnect from ap
 *
 * Parameters:
 *   void
 *  
 * Return:
 *   0 on success; < 0 on failure
 *
 ****************************************************************************/
int yunos_bsp_wifi_disconnect(void)
{
	return  wpas_wifi_disconnect(1);
}

/****************************************************************************
 * Name: yunos_bsp_wifi_get_ssid
 *
 * Description:
 *   get current connect ap ssid
 *
 * Parameters:
 *   void
 *  
 * Return:
 *   return ssid string
 *
 ****************************************************************************/
char *yunos_bsp_wifi_get_ssid(void)
{
	static char ssid[MAX_SSID_LEN];

	/*FIXME*/

	return ssid;
}

/****************************************************************************
 * Name: yunos_bsp_wifi_get_bssid
 *
 * Description:
 *   get current ap mac address
 *
 * Parameters:
 *   void
 *  
 * Return:
 *   0 on success; < 0 on failure
 *
 ****************************************************************************/
int yunos_bsp_wifi_get_bssid(wifi_mac_addr_t mac_addr)
{
	return wpas_get_current_ap_bssid(mac_addr);
}

/****************************************************************************
 * Name: yunos_bsp_wifi_get_channel
 *
 * Description:
 *   get current ap signal channel
 *
 * Parameters:
 *   void
 *  
 * Return:
 *   channel  1~13 else error
 *
 ****************************************************************************/
int yunos_bsp_wifi_get_channel(void)
{
	return wpas_get_current_ap_channel();
}

/****************************************************************************
 * Name: yunos_bsp_wifi_get_security
 *
 * Description:
 *   get current ap security type
 *
 * Parameters:
 *   void
 *  
 * Return:
 *   security type
 *
 ****************************************************************************/
wifi_conn_sectype_t yunos_bsp_wifi_get_security(void)
{
	return wpas_get_current_ap_security();
}

/****************************************************************************
 * Name: yunos_bsp_wifi_get_rssi
 *
 * Description:
 *   get current connect signal rssi
 *
 * Parameters:
 *   void
 *  
 * Return:
 *   return rssi < 0, ==0 error
 *
 ****************************************************************************/
int yunos_bsp_wifi_get_rssi(void)
{
	return wpas_wifi_get_rssi();
}

/****************************************************************************
 * Name: yunos_bsp_wifi_get_rate
 *
 * Description:
 *   get current connect speed rate
 *
 * Parameters:
 *   void
 *  
 * Return:
 *   speed rate Mbps, <=0 error
 *
 ****************************************************************************/
int yunos_bsp_wifi_get_rate(void)
{
	return wpas_wifi_get_rate();
}

//4.5.
/****************************************************************************
 * Name: yunos_bsp_wifi_softap_start
 *
 * Description:
 *   start soft ap mode
 *
 * Parameters:
 *   param    ap mode param
 *  
 * Return:
 *   0 on success; <0 on failure
 *
 ****************************************************************************/
int yunos_bsp_wifi_softap_start(const wifi_ap_param_t * param)
{
	return hostapd_wifi_softap_start(param);
}

/****************************************************************************
 * Name: yunos_bsp_wifi_softap_stop
 *
 * Description:
 *   stop soft ap mode
 *
 * Parameters:
 *   void
 *  
 * Return:
 *   0 on success; <0 on failure
 *
 ****************************************************************************/
int yunos_bsp_wifi_softap_stop(void)
{
	return hostapd_wifi_softap_stop();
}

//4.6.
/****************************************************************************
 * Name: yunos_bsp_wifi_monitor_start
 *
 * Description:
 *   start monitor mode and register monitor data callback
 *
 * Parameters:
 *   cb
 *  
 * Return:
 *   0 on success; <0 on failure
 *
 ****************************************************************************/
int yunos_bsp_wifi_monitor_start(wifi_recv_mon_cb_t cb)
{
	int ret = 0;

	int sprdwl_cmd_set_monitor_mode(unsigned char vif_id,
					unsigned char flag);
	int sprdwl_monitor_register_cb(wifi_recv_mon_cb_t cb);

	sprdwl_monitor_register_cb(cb);
	ret = sprdwl_cmd_set_monitor_mode(0, 1);
	return 0;
}

/****************************************************************************
 * Name: yunos_bsp_wifi_monitor_stop
 *
 * Description:
 *   stop monitor mode
 *
 * Parameters:
 *   void
 *  
 * Return:
 *   0 on success; <0 on failure
 *
 ****************************************************************************/
int yunos_bsp_wifi_monitor_stop(void)
{
	int ret = 0;

	int sprdwl_cmd_set_monitor_mode(unsigned char vif_id,
			    unsigned char flag);
	ret = sprdwl_cmd_set_monitor_mode(0, 0);

	return ret;
}

/****************************************************************************
 * Name: yunos_bsp_wifi_set_channel
 *
 * Description:
 *   set monitor recv channel
 *
 * Parameters:
 *   channel  wifi channel 1~13
 *  
 * Return:
 *   0 on success; -1 on failure
 *
 ****************************************************************************/
int yunos_bsp_wifi_set_channel(int32_t channel)
{
	int ret = 0;
	int sprdwl_cmd_set_channel(unsigned char vif_id,
			   unsigned int channel);

	ret = sprdwl_cmd_set_channel(0, channel);
	return ret;
}

/****************************************************************************
 * Name: yunos_bsp_wifi_set_monitor_filter
 *
 * Description:
 *   set monitor filter
 *
 * Parameters:
 *   void
 *  
 * Return:
 *   0 on success; <0 on failure
 *
 ****************************************************************************/
int yunos_bsp_wifi_set_monitor_filter(void)
{
	/*FIXME*/
	return 0;
}

/****************************************************************************
 * Name: yunos_bsp_wifi_clear_monitor_filter
 *
 * Description:
 *   clear monitor filter
 *
 * Parameters:
 *   void
 *  
 * Return:
 *   0 on success; <0 on failure
 *
 ****************************************************************************/
int yunos_bsp_wifi_clear_monitor_filter(void)
{
	/*FIXME*/
	return 0;
}

//4.7.
/****************************************************************************
 * Name: yunos_bsp_wifi_before_sleep
 *
 * Description:
 *   be called when main cpu enter standby mode
 *
 * Parameters:
 *   ipaddr ip address
 *  
 * Return:
 *   0 on success; <0 on failure
 *
 ****************************************************************************/
int yunos_bsp_wifi_before_sleep(uint8_t ipaddr[4])
{
	/*FIXME*/
	return 0;
}

/****************************************************************************
 * Name: yunos_bsp_wifi_after_wakeup
 *
 * Description:
 *   after main cpu wakeup, call this function, let wifi module in right mode
 *
 * Parameters:
 *   void
 *  
 * Return:
 *   0 on success; <0 on failure
 *
 ****************************************************************************/
int yunos_bsp_wifi_after_wakeup(void)
{
	/*FIXME*/
	return 0;
}

//4.8.
/****************************************************************************
 * Name: yunos_bsp_wifi_scan
 *
 * Description:
 *   scan ap info
 *
 * Parameters:
 *   void
 *  
 * Return:
 *   0 on success; <0 on failure
 *
 ****************************************************************************/
int yunos_bsp_wifi_scan(wifi_scan_ap_t * info, uint32_t size)
{
	return  wpas_wifi_scan(info, size);
}


/****************************************************************************
 * Name: wifi_is_es_mode
 *
 * Description:
 *   check is in easy setup mode
 *
 * Parameters:
 *   void
 *
 * Return:
 *   true  is in easy setup mode
 *
 ****************************************************************************/
bool wifi_is_es_mode(void)
{
    return 0;
}
