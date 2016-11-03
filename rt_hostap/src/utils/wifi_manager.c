#include "wifi_manager.h"
#include "os_adp.h"
#include "wifi_server_intf.h"

enum wpas_wifi_mode_t  wifi_work_mode = WIFI_MODE_NONE;
#ifdef WCND_IS_OK
int wifi_manager_inited = 0;
#endif

#ifdef WCND_IS_OK
static void wpa_supplicant_init_cb(uint32 id, uint32 argc, void *argv)
{
	if (id == WCND_RESET_OK || id == WCND_RESPONSE_OK) {
		wifi_manager_inited = 1;
	} else if (id == WCND_RESET_START) {
		wifi_manager_inited = 0;
	}
}
#endif
void wifi_manager_init(void)
{
	wifi_work_mode = WIFI_MODE_NONE;
#ifdef WCND_IS_OK
	wifi_manager_inited = 0;
	SCI_ClientRegisterWCND(wpa_supplicant_init_cb);
#endif
}

int wpas_change_wifi_mode(enum wpas_wifi_mode_t mode, int needcheck)
{
	int count = 50;
#ifdef WCND_IS_OK
	int status = 0;
#endif
	if (wifi_work_mode == WIFI_MODE_NONE) {
		wifi_work_mode = mode;
	} else {
		if (!needcheck && mode == WIFI_MODE_NONE) {
			wifi_work_mode = mode;
			return 0;
		}

		if (wifi_work_mode == WIFI_MODE_STA)
			wpas_eloop_exit_thread();

		if (wifi_work_mode == WIFI_MODE_AP)
			hostapd_eloop_exit_thread();

		while(wifi_work_mode != WIFI_MODE_NONE && --count){
			SCI_Sleep(200);
		}
		if (count == 0)
		    return -1;
		wifi_work_mode = mode;
#ifdef WCND_IS_OK
		if (mode == WIFI_MODE_STA || mode == WIFI_MODE_AP) {
			if ( wifi_manager_inited  == 1)
				return 0;
			status = SCI_WCNWIFIOpen();
			if (status < 0)
				return -1;
			count = 200;
			while(wifi_manager_inited == 0 && --count) {
				SCI_Sleep(200);
			}
			if(count == 0)
				return -1;
		}
#endif
	}
	return 0;
}
