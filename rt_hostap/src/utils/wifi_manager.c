#include "wifi_manager.h"
#include "wifi_server_intf.h"

enum wpas_wifi_mode_t  wifi_work_mode = WIFI_MODE_NONE;

void wifi_manager_init(void)
{
	wifi_work_mode = WIFI_MODE_NONE;
}

int wpas_change_wifi_mode(enum wpas_wifi_mode_t mode, int needcheck)
{
	int count = 50;
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
	}
	return 0;
}
