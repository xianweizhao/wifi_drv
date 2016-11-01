#ifndef WIFI_MANAGER_H
#define WIFI_MANAGER_H
#ifndef __SX__ 
#include "wcnd_api.h"
#define WCND_IS_OK
#endif
enum wpas_wifi_mode_t{
	WIFI_MODE_STA,
	WIFI_MODE_AP,
	WIFI_MODE_OTHER,
	WIFI_MODE_NONE
};

extern enum wpas_wifi_mode_t  wifi_work_mode;

int wpas_change_wifi_mode(enum wpas_wifi_mode_t new_mode, int needcheck);
void wifi_manager_init(void);
#endif
