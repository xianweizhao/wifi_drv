/*
 * WPA Supplicant / Example program entrypoint
 * Copyright (c) 2003-2005, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include "includes.h"
#include "common.h"
#include "wifi_manager.h"
#include "wpa_supplicant_i.h"
#include "wifi_server_intf.h"
#define WPA_DRIVER_NAME "direct"
#define WPA_INTF_NAME   "wlan0"

#define WPA_TASK_PRI 230

static void wpa_supplicant_thread_entry(uint32 argc, void *argv)
{
	struct wpa_supplicant *wpa_s = NULL;
	int status = 0;
	printf("%s: enter\n",__func__);
	wpas_change_wifi_mode(WIFI_MODE_STA, 1);

	wpa_s = wpa_supplicant_init();
	if (wpa_s == NULL)
		goto out1;

	wpas_priv_data_init(wpa_s);
	status = wpa_supplicant_run(wpa_s);
	wpas_priv_data_deinit();
out1:
	wpa_supplicant_deinit(wpa_s);
	wpa_s = NULL;
out:
	wpas_change_wifi_mode(WIFI_MODE_NONE, 0);

}

int wpa_supplicant_main(void)
{
	uint32 wpa_supplicant_id = 0;
	printf("%s: enter\n",__func__);
	if (wifi_work_mode == WIFI_MODE_STA){
		return 0;
	}
	wpa_supplicant_id = SCI_CreateThread(
			"wpa_supplicant",
			"wpa_supplicant",
			wpa_supplicant_thread_entry,
			0,
			NULL,
			2048,
			10,
			WPA_TASK_PRI,
			SCI_PREEMPT,
			SCI_AUTO_START
			);

	if (wpa_supplicant_id == 0){
		return -1;
	}

	return 0;
}
