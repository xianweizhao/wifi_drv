/*
 * hostapd / Example program entrypoint
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

#include "utils/includes.h"
#include "utils/common.h"
#include "ap/hostapd.h"
#include "wifi_manager.h"
#include "os_adp.h"
#include "init.h"
#include "wifi_server_intf.h"
#define HOSTAPD_TASK_PRI 80

struct hostapd_iface *g_hostapd_iface = NULL;

static void hostapd_thread_entry(uint32 argc, void *argv)
{
	int status = 0;

	status = wpas_change_wifi_mode(WIFI_MODE_AP, 1);

	if (hostapd_global_init(NULL))
		goto out;

	/* Initialize interfaces */

	g_hostapd_iface = hostapd_interface_init();
	if (g_hostapd_iface == NULL)
		goto out1;

	hostapd_priv_data_init(g_hostapd_iface);
	status = hostapd_global_run(g_hostapd_iface);
	wpas_priv_data_deinit();

out1:
	/* Deinitialize all interfaces */
	hostapd_interface_deinit_free(g_hostapd_iface);
	g_hostapd_iface = NULL;

	hostapd_global_deinit();

#ifdef WCND_IS_OK
	status = SCI_WCNWIFIClose();
#endif
out:
	wpas_change_wifi_mode(WIFI_MODE_NONE, 0);
}

int hostapd_main(void)
{
	uint32 hostapd_id = 0;

	if (wifi_work_mode == WIFI_MODE_AP){
		return 0;
	}

	hostapd_id = SCI_CreateThread(
			"hostapd",
			"hostapd",
			hostapd_thread_entry,
			0,
			NULL,
			2048,
			10,
			HOSTAPD_TASK_PRI,
			SCI_PREEMPT,
			SCI_AUTO_START
			);

	if (hostapd_id == 0){
		return -1;
	}

	return 0;
}

