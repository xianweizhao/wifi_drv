/*
 * hostapd / main()
 * Copyright (c) 2002-2010, Jouni Malinen <j@w1.fi>
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
#include "utils/eloop.h"
#include "crypto/tls.h"
#include "common/version.h"
#include "drivers/driver.h"
#include "eap_server/eap.h"
#include "eap_server/tncs.h"
#include "ap/hostapd.h"
#include "ap/ap_config.h"


extern int wpa_debug_level;
extern int wpa_debug_show_keys;
extern int wpa_debug_timestamp;

/**
 * hostapd_init - Allocate and initialize per-interface data
 * @config_file: Path to the configuration file
 * Returns: Pointer to the allocated interface data or %NULL on failure
 *
 * This function is used to allocate main data structures for per-interface
 * data. The allocated data buffer will be freed by calling
 * hostapd_cleanup_iface().
 */
static struct hostapd_iface * hostapd_init(void)
{
	struct hostapd_iface *hapd_iface = NULL;
	struct hostapd_config *conf = NULL;
	struct hostapd_data *hapd;
	size_t i;

	hapd_iface = os_zalloc(sizeof(*hapd_iface));
	if (hapd_iface == NULL)
		goto fail;

	conf = hostapd_config_defaults();
	if (conf == NULL)
		goto fail;

	hapd_iface->conf = conf;
	hapd_iface->num_bss = conf->num_bss;
	hapd_iface->bss = os_zalloc(hapd_iface->num_bss *
				    sizeof(struct hostapd_data *));
	if (hapd_iface->bss == NULL)
		goto fail;

	for (i = 0; i < hapd_iface->num_bss; i++) {
		hapd = hapd_iface->bss[i] =
			hostapd_alloc_bss_data(hapd_iface, conf,
					       &conf->bss[i]);
		if (hapd == NULL)
			goto fail;
		hapd->msg_ctx = hapd;
	}

	return hapd_iface;

fail:
	if (hapd_iface) {
		os_free(hapd_iface->bss);
		os_free(hapd_iface);
	}
	if (conf) {
		os_free(conf);
	}
	return NULL;
}


static int hostapd_driver_init(struct hostapd_iface *iface)
{
	struct wpa_init_params params;
	size_t i;
	struct hostapd_data *hapd = iface->bss[0];
	struct hostapd_bss_config *conf = hapd->conf;
	u8 *b = conf->bssid;

	if (hapd->driver == NULL || hapd->driver->hapd_init == NULL) {
		wpa_printf(MSG_ERROR, "No hostapd driver wrapper available");
		return -1;
	}

	/* Initialize the driver interface */
	if (!(b[0] | b[1] | b[2] | b[3] | b[4] | b[5]))
		b = NULL;

	os_memset(&params, 0, sizeof(params));
	params.bssid = b;
	params.ifname = hapd->conf->iface;
	params.ssid = (const u8 *) hapd->conf->ssid.ssid;
	params.ssid_len = hapd->conf->ssid.ssid_len;
	params.test_socket = hapd->conf->test_socket;

	params.num_bridge = hapd->iface->num_bss;
	params.bridge = os_zalloc(hapd->iface->num_bss * sizeof(char *));
	if (params.bridge == NULL)
		return -1;
	for (i = 0; i < hapd->iface->num_bss; i++) {
		struct hostapd_data *bss = hapd->iface->bss[i];
		if (bss->conf->bridge[0])
			params.bridge[i] = bss->conf->bridge;
	}

	params.own_addr = hapd->own_addr;

	hapd->drv_priv = hapd->driver->hapd_init(hapd, &params);
	os_free(params.bridge);
	if (hapd->drv_priv == NULL) {
		wpa_printf(MSG_ERROR, "%s driver initialization failed.",
			   hapd->driver->name);
		hapd->driver = NULL;
		return -1;
	}

	return 0;
}


void hostapd_interface_deinit_free(struct hostapd_iface *iface)
{
	const struct wpa_driver_ops *driver;
	void *drv_priv;
	if (iface == NULL)
		return;
	driver = iface->bss[0]->driver;
	drv_priv = iface->bss[0]->drv_priv;
	hostapd_interface_deinit(iface);
	if (driver && driver->hapd_deinit)
		driver->hapd_deinit(drv_priv);
	hostapd_interface_free(iface);
}


struct hostapd_iface *
hostapd_interface_init(void)
{
	struct hostapd_iface *iface;

	iface = hostapd_init();
	if (!iface)
		return NULL;

	if (hostapd_driver_init(iface) ||
	    hostapd_setup_interface(iface)) {
		hostapd_interface_deinit_free(iface);
		return NULL;
	}

	return iface;
}


int hostapd_global_init(struct hostapd_iface  *interface)
{


	eloop_init();
	return 0;
}


void hostapd_global_deinit(void)
{

	eloop_destroy();

	/*eap_server_unregister_methods();*/
}


int hostapd_global_run(struct hostapd_iface *ifaces)
{

	eloop_run();

	return 0;
}
