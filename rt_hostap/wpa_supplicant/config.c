/*
 * WPA Supplicant / Configuration parser and common functions
 * Copyright (c) 2003-2008, Jouni Malinen <j@w1.fi>
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
#include "utils/uuid.h"
#include "crypto/sha1.h"
#include "rsn_supp/wpa.h"
#include "eap_peer/eap.h"
#include "config.h"

/**
 * wpa_config_free_ssid - Free network/ssid configuration data
 * @ssid: Configuration data for the network
 *
 * This function frees all resources allocated for the network configuration
 * data.
 */
void wpa_config_free_ssid(struct wpa_ssid *ssid)
{
	os_free(ssid->ssid);
	os_free(ssid);
}


/**
 * wpa_config_free - Free configuration data
 * @config: Configuration data from wpa_config_read()
 *
 * This function frees all resources allocated for the configuration data by
 * wpa_config_read().
 */
void wpa_config_free(struct wpa_config *config)
{

	struct wpa_ssid *ssid, *prev = NULL;
	int i;

	ssid = config->ssid;
	while (ssid) {
		prev = ssid;
		ssid = ssid->next;
		wpa_config_free_ssid(prev);
	}

	/*os_free(config->ctrl_interface);*/
	/*os_free(config->ctrl_interface_group);*/
	os_free(config->opensc_engine_path);
	os_free(config->pkcs11_engine_path);
	os_free(config->pkcs11_module_path);
	os_free(config->driver_param);
	os_free(config->device_name);
	os_free(config->manufacturer);
	os_free(config->model_name);
	os_free(config->model_number);
	os_free(config->serial_number);
	os_free(config->device_type);
	for (i = 0; i < MAX_SEC_DEVICE_TYPES; i++)
		os_free(config->sec_device_type[i]);
	os_free(config->config_methods);
	os_free(config->p2p_ssid_postfix);
	os_free(config->pssid);
	os_free(config);
}


/**
 * wpa_config_alloc_empty - Allocate an empty configuration
 * @ctrl_interface: Control interface parameters, e.g., path to UNIX domain
 * socket
 * @driver_param: Driver parameters
 * Returns: Pointer to allocated configuration data or %NULL on failure
 */
struct wpa_config * wpa_config_alloc_empty(void)
{
	struct wpa_config *config;

	config = os_zalloc(sizeof(*config));
	if (config == NULL)
		return NULL;
	config->eapol_version = DEFAULT_EAPOL_VERSION;
	config->ap_scan = DEFAULT_AP_SCAN;
	config->fast_reauth = DEFAULT_FAST_REAUTH;
	config->p2p_go_intent = DEFAULT_P2P_GO_INTENT;
	config->p2p_intra_bss = DEFAULT_P2P_INTRA_BSS;
	config->bss_max_count = DEFAULT_BSS_MAX_COUNT;
	config->ssid = NULL;

	return config;
}

/**
 * wpa_config_set_network_defaults - Set network default values
 * @ssid: Pointer to network configuration data
 */

void wpa_config_set_network_defaults(struct wpa_ssid *ssid)
{
	ssid->proto = (WPA_PROTO_WPA | WPA_PROTO_RSN);
	ssid->pairwise_cipher = (WPA_CIPHER_CCMP | WPA_CIPHER_TKIP);
	ssid->group_cipher = (WPA_CIPHER_CCMP | WPA_CIPHER_TKIP |
		       WPA_CIPHER_WEP104 | WPA_CIPHER_WEP40);
	ssid->key_mgmt = WPA_KEY_MGMT_PSK;
}

struct wpa_ssid *wpa_config_find_network(struct wpa_config *config, char *name)
{
	struct wpa_ssid *ssid, *last = NULL;
	int ssid_len = 0;

	ssid = config->ssid;
	while (ssid) {
		if (os_strncmp((const char *)ssid->ssid, name,
				ssid->ssid_len) == 0)
			return ssid;
		last = ssid;
		ssid = ssid->next;
	}

	ssid_len = os_strlen(name);
	ssid = os_zalloc(sizeof(*ssid));
	if (ssid == NULL)
		return NULL;
	if (last) {
		last->next = ssid;
		last->pnext = ssid;
	} else
		config->ssid = ssid;
	wpa_config_set_network_defaults(ssid);

	ssid->disabled = 1;
	ssid->ssid = (u8*)os_zalloc(ssid_len);
	if(ssid->ssid) {
		os_memcpy(ssid->ssid, name, ssid_len);
		ssid->ssid_len = ssid_len;
	}
	return ssid;
}

