/*
 * WPA Supplicant / Configuration backend: empty starting point
 * Copyright (c) 2003-2005, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * This file implements dummy example of a configuration backend. None of the
 * functions are actually implemented so this can be used as a simple
 * compilation test or a starting point for a new configuration backend.
 */

#include "includes.h"

#include "common.h"
#include "config.h"
#include "base64.h"


struct wpa_config * wpa_config_read(const char *name, struct wpa_config *cfgp)
{
	struct wpa_config *config;

	if (name == NULL)
		return NULL;
	if (cfgp)
		config = cfgp;
	else
		config = wpa_config_alloc_empty();
	if (config == NULL)
		return NULL;
	/* TODO: fill in configuration data */
	return config;
}


int wpa_config_write(const char *name, struct wpa_config *config)
{
	return 0;
}
