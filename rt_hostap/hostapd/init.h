/*
 * hostapd - Internal definitions
 * Copyright (c) 2003-2010, Jouni Malinen <j@w1.fi>
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

#ifndef INIT_H
#define INIT_H

#include "ap/hostapd.h"

int hostapd_global_init(struct hostapd_iface  *interface);
struct hostapd_iface * hostapd_interface_init(void);
int hostapd_global_run(struct hostapd_iface *ifaces);
void hostapd_interface_deinit_free(struct hostapd_iface *iface);
void hostapd_global_deinit(void);
int wpa_supplicant_main(void);
#endif /* INIT_H */
