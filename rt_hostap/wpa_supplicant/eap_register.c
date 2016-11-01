/*
 * EAP method registration
 * Copyright (c) 2004-2009, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "eap_peer/eap_methods.h"
#include "eap_server/eap_methods.h"
#include "wpa_supplicant_i.h"


/**
 * eap_register_methods - Register statically linked EAP methods
 * Returns: 0 on success, -1 or -2 on failure
 *
 * This function is called at program initialization to register all EAP
 * methods that were linked in statically.
 */
int eap_register_methods(void)
{
	int ret = 0;
#ifdef EAP_WSC
	if (ret == 0)
		ret = eap_peer_wsc_register();
#endif /* EAP_WSC */

#ifdef EAP_SERVER_WSC
	if (ret == 0)
		ret = eap_server_wsc_register();
#endif /* EAP_SERVER_WSC */


	return ret;
}
