/*
 * wpa_supplicant/hostapd - Default include files
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * This header file is included into all C files so that commonly used header
 * files can be selected with OS specific ifdef blocks in one place instead of
 * having to have OS/C library specific selection in many files.
 */

#ifndef INCLUDES_H
#define INCLUDES_H

/* Include possible build time configuration before including anything else */
#include "build_config.h"

#ifdef __SX__
#include "stdlib.h"
#include "stddef.h"
#include "stdio.h"
#include "stdarg.h"
#include "string.h"
#include "ctype.h"
#include "cs_types.h"
#include "cos.h"
#include "time.h"
#include "tcpip_inet.h"
#include "tcpip_sockets.h"
#include "os_adp.h"
#endif /* __SX__ */
#endif /* INCLUDES_H */
