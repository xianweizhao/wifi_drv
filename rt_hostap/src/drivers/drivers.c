#include "includes.h"
#include "rtos_sta_direct.h"

extern struct wpa_driver_ops wpa_driver_direct_ops; /* rtos_sta-disrect.c */

struct wpa_driver_ops *wpa_drivers[] =
{
	&wpa_driver_direct_ops,
	NULL
};
