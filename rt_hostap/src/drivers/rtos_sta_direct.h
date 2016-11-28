#ifndef __RTOS_STA_DIRECT_H__
#define __RTOS_STA_DIRECT_H__

#include "driver.h"
#include "os_adp.h"
#include "rtos_direct_drv.h"
#include "rtos_drv_sc2331.h"

struct wpa_driver_direct_data {
	void *ctx;
	struct sprdwl_priv *drv_priv;
	SCI_MSG_QUEUE_PTR msg_q;

	char ifname[IFNAMSIZ + 1];
	int ifindex;
	int ifindex2;
	int if_removed;
	int if_disabled;
	
	u8 *assoc_req_ies;
	size_t assoc_req_ies_len;
	u8 *assoc_resp_ies;
	size_t assoc_resp_ies_len;
	struct wpa_driver_capa capa;
	int has_capability;
	int we_version_compiled;

	/* for set_auth_alg fallback */
	int use_crypt;
	int auth_alg_fallback;

	int operstate;

	int cfg80211; /* whether driver is using cfg80211 */

	u8 max_level;
};

void rtos_drv_rx_eapol(struct wpa_driver_direct_data *drv, const u8 *data, u32 len);
#endif /* RTOS_STA_DIRECT_H */
