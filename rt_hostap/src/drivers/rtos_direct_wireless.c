#include <string.h>
#include "rtos_drv_sc2331.h"
#include "rtos_drv_sc2331_cmdevt.h"

#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "rtos_drv_intf_common.h"
#include "utils/list.h"
#include "rtos_direct_wireless.h"

static const u32 sprdwl_cipher_suites[] = {
	WLAN_CIPHER_SUITE_WEP40,
	WLAN_CIPHER_SUITE_WEP104,
	WLAN_CIPHER_SUITE_TKIP,
	WLAN_CIPHER_SUITE_CCMP,
	/* required by ieee802.11w */
	WLAN_CIPHER_SUITE_AES_CMAC,
	WLAN_CIPHER_SUITE_PMK,
};

static struct ieee80211_channel sprdwl_2ghz_channels[] = {
	CHAN2G(1, 2412, 0),
	CHAN2G(2, 2417, 0),
	CHAN2G(3, 2422, 0),
	CHAN2G(4, 2427, 0),
	CHAN2G(5, 2432, 0),
	CHAN2G(6, 2437, 0),
	CHAN2G(7, 2442, 0),
	CHAN2G(8, 2447, 0),
	CHAN2G(9, 2452, 0),
	CHAN2G(10, 2457, 0),
	CHAN2G(11, 2462, 0),
	CHAN2G(12, 2467, 0),
	CHAN2G(13, 2472, 0),
	CHAN2G(14, 2484, 0),
};
static struct ieee80211_supported_band sprdwl_band_2ghz = {
	.n_channels = ARRAY_SIZE(sprdwl_2ghz_channels),
	.channels = sprdwl_2ghz_channels,
};

/* We should alloc different space for different type of network card */
struct wiphy *register_wireless_device(void *data)
{
	struct wiphy *wiphy = NULL;
#ifdef CONFIG_NET_DEV
	struct net_device *wireless = NULL;
	wireless = os_zalloc(sizeof(struct net_device));
	if (!wireless) {
		pr_error("%s no enough space for wirless\n", __func__);
		return NULL;
	}
#endif
	printf("%s enter\n",__func__);
	wiphy = os_zalloc(sizeof(struct wiphy));
	if (!wiphy) {
		pr_error("%s no enough space for wirelss priv\n", __func__);
		goto err1;
	}

	/* vendor specific */
	wiphy->signal_type = IEEE80211_SIGNAL_TYPE_MBM;
	wiphy->cipher_suites = sprdwl_cipher_suites;
	wiphy->n_cipher_suites = ARRAY_SIZE(sprdwl_cipher_suites);
	wiphy->bands[IEEE80211_BAND_2GHZ] = &sprdwl_band_2ghz;
	wiphy->max_scan_ssids = 12;

	wiphy->priv_data = data;

	return wiphy;

err1:
	os_free(wiphy);

	return NULL;
}

void unregister_wireless_device(struct wiphy *wiphy)
{
	os_free(wiphy->priv_data);
	os_free(wiphy);
}

