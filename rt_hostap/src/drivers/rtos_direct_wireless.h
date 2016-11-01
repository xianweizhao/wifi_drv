#ifndef __RTOS_DIRECT_WIRELESS_H__
#define __RTOS_DIRECT_WIRELESS_H__
enum ieee80211_band {
	IEEE80211_BAND_2GHZ,

	/* keep last */
	IEEE80211_NUM_BANDS
};

enum ieee80211_signal_type {
	IEEE80211_SIGNAL_TYPE_NONE,
	IEEE80211_SIGNAL_TYPE_MBM,
	IEEE80211_SIGNAL_TYPE_UNSPEC,
};
#define CHAN2G(_channel, _freq, _flags) {				\
	.band			= IEEE80211_BAND_2GHZ,			\
	.center_freq		= (_freq),				\
	.hw_value		= (_channel),				\
	.flags			= (_flags),				\
}
struct ieee80211_channel {
	enum ieee80211_band band;
	u16 center_freq;
	u16 hw_value;
	u32 flags;
};

struct ieee80211_supported_band {
	struct ieee80211_channel *channels;
	int n_channels;
};

struct wiphy {
	u8 signal_type;
	signed short scan_signal;
	u8 max_scan_ssids;
	const u32 *cipher_suites;
	int n_cipher_suites;
	struct ieee80211_supported_band *bands[IEEE80211_NUM_BANDS];
	void * priv_data;
};
#endif