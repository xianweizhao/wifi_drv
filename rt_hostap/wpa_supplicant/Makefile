ifndef CC
CC=gcc
endif

export LIBDIR ?= /usr/local/lib/
export INCDIR ?= /usr/local/include/
export BINDIR ?= /usr/local/sbin/
PKG_CONFIG ?= pkg-config

CFLAGS += -MMD -Os -Wall -g
CFLAGS += $(EXTRA_CFLAGS)
CFLAGS += -I$(abspath ../src)
CFLAGS += -I$(abspath ../src/utils)

ifdef CONFIG_TESTING_OPTIONS
CFLAGS += -DCONFIG_TESTING_OPTIONS
CONFIG_WPS_TESTING=y
CONFIG_TDLS_TESTING=y
endif

#BINALL=wpa_supplicant wpa_cli
BINALL=wpa_supplicant

#ifndef CONFIG_NO_WPA_PASSPHRASE
#BINALL += wpa_passphrase
#endif

ALL = $(BINALL)
#ALL += systemd/wpa_supplicant.service
#ALL += systemd/wpa_supplicant@.service
#ALL += systemd/wpa_supplicant-nl80211@.service
#ALL += systemd/wpa_supplicant-wired@.service
#ALL += dbus/fi.epitest.hostap.WPASupplicant.service
#ALL += dbus/fi.w1.wpa_supplicant1.service
ifdef CONFIG_BUILD_WPA_CLIENT_SO
ALL += libwpa_client.so
endif


#all: verify_config $(ALL) dynamic_eap_methods
all: .config libwifi

.config:
	cp $(CONFIG_NAME)defconfig .config

verify_config:
	@if [ ! -r .config ]; then \
		echo 'Building wpa_supplicant requires a configuration file'; \
		echo '(.config). See README for more instructions. You can'; \
		echo 'run "cp defconfig .config" to create an example'; \
		echo 'configuration.'; \
		exit 1; \
	fi

mkconfig:
	@if [ -f .config ]; then \
		echo '.config exists - did not replace it'; \
		exit 1; \
	fi
	echo CONFIG_DRIVER_HOSTAP=y >> .config
	echo CONFIG_DRIVER_WEXT=y >> .config

$(DESTDIR)$(BINDIR)/%: %
	install -D $(<) $(@)

install: $(addprefix $(DESTDIR)$(BINDIR)/,$(BINALL))
	$(MAKE) -C ../src install
ifdef CONFIG_BUILD_WPA_CLIENT_SO
	install -m 0644 -D libwpa_client.so $(DESTDIR)/$(LIBDIR)/libwpa_client.so
	install -m 0644 -D ../src/common/wpa_ctrl.h $(DESTDIR)/$(INCDIR)/wpa_ctrl.h
endif

ifdef CONFIG_FIPS
CONFIG_NO_RANDOM_POOL=
CONFIG_OPENSSL_CMAC=y
endif

OBJS = config.o
OBJS += notify_none.o
OBJS += bss.o
OBJS += eap_register.o
OBJS += ../src/utils/common.o
OBJS += ../src/utils/wpa_debug.o
OBJS += ../src/utils/wpabuf.o
OBJS_p = wpa_passphrase.o
OBJS_p += ../src/utils/common.o
OBJS_p += ../src/utils/wpa_debug.o
OBJS_p += ../src/utils/wpabuf.o
OBJS_c = wpa_cli.o ../src/common/wpa_ctrl.o
OBJS_c += ../src/utils/wpa_debug.o
OBJS_c += ../src/utils/common.o

ifdef CONFIG_OS
CONFIG_NAME=$(CONFIG_OS)_
OBJS += ../src/utils/wifi_manager.o
OBJS += ../src/utils/wifi_server_intf.o
OBJS += ../src/utils/intf_yunos.o
endif

-include .config



ifeq ($(CONFIG_OS),sx)
OBJS += ../src/utils/os_rtos.o

endif
OBJS_p += ../src/utils/os_$(CONFIG_OS).o
OBJS_c += ../src/utils/os_$(CONFIG_OS).o



ifndef CONFIG_ELOOP
CONFIG_ELOOP=eloop
endif
OBJS += ../src/utils/$(CONFIG_ELOOP).o
OBJS_c += ../src/utils/$(CONFIG_ELOOP).o





ifdef CONFIG_ELOOP_POLL
CFLAGS += -DCONFIG_ELOOP_POLL
endif

ifdef CONFIG_ELOOP_EPOLL
CFLAGS += -DCONFIG_ELOOP_EPOLL
endif

ifdef CONFIG_EAPOL_TEST
CFLAGS += -Werror -DEAPOL_TEST
endif

ifdef CONFIG_CODE_COVERAGE
CFLAGS += -O0 -fprofile-arcs -ftest-coverage
LIBS += -lgcov
LIBS_c += -lgcov
LIBS_p += -lgcov
endif

ifdef CONFIG_HT_OVERRIDES
CFLAGS += -DCONFIG_HT_OVERRIDES
endif

ifdef CONFIG_VHT_OVERRIDES
CFLAGS += -DCONFIG_VHT_OVERRIDES
endif




ifeq ($(CONFIG_BACKEND), none)
OBJS += config_none.o
endif

ifdef CONFIG_NO_CONFIG_WRITE
CFLAGS += -DCONFIG_NO_CONFIG_WRITE
endif

ifdef CONFIG_NO_CONFIG_BLOBS
CFLAGS += -DCONFIG_NO_CONFIG_BLOBS
endif

ifdef CONFIG_NO_SCAN_PROCESSING
CFLAGS += -DCONFIG_NO_SCAN_PROCESSING
endif

ifdef CONFIG_SUITEB
CFLAGS += -DCONFIG_SUITEB
NEED_SHA256=y
NEED_AES_OMAC1=y
endif

ifdef CONFIG_SUITEB192
CFLAGS += -DCONFIG_SUITEB192
NEED_SHA384=y
endif



ifdef CONFIG_IEEE80211R
CFLAGS += -DCONFIG_IEEE80211R
OBJS += ../src/rsn_supp/wpa_ft.o
NEED_SHA256=y
NEED_AES_OMAC1=y
endif

ifdef CONFIG_MESH
NEED_80211_COMMON=y
NEED_SHA256=y
NEED_AES_SIV=y
NEED_AES_OMAC1=y
NEED_AES_CTR=y
CONFIG_SAE=y
CONFIG_AP=y
CFLAGS += -DCONFIG_MESH
OBJS += mesh.o
OBJS += mesh_mpm.o
OBJS += mesh_rsn.o
endif

ifdef CONFIG_SAE
CFLAGS += -DCONFIG_SAE
OBJS += ../src/common/sae.o
NEED_ECC=y
NEED_DH_GROUPS=y
endif

ifdef CONFIG_WNM
CFLAGS += -DCONFIG_WNM
OBJS += wnm_sta.o
endif

ifdef CONFIG_TDLS
CFLAGS += -DCONFIG_TDLS
OBJS += ../src/rsn_supp/tdls.o
NEED_SHA256=y
NEED_AES_OMAC1=y
endif

ifdef CONFIG_TDLS_TESTING
CFLAGS += -DCONFIG_TDLS_TESTING
endif

ifdef CONFIG_PEERKEY
CFLAGS += -DCONFIG_PEERKEY
endif

ifndef CONFIG_NO_WPA
OBJS += ../src/rsn_supp/wpa.o
OBJS += ../src/rsn_supp/preauth.o
OBJS += ../src/rsn_supp/pmksa_cache.o
OBJS += ../src/rsn_supp/peerkey.o
OBJS += ../src/rsn_supp/wpa_ie.o
OBJS += ../src/common/wpa_common.o
NEED_AES=y
NEED_SHA1=y
NEED_MD5=y
NEED_RC4=y
else
CFLAGS += -DCONFIG_NO_WPA
endif




ifdef CONFIG_NO_ROAMING
CFLAGS += -DCONFIG_NO_ROAMING
endif

include ../src/drivers/drivers.mak
ifdef CONFIG_AP
OBJS_d += $(DRV_BOTH_OBJS)
CFLAGS += $(DRV_BOTH_CFLAGS)
LDFLAGS += $(DRV_BOTH_LDFLAGS)
LIBS += $(DRV_BOTH_LIBS)
else
OBJS_d += $(DRV_WPA_OBJS)
CFLAGS += $(DRV_WPA_CFLAGS)
LDFLAGS += $(DRV_WPA_LDFLAGS)
LIBS += $(DRV_WPA_LIBS)
endif



ifdef CONFIG_ERP
CFLAGS += -DCONFIG_ERP
NEED_SHA256=y
NEED_HMAC_SHA256_KDF=y
endif

ifdef CONFIG_EAP_TLS
# EAP-TLS
ifeq ($(CONFIG_EAP_TLS), dyn)
CFLAGS += -DEAP_TLS_DYNAMIC
EAPDYN += ../src/eap_peer/eap_tls.so
else
CFLAGS += -DEAP_TLS
OBJS += ../src/eap_peer/eap_tls.o
OBJS_h += ../src/eap_server/eap_server_tls.o
endif
TLS_FUNCS=y
CONFIG_IEEE8021X_EAPOL=y
endif









# backwards compatibility for old spelling
ifdef CONFIG_MSCHAPV2
ifndef CONFIG_EAP_MSCHAPV2
CONFIG_EAP_MSCHAPV2=y
endif
endif






















ifdef CONFIG_WPS
# EAP-WSC
CFLAGS += -DCONFIG_WPS -DEAP_WSC
OBJS += wps_supplicant.o
OBJS += ../src/utils/uuid.o
OBJS += ../src/eap_peer/eap_wsc.o ../src/eap_common/eap_wsc_common.o
OBJS += ../src/wps/wps.o
OBJS += ../src/wps/wps_common.o
OBJS += ../src/wps/wps_attr_parse.o
OBJS += ../src/wps/wps_attr_build.o
OBJS += ../src/wps/wps_attr_process.o
OBJS += ../src/wps/wps_dev_attr.o
OBJS += ../src/wps/wps_enrollee.o
OBJS += ../src/wps/wps_registrar.o
OBJS_h += ../src/eap_server/eap_server_wsc.o
CONFIG_IEEE8021X_EAPOL=y
NEED_DH_GROUPS=y
NEED_SHA256=y
NEED_BASE64=y
NEED_AES_CBC=y
NEED_MODEXP=y

ifdef CONFIG_WPS_NFC
CFLAGS += -DCONFIG_WPS_NFC
OBJS += ../src/wps/ndef.o
NEED_WPS_OOB=y
endif

ifdef NEED_WPS_OOB
CFLAGS += -DCONFIG_WPS_OOB
endif

ifdef CONFIG_WPS_ER
CONFIG_WPS_UPNP=y
CFLAGS += -DCONFIG_WPS_ER
OBJS += ../src/wps/wps_er.o
OBJS += ../src/wps/wps_er_ssdp.o
endif

ifdef CONFIG_WPS_UPNP
CFLAGS += -DCONFIG_WPS_UPNP
OBJS += ../src/wps/wps_upnp.o
OBJS += ../src/wps/wps_upnp_ssdp.o
OBJS += ../src/wps/wps_upnp_web.o
OBJS += ../src/wps/wps_upnp_event.o
OBJS += ../src/wps/wps_upnp_ap.o
OBJS += ../src/wps/upnp_xml.o
OBJS += ../src/wps/httpread.o
OBJS += ../src/wps/http_client.o
OBJS += ../src/wps/http_server.o
endif

ifdef CONFIG_WPS_STRICT
CFLAGS += -DCONFIG_WPS_STRICT
OBJS += ../src/wps/wps_validate.o
endif

ifdef CONFIG_WPS_TESTING
CFLAGS += -DCONFIG_WPS_TESTING
endif

ifdef CONFIG_WPS_REG_DISABLE_OPEN
CFLAGS += -DCONFIG_WPS_REG_DISABLE_OPEN
endif

endif

ifdef CONFIG_EAP_IKEV2
# EAP-IKEv2
ifeq ($(CONFIG_EAP_IKEV2), dyn)
CFLAGS += -DEAP_IKEV2_DYNAMIC
EAPDYN += ../src/eap_peer/eap_ikev2.so ../src/eap_peer/ikev2.o
EAPDYN += ../src/eap_common/eap_ikev2_common.o ../src/eap_common/ikev2_common.o
else
CFLAGS += -DEAP_IKEV2
OBJS += ../src/eap_peer/eap_ikev2.o ../src/eap_peer/ikev2.o
OBJS += ../src/eap_common/eap_ikev2_common.o ../src/eap_common/ikev2_common.o
OBJS_h += ../src/eap_server/eap_server_ikev2.o
OBJS_h += ../src/eap_server/ikev2.o
endif
CONFIG_IEEE8021X_EAPOL=y
NEED_DH_GROUPS=y
NEED_DH_GROUPS_ALL=y
NEED_MODEXP=y
NEED_CIPHER=y
endif

ifdef CONFIG_EAP_VENDOR_TEST
ifeq ($(CONFIG_EAP_VENDOR_TEST), dyn)
CFLAGS += -DEAP_VENDOR_TEST_DYNAMIC
EAPDYN += ../src/eap_peer/eap_vendor_test.so
else
CFLAGS += -DEAP_VENDOR_TEST
OBJS += ../src/eap_peer/eap_vendor_test.o
OBJS_h += ../src/eap_server/eap_server_vendor_test.o
endif
CONFIG_IEEE8021X_EAPOL=y
endif

ifdef CONFIG_EAP_TNC
# EAP-TNC
CFLAGS += -DEAP_TNC
OBJS += ../src/eap_peer/eap_tnc.o
OBJS += ../src/eap_peer/tncc.o
OBJS_h += ../src/eap_server/eap_server_tnc.o
OBJS_h += ../src/eap_server/tncs.o
NEED_BASE64=y
ifndef CONFIG_DRIVER_BSD
LIBS += -ldl
endif
endif

ifdef CONFIG_IEEE8021X_EAPOL
# IEEE 802.1X/EAPOL state machines (e.g., for RADIUS authentication)
CFLAGS += -DIEEE8021X_EAPOL
OBJS += ../src/eapol_supp/eapol_supp_sm.o
OBJS += ../src/eap_peer/eap.o ../src/eap_peer/eap_methods.o
NEED_EAP_COMMON=y
ifdef CONFIG_DYNAMIC_EAP_METHODS
CFLAGS += -DCONFIG_DYNAMIC_EAP_METHODS
LIBS += -ldl -rdynamic
endif
endif

ifdef CONFIG_MACSEC
CFLAGS += -DCONFIG_MACSEC
NEED_AES_ENCBLOCK=y
NEED_AES_UNWRAP=y
NEED_AES_WRAP=y
NEED_AES_OMAC1=y
OBJS += wpas_kay.o
OBJS += ../src/pae/ieee802_1x_cp.o
OBJS += ../src/pae/ieee802_1x_kay.o
OBJS += ../src/pae/ieee802_1x_key.o
OBJS += ../src/pae/ieee802_1x_secy_ops.o
endif







ifdef CONFIG_AUTHENTICATOR
OBJS_h += ../src/eapol_auth/eapol_auth_sm.o
OBJS_h += ../src/ap/ieee802_1x.o
endif

ifdef CONFIG_WPA_AUTHENTICATOR
OBJS_h += ../src/ap/wpa_auth.o
OBJS_h += ../src/ap/wpa_auth_ie.o
OBJS_h += ../src/ap/pmksa_cache_auth.o
ifdef CONFIG_IEEE80211R
OBJS_h += ../src/ap/wpa_auth_ft.o
endif
ifdef CONFIG_PEERKEY
OBJS_h += ../src/ap/peerkey_auth.o
endif
endif

ifdef CONFIG_PCSC
# PC/SC interface for smartcards (USIM, GSM SIM)
CFLAGS += -DPCSC_FUNCS -I/usr/include/PCSC
OBJS += ../src/utils/pcsc_funcs.o
# -lpthread may not be needed depending on how pcsc-lite was configured
LIBS += -lpcsclite -lpthread
endif

ifdef CONFIG_SIM_SIMULATOR
CFLAGS += -DCONFIG_SIM_SIMULATOR
NEED_MILENAGE=y
endif

ifdef CONFIG_USIM_SIMULATOR
CFLAGS += -DCONFIG_USIM_SIMULATOR
NEED_MILENAGE=y
endif

ifdef NEED_MILENAGE
OBJS += ../src/crypto/milenage.o
NEED_AES_ENCBLOCK=y
endif

ifdef CONFIG_PKCS12
CFLAGS += -DPKCS12_FUNCS
endif

ifdef CONFIG_SMARTCARD
CFLAGS += -DCONFIG_SMARTCARD
endif

ifdef MS_FUNCS
OBJS += ../src/crypto/ms_funcs.o
NEED_DES=y
NEED_MD4=y
endif

ifdef CHAP
OBJS += ../src/eap_common/chap.o
endif

ifdef TLS_FUNCS
NEED_DES=y
# Shared TLS functions (needed for EAP_TLS, EAP_PEAP, EAP_TTLS, and EAP_FAST)
OBJS += ../src/eap_peer/eap_tls_common.o
OBJS_h += ../src/eap_server/eap_server_tls_common.o
ifndef CONFIG_FIPS
NEED_TLS_PRF=y
NEED_SHA1=y
NEED_MD5=y
endif
endif

ifndef CONFIG_TLS
CONFIG_TLS=openssl
endif

ifdef CONFIG_TLSV11
CFLAGS += -DCONFIG_TLSV11
endif

ifdef CONFIG_TLSV12
CFLAGS += -DCONFIG_TLSV12
NEED_SHA256=y
endif

ifeq ($(CONFIG_TLS), openssl)
ifdef TLS_FUNCS
CFLAGS += -DEAP_TLS_OPENSSL
OBJS += ../src/crypto/tls_openssl.o
LIBS += -lssl
endif
OBJS += ../src/crypto/crypto_openssl.o
OBJS_p += ../src/crypto/crypto_openssl.o
OBJS_priv += ../src/crypto/crypto_openssl.o
ifdef NEED_FIPS186_2_PRF
OBJS += ../src/crypto/fips_prf_openssl.o
endif
NEED_SHA256=y
NEED_TLS_PRF_SHA256=y
LIBS += -lcrypto
LIBS_p += -lcrypto
ifdef CONFIG_TLS_ADD_DL
LIBS += -ldl
LIBS_p += -ldl
endif
endif

ifeq ($(CONFIG_TLS), gnutls)
ifdef TLS_FUNCS
OBJS += ../src/crypto/tls_gnutls.o
LIBS += -lgnutls -lgpg-error
endif
OBJS += ../src/crypto/crypto_gnutls.o
OBJS_p += ../src/crypto/crypto_gnutls.o
OBJS_priv += ../src/crypto/crypto_gnutls.o
ifdef NEED_FIPS186_2_PRF
OBJS += ../src/crypto/fips_prf_internal.o
SHA1OBJS += ../src/crypto/sha1-internal.o
endif
LIBS += -lgcrypt
LIBS_p += -lgcrypt
CONFIG_INTERNAL_SHA256=y
CONFIG_INTERNAL_RC4=y
CONFIG_INTERNAL_DH_GROUP5=y
endif

ifeq ($(CONFIG_TLS), internal)
ifndef CONFIG_CRYPTO
CONFIG_CRYPTO=internal
endif
ifdef TLS_FUNCS
OBJS += ../src/crypto/crypto_internal-rsa.o
OBJS += ../src/crypto/tls_internal.o
OBJS += ../src/tls/tlsv1_common.o
OBJS += ../src/tls/tlsv1_record.o
OBJS += ../src/tls/tlsv1_cred.o
OBJS += ../src/tls/tlsv1_client.o
OBJS += ../src/tls/tlsv1_client_write.o
OBJS += ../src/tls/tlsv1_client_read.o
OBJS += ../src/tls/asn1.o
OBJS += ../src/tls/rsa.o
OBJS += ../src/tls/x509v3.o
OBJS += ../src/tls/pkcs1.o
OBJS += ../src/tls/pkcs5.o
OBJS += ../src/tls/pkcs8.o
NEED_SHA256=y
NEED_BASE64=y
NEED_TLS_PRF=y
ifdef CONFIG_TLSV12
NEED_TLS_PRF_SHA256=y
endif
NEED_MODEXP=y
NEED_CIPHER=y
CFLAGS += -DCONFIG_TLS_INTERNAL_CLIENT
endif
ifdef NEED_CIPHER
NEED_DES=y
OBJS += ../src/crypto/crypto_internal-cipher.o
endif
ifdef NEED_MODEXP
OBJS += ../src/crypto/crypto_internal-modexp.o
OBJS += ../src/tls/bignum.o
endif
ifeq ($(CONFIG_CRYPTO), libtomcrypt)
OBJS += ../src/crypto/crypto_libtomcrypt.o
OBJS_p += ../src/crypto/crypto_libtomcrypt.o
LIBS += -ltomcrypt -ltfm
LIBS_p += -ltomcrypt -ltfm
CONFIG_INTERNAL_SHA256=y
CONFIG_INTERNAL_RC4=y
CONFIG_INTERNAL_DH_GROUP5=y
endif
ifeq ($(CONFIG_CRYPTO), internal)
OBJS += ../src/crypto/crypto_internal.o
OBJS_p += ../src/crypto/crypto_internal.o
NEED_AES_ENC=y
CFLAGS += -DCONFIG_CRYPTO_INTERNAL
ifdef CONFIG_INTERNAL_LIBTOMMATH
CFLAGS += -DCONFIG_INTERNAL_LIBTOMMATH
ifdef CONFIG_INTERNAL_LIBTOMMATH_FAST
CFLAGS += -DLTM_FAST
endif
else
LIBS += -ltommath
LIBS_p += -ltommath
endif
CONFIG_INTERNAL_AES=y
CONFIG_INTERNAL_DES=y
CONFIG_INTERNAL_SHA1=y
CONFIG_INTERNAL_MD4=y
CONFIG_INTERNAL_MD5=y
CONFIG_INTERNAL_SHA256=y
CONFIG_INTERNAL_RC4=y
CONFIG_INTERNAL_DH_GROUP5=y
endif
ifeq ($(CONFIG_CRYPTO), cryptoapi)
OBJS += ../src/crypto/crypto_cryptoapi.o
OBJS_p += ../src/crypto/crypto_cryptoapi.o
CFLAGS += -DCONFIG_CRYPTO_CRYPTOAPI
CONFIG_INTERNAL_SHA256=y
CONFIG_INTERNAL_RC4=y
endif
endif

ifeq ($(CONFIG_TLS), none)
ifdef TLS_FUNCS
OBJS += ../src/crypto/tls_none.o
CFLAGS += -DEAP_TLS_NONE
CONFIG_INTERNAL_AES=y
CONFIG_INTERNAL_SHA1=y
CONFIG_INTERNAL_MD5=y
endif
OBJS += ../src/crypto/crypto_none.o
OBJS_p += ../src/crypto/crypto_none.o
CONFIG_INTERNAL_SHA256=y
CONFIG_INTERNAL_RC4=y
endif

ifdef TLS_FUNCS
ifdef CONFIG_SMARTCARD
ifneq ($(CONFIG_L2_PACKET), freebsd)
LIBS += -ldl
endif
endif
endif

ifndef TLS_FUNCS
OBJS += ../src/crypto/tls_none.o
ifeq ($(CONFIG_TLS), internal)
CONFIG_INTERNAL_AES=y
CONFIG_INTERNAL_SHA1=y
CONFIG_INTERNAL_MD5=y
CONFIG_INTERNAL_RC4=y
endif
endif

AESOBJS = # none so far (see below)
ifdef CONFIG_INTERNAL_AES
AESOBJS += ../src/crypto/aes-internal.o ../src/crypto/aes-internal-dec.o
endif

ifneq ($(CONFIG_TLS), openssl)
NEED_INTERNAL_AES_WRAP=y
endif
ifdef CONFIG_OPENSSL_INTERNAL_AES_WRAP
# Seems to be needed at least with BoringSSL
NEED_INTERNAL_AES_WRAP=y
CFLAGS += -DCONFIG_OPENSSL_INTERNAL_AES_WRAP
endif
ifdef CONFIG_FIPS
# Have to use internal AES key wrap routines to use OpenSSL EVP since the
# OpenSSL AES_wrap_key()/AES_unwrap_key() API is not available in FIPS mode.
NEED_INTERNAL_AES_WRAP=y
endif

ifdef NEED_INTERNAL_AES_WRAP
AESOBJS += ../src/crypto/aes-unwrap.o
endif
ifdef NEED_AES_EAX
AESOBJS += ../src/crypto/aes-eax.o
NEED_AES_CTR=y
endif
ifdef NEED_AES_CTR
AESOBJS += ../src/crypto/aes-ctr.o
endif
ifdef NEED_AES_ENCBLOCK
AESOBJS += ../src/crypto/aes-encblock.o
endif
ifdef NEED_AES_OMAC1
NEED_AES_ENC=y
ifdef CONFIG_OPENSSL_CMAC
CFLAGS += -DCONFIG_OPENSSL_CMAC
else
AESOBJS += ../src/crypto/aes-omac1.o
endif
endif
ifdef NEED_AES_SIV
AESOBJS += ../src/crypto/aes-siv.o
endif
ifdef NEED_AES_WRAP
NEED_AES_ENC=y
ifdef NEED_INTERNAL_AES_WRAP
AESOBJS += ../src/crypto/aes-wrap.o
endif
endif
ifdef NEED_AES_CBC
NEED_AES_ENC=y
ifneq ($(CONFIG_TLS), openssl)
AESOBJS += ../src/crypto/aes-cbc.o
endif
endif
ifdef NEED_AES_ENC
ifdef CONFIG_INTERNAL_AES
AESOBJS += ../src/crypto/aes-internal-enc.o
endif
endif
ifdef NEED_AES
OBJS += $(AESOBJS)
endif

ifdef NEED_SHA1
ifneq ($(CONFIG_TLS), openssl)
SHA1OBJS += ../src/crypto/sha1.o
endif
ifdef CONFIG_INTERNAL_SHA1
SHA1OBJS += ../src/crypto/sha1-internal.o
ifdef NEED_FIPS186_2_PRF
SHA1OBJS += ../src/crypto/fips_prf_internal.o
endif
endif
ifdef CONFIG_NO_WPA_PASSPHRASE
CFLAGS += -DCONFIG_NO_PBKDF2
else
ifneq ($(CONFIG_TLS), openssl)
SHA1OBJS += ../src/crypto/sha1-pbkdf2.o
endif
endif
ifdef NEED_T_PRF
SHA1OBJS += ../src/crypto/sha1-tprf.o
endif
ifdef NEED_TLS_PRF
SHA1OBJS += ../src/crypto/sha1-tlsprf.o
endif
endif

ifndef CONFIG_FIPS
ifneq ($(CONFIG_TLS), openssl)
MD5OBJS += ../src/crypto/md5.o
endif
endif
ifdef NEED_MD5
ifdef CONFIG_INTERNAL_MD5
MD5OBJS += ../src/crypto/md5-internal.o
endif
OBJS += $(MD5OBJS)
OBJS_p += $(MD5OBJS)
OBJS_priv += $(MD5OBJS)
endif

ifdef NEED_MD4
ifdef CONFIG_INTERNAL_MD4
OBJS += ../src/crypto/md4-internal.o
endif
endif

DESOBJS = # none needed when not internal
ifdef NEED_DES
ifdef CONFIG_INTERNAL_DES
DESOBJS += ../src/crypto/des-internal.o
endif
endif

ifdef CONFIG_NO_RC4
CFLAGS += -DCONFIG_NO_RC4
endif

ifdef NEED_RC4
ifdef CONFIG_INTERNAL_RC4
ifndef CONFIG_NO_RC4
OBJS += ../src/crypto/rc4.o
endif
endif
endif

SHA256OBJS = # none by default
ifdef NEED_SHA256
CFLAGS += -DCONFIG_SHA256
ifneq ($(CONFIG_TLS), openssl)
SHA256OBJS += ../src/crypto/sha256.o
endif
SHA256OBJS += ../src/crypto/sha256-prf.o
ifdef CONFIG_INTERNAL_SHA256
SHA256OBJS += ../src/crypto/sha256-internal.o
endif
ifdef NEED_TLS_PRF_SHA256
SHA256OBJS += ../src/crypto/sha256-tlsprf.o
endif
ifdef NEED_HMAC_SHA256_KDF
OBJS += ../src/crypto/sha256-kdf.o
endif
OBJS += $(SHA256OBJS)
endif
ifdef NEED_SHA384
CFLAGS += -DCONFIG_SHA384
OBJS += ../src/crypto/sha384-prf.o
endif

ifdef NEED_DH_GROUPS
OBJS += ../src/crypto/dh_groups.o
endif
ifdef NEED_DH_GROUPS_ALL
CFLAGS += -DALL_DH_GROUPS
endif
ifdef CONFIG_INTERNAL_DH_GROUP5
ifdef NEED_DH_GROUPS
OBJS += ../src/crypto/dh_group5.o
endif
endif

ifdef NEED_ECC
CFLAGS += -DCONFIG_ECC
endif

ifdef CONFIG_CTRL_IFACE
ifeq ($(CONFIG_CTRL_IFACE), y)
CONFIG_CTRL_IFACE=unix
endif
CFLAGS += -DCONFIG_CTRL_IFACE
ifeq ($(CONFIG_CTRL_IFACE), unix)
CFLAGS += -DCONFIG_CTRL_IFACE_UNIX
endif
ifeq ($(CONFIG_CTRL_IFACE), udp)
CFLAGS += -DCONFIG_CTRL_IFACE_UDP
endif
ifeq ($(CONFIG_CTRL_IFACE), udp6)
CONFIG_CTRL_IFACE=udp
CFLAGS += -DCONFIG_CTRL_IFACE_UDP
CFLAGS += -DCONFIG_CTRL_IFACE_UDP_IPV6
endif
ifeq ($(CONFIG_CTRL_IFACE), named_pipe)
CFLAGS += -DCONFIG_CTRL_IFACE_NAMED_PIPE
endif
ifeq ($(CONFIG_CTRL_IFACE), udp-remote)
CONFIG_CTRL_IFACE=udp
CFLAGS += -DCONFIG_CTRL_IFACE_UDP
CFLAGS += -DCONFIG_CTRL_IFACE_UDP_REMOTE
endif
ifeq ($(CONFIG_CTRL_IFACE), udp6-remote)
CONFIG_CTRL_IFACE=udp
CFLAGS += -DCONFIG_CTRL_IFACE_UDP
CFLAGS += -DCONFIG_CTRL_IFACE_UDP_REMOTE
CFLAGS += -DCONFIG_CTRL_IFACE_UDP_IPV6
endif
OBJS += ctrl_iface.o ctrl_iface_$(CONFIG_CTRL_IFACE).o
endif

ifdef CONFIG_CTRL_IFACE_DBUS
DBUS=y
DBUS_CFLAGS += -DCONFIG_CTRL_IFACE_DBUS -DDBUS_API_SUBJECT_TO_CHANGE
DBUS_OBJS += dbus/dbus_old.o dbus/dbus_old_handlers.o
ifdef CONFIG_WPS
DBUS_OBJS += dbus/dbus_old_handlers_wps.o
endif
DBUS_OBJS += dbus/dbus_dict_helpers.o
ifndef DBUS_LIBS
DBUS_LIBS := $(shell $(PKG_CONFIG) --libs dbus-1)
endif
ifndef DBUS_INCLUDE
DBUS_INCLUDE := $(shell $(PKG_CONFIG) --cflags dbus-1)
endif
DBUS_CFLAGS += $(DBUS_INCLUDE)
endif



ifdef DBUS
DBUS_CFLAGS += -DCONFIG_DBUS
DBUS_OBJS += dbus/dbus_common.o
endif

OBJS += $(DBUS_OBJS)
CFLAGS += $(DBUS_CFLAGS)
LIBS += $(DBUS_LIBS)


ifdef CONFIG_NO_STDOUT_DEBUG
CFLAGS += -DCONFIG_NO_STDOUT_DEBUG
ifndef CONFIG_CTRL_IFACE
CFLAGS += -DCONFIG_NO_WPA_MSG
endif
endif

ifdef CONFIG_IPV6
# for eapol_test only
CFLAGS += -DCONFIG_IPV6
endif

ifdef NEED_BASE64
OBJS += ../src/utils/base64.o
endif

ifdef NEED_SME
OBJS += sme.o
CFLAGS += -DCONFIG_SME
endif

OBJS += ../src/common/ieee802_11_common.o

ifdef NEED_EAP_COMMON
OBJS += ../src/eap_common/eap_common.o
endif


ifdef CONFIG_DEBUG_LINUX_TRACING
CFLAGS += -DCONFIG_DEBUG_LINUX_TRACING
endif

ifdef CONFIG_DEBUG_FILE
CFLAGS += -DCONFIG_DEBUG_FILE
endif

ifdef CONFIG_DELAYED_MIC_ERROR_REPORT
CFLAGS += -DCONFIG_DELAYED_MIC_ERROR_REPORT
endif



OBJS += $(SHA1OBJS) $(DESOBJS)

OBJS_p += $(SHA1OBJS)
OBJS_p += $(SHA256OBJS)
OBJS_priv += $(SHA1OBJS)

















OBJS_wpa_rm := ctrl_iface.o ctrl_iface_unix.o
OBJS_wpa := $(filter-out $(OBJS_wpa_rm),$(OBJS)) $(OBJS_h) tests/test_wpa.o
ifdef CONFIG_AUTHENTICATOR
OBJS_wpa += tests/link_test.o
endif
OBJS_wpa += $(OBJS_l2)
OBJS += wpa_supplicant.o events.o blacklist.o wpas_glue.o scan.o
OBJS_t := $(OBJS) $(OBJS_l2) eapol_test.o
OBJS_t += ../src/radius/radius_client.o
OBJS_t += ../src/radius/radius.o
ifndef CONFIG_AP
OBJS_t += ../src/utils/ip_addr.o
endif
OBJS_t2 := $(OBJS) $(OBJS_l2) preauth_test.o

OBJS_nfc := $(OBJS) $(OBJS_l2) nfc_pw_token.o
OBJS_nfc += $(OBJS_d) ../src/drivers/drivers.o

ifeq ($(CONFIG_OS), nuttx)
OBJS += wpa_supplicant_main.o
else ifeq ($(CONFIG_OS),sx)
OBJS += wpa_supplicant_main.o
else
OBJS += $(CONFIG_MAIN).o
endif



OBJS += $(OBJS_d) ../src/drivers/drivers.o
OBJS += $(OBJS_l2)



ifdef CONFIG_FST
CFLAGS += -DCONFIG_FST
ifdef CONFIG_FST_TEST
CFLAGS += -DCONFIG_FST_TEST
endif


OBJS += $(FST_OBJS)
OBJS_t += $(FST_OBJS)
OBJS_t2 += $(FST_OBJS)
endif

ifndef LDO
LDO=$(CC)
endif

Q=@
E=echo
ifeq ($(V), 1)
Q=
E=true
endif
ifeq ($(QUIET), 1)
Q=@
E=true
endif

dynamic_eap_methods: $(EAPDYN)

../src/drivers/build.wpa_supplicant:
	@if [ -f ../src/drivers/build.hostapd ]; then \
		$(MAKE) -C ../src/drivers clean; \
	fi
	@touch ../src/drivers/build.wpa_supplicant

BCHECK=../src/drivers/build.wpa_supplicant



$(OBJS_c) $(OBJS_t) $(OBJS_t2) $(OBJS) $(BCHECK) $(EXTRA_progs): .config





%.so: %.c
	$(CC) $(LDFLAGS) -o $@ $(CFLAGS) -shared -rdynamic -fPIC $< \
		-D$(*F:eap_%=eap_peer_%)_register=eap_peer_method_dynamic_init

ifdef CONFIG_CODE_COVERAGE
%.o: %.c
	@$(E) "  CC " $<
	$(Q)cd $(dir $@); $(CC) -c -o $(notdir $@) $(CFLAGS) $(notdir $<)
else
%.o: %.c
	$(Q)$(CC) -c -o $@ $(CFLAGS) $<
	@$(E) "  CC " $<
endif

%.service: %.service.in
	$(Q)sed -e 's|\@BINDIR\@|$(BINDIR)|g' $< >$@
	@$(E) "  sed" $<

%@.service: %.service.arg.in
	$(Q)sed -e 's|\@BINDIR\@|$(BINDIR)|g' $< >$@
	@$(E) "  sed" $<




libwifi: $(OBJS)
	$(AR) rcs ../libwifi.a $^
clean:
	$(MAKE) -C ../src clean
	rm -f core *~ *.o *.d *.gcno *.gcda *.gcov
	rm -f eap_*.so $(ALL) $(WINALL) eapol_test preauth_test
	rm -f wpa_priv
	rm -f nfc_pw_token
	rm -f lcov.info
	rm -rf lcov-html
	rm -f libwpa_client.a
	rm -f libwpa_client.so
	@if [ -f ../libwifi.a ]; then \
		rm -f ../libwifi.a; \
	fi
	@if [ -f .config ]; then \
		rm -f .config; \
	fi

distclean: clean
	rm -f .config

-include $(OBJS:%.o=%.d)
