ifdef CONFIG_OS
ifeq ($(CONFIG_OS),sx)
CFLAGS +=  -D__SX__
CFLAGS +=  -DCONFIG_NO_WPA_MSG
endif
export CFLAGS CONFIG_OS
endif

all:
ifeq ($(CONFIG_OS),sx)
	$(Q) $(MAKE) -C wpa_supplicant
	$(Q) $(MAKE) -C hostapd
endif

clean:
ifeq ($(CONFIG_OS),sx)
	$(Q) $(MAKE) -C wpa_supplicant clean
	$(Q) $(MAKE) -C hostapd clean
endif

distclean:
ifeq ($(CONFIG_OS),sx)
	$(Q) $(MAKE) -C wpa_supplicant distclean
	$(Q) $(MAKE) -C hostapd distclean
endif
