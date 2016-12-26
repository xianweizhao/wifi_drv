##### CLEAR VARS

DRV_WPA_CFLAGS =
DRV_OBJS =
DRV_WPA_OBJS =

##### COMMON DRIVERS

DRV_OBJS += ../src/drivers/drivers.o
ifdef CONFIG_DRIVER_RTOS
DRV_WPA_OBJS += ../src/drivers/rtos_sta_direct.o
DRV_WPA_OBJS += ../src/drivers/rtos_drv_sc2331_cmdevt.o
DRV_WPA_OBJS += ../src/drivers/rtos_drv_sc2331_rx_process.o
DRV_WPA_OBJS += ../src/drivers/rtos_drv_sc2331_inf.o
DRV_WPA_OBJS += ../src/drivers/rtos_direct_wireless.o
DRV_WPA_CFLAGS += -DCONFIG_WIRELESS_EXTENSION
endif

##### COMMON VARS
DRV_BOTH_CFLAGS := $(DRV_WPA_CFLAGS)

DRV_BOTH_OBJS := $(DRV_OBJS) $(DRV_WPA_OBJS)
DRV_WPA_OBJS += $(DRV_OBJS)
