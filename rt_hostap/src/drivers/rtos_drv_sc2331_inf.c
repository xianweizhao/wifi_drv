#include "rtos_drv_sc2331_cmdevt.h"
#include "rtos_drv_intf_common.h"
#include "rtos_drv_sc2331_inf.h"
#include "rtos_drv_sc2331.h"


#define SPRDWL_TX_MSG_NUM 256
#define SPRDWL_TX_DATA_STOPE_QUEU_NUM (SPRDWL_TX_MSG_NUM - 4)
#define SPRDWL_TX_DATA_START_QUEU_NUM (SPRDWL_TX_DATA_STOPE_QUEU_NUM - 4)
#define SPRDWL_RX_MSG_NUM 10
#define HW_TX_SIZE              (13 * 1024)
#define HW_RX_SIZE              (12288)
#define PKT_AGGR_NUM            (14)

struct sdio_chn tx_chn;
struct sdio_chn rx_chn;

static int sprdwl_hw_init(void)
{
	tx_chn.ch[0] = 0;
	tx_chn.ch[1] = 1;
	tx_chn.ch[2] = 2;
	tx_chn.num = 3;
	tx_chn.bit_map = 0x0007;
	tx_chn.timeout_time = 2000;
	tx_chn.timeout_flag = false;

	rx_chn.ch[0] = 8;
	rx_chn.ch[1] = 9;
	rx_chn.ch[2] = 14;
	rx_chn.ch[3] = 11;
	rx_chn.ch[4] = 15;
	rx_chn.ch[5] = 13;
	rx_chn.ch[6] = 10;
	rx_chn.num = 7;
	rx_chn.bit_map = 0xef00;
	rx_chn.timeout_time = 600;
	rx_chn.timeout_flag = false;
	rx_chn.read_flag = true;

	return 0;
}

static int sprdwl_check_valid_chn(struct sdio_chn *chn_info,
				  unsigned short status)
{
	int i, index = -1;

	if (chn_info->read_flag)
		status = status & chn_info->bit_map;
	else
		status = ((status & chn_info->bit_map) ^ (chn_info->bit_map));

	if (status == 0)
		return index;

	for (i = 0; i < chn_info->num; ++i) {
		if (status & (0x1 << chn_info->ch[i])) {
			index = chn_info->ch[i];
			break;
		}
	}

	return index;
}

int sprdwl_get_valid_ch(struct sdio_chn *chn_info)
{
	int ret;
	unsigned short status;

	ret = sdio_chn_status(chn_info->bit_map, &status);
	if (ret != 0) {
		pr_error("%s sdio get status failed.\n", __func__);
		return -1;
	}

	return sprdwl_check_valid_chn(chn_info, status);
}

static int sprdwl_tx_data(unsigned char *data, unsigned int len)
{
	int ret;
	int sdio_ch;
	//pr_info("sdio write data len:%d\n", len);

	sdio_ch = sprdwl_get_valid_ch(&tx_chn);
	if (sdio_ch < 0) {
		pr_error("%s invalid ch: %d\n", __func__, sdio_ch);
		return -1;
	}
	ret = sdio_dev_write(sdio_ch, data, len);
	//data_dump(data+64,32);
	//printf("sdio_dev_write sdio_ch len:(%d %d)",sdio_ch,len);
	if (ret != 0) {
		pr_error("%s sdio write failed.\n", __func__);
		return -1;
	}

	return 0;
}

static int sprdwl_rx_data(unsigned char *data, unsigned int *len)
{
	int ret;
	int sdio_ch;
	int read_len;

	sdio_ch = sprdwl_get_valid_ch(&rx_chn);
	if (sdio_ch < 0) {
		pr_error("%s invalid ch: %d\n", __func__, sdio_ch);
		return -1;
	}

	switch (sdio_ch) {
	case 10:
	case 11:
	case 14:
	case 15:
		SCI_SDIOHandleChnRx();
		break;
	default:
		break;
	}
#ifdef SDIO_BYTES_OPS
	read_len = SCI_SDIOGetChannelDataLenForBlkLmt(sdio_ch);
#else
    read_len = SCI_SDIOGetChannelDataLen(sdio_ch);
#endif
	if (read_len <= 0)
		return -1;

	if(read_len > *len) {
		pr_error("%s invalid data len: %d.\n", __func__, read_len);
		*len = 0;
		return -1;
	}

	*len = (unsigned int)read_len;

	ret = sdio_dev_read(sdio_ch, data, len);
	if (ret != 0) {
		pr_error("%s sdio read failed.\n", __func__);
		return -1;
	}

	return 0;
}

void sprdwl_rx_chn_isr(int chn)
{
	sprdwl_notify_txrx();
}

static void sprdwl_sdio_force_exit(void)
{
}

static int sprdwl_sdio_is_exit(void)
{
	return 0;
}

static struct sprdwl_if_ops sprdwl_sdio_ops = {
	.tx = sprdwl_tx_data,
	.rx = sprdwl_rx_data,
	.force_exit = sprdwl_sdio_force_exit,
	.is_exit = sprdwl_sdio_is_exit,
};

int sprdwl_intf_init(struct sprdwl_priv *priv)
{
	int ret = 0;

	sprdwl_hw_init();

	priv->if_ops = &sprdwl_sdio_ops;

	invalid_recv_flush(8);
	invalid_recv_flush(9);
	/* flush marlin log */
	invalid_recv_flush(14);
	sdiodev_readchn_init(8, (void *)sprdwl_rx_chn_isr, 0);
	sdiodev_readchn_init(9, (void *)sprdwl_rx_chn_isr, 0);

	return ret;
}

