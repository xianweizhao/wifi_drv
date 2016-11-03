#ifndef __RTOS_DRV_SC2331_INF_H__
#define __RTOS_DRV_SC2331_INF_H__
#include "sdio_adp.h"
struct sdio_chn {
	unsigned char ch[16];
	unsigned char num;
	unsigned short bit_map;
	int gpio_high;
	int chn_timeout_cnt;
	unsigned long timeout;
	unsigned long timeout_time;
	bool timeout_flag;
	bool read_flag;
};

struct hw_info {
	int wakeup;
	int can_sleep;
	unsigned int rx_record;
	struct sdio_chn sdio_tx_chn;
	struct sdio_chn sdio_rx_chn;
	unsigned int rx_gpio;
};

struct sprdwl_tx_buf {
	unsigned char *base;
	unsigned short buf_len;
	unsigned short curpos;
};

struct sprdwl_rx_buf {
	unsigned char *base;
	unsigned short buf_len;
	unsigned short data_len;
};

struct sprdwl_priv;
struct sprdwl_sdio {
	/* priv use void *, after MCC adn priv->flags,
	 * and change txrx intf pass priv to void later
	 */
	struct sprdwl_priv *priv;
	/* if nedd more flags which not only exit, fix it */
	/* unsigned int exit:1; */
	int exit;

	/* tx work */
	struct sprdwl_tx_buf txbuf;

	struct sprdwl_rx_buf rxbuf;
	struct sdio_chn chn;
	struct hw_info hw;
};

/* 0 for cmd, 1 for event, 2 for data */
enum sprdwl_head_type {
	SPRDWL_TYPE_CMD,
	SPRDWL_TYPE_EVENT,
	SPRDWL_TYPE_DATA,
};

enum sprdwl_head_rsp {
	/* cmd no rsp */
	SPRDWL_HEAD_NORSP,
	/* cmd need rsp */
	SPRDWL_HEAD_RSP,
};

/* bit[7][6][5] mode: sprdwl_mode
 * bit[4] rsp: sprdwl_head_rsp
 * bit[3] reserv
 * bit[2][1][0] type: sprdwl_head_type
 */
struct sprdwl_common_hdr {
	unsigned char type:3;
	unsigned char reserv:1;
	unsigned char rsp:1;
	unsigned char mode:3;
};

#define SPRDWL_HEAD_GET_TYPE(common) \
	(((struct sprdwl_common_hdr *)(common))->type)

struct sprdwl_cmd_hdr {
	struct sprdwl_common_hdr common;
	unsigned char cmd_id;
	/* the payload len include the size of this struct */
	unsigned short plen;
	unsigned int mstime;
	unsigned char paydata[0];
};

#define SPRDWL_GET_CMD_PAYDATA(msg) \
	    (((struct sprdwl_cmd_hdr *)((msg)->skb->data))->paydata)

struct sprdwl_data_hdr {
	struct sprdwl_common_hdr common;
	/* bit[7][6][5] type: 0 for normal data, 1 for wapi data
	 * bit[4][3][2][1][0] offset: the ETH data after this struct address
	 */
#define SPRDWL_DATA_TYPE_NORMAL		0
#define SPRDWL_DATA_TYPE_WAPI		(0x1 << 5)
#define SPRDWL_DATA_TYPE_MAX		SPRDWL_DATA_TYPE_WAPI
#define SPRDWL_GET_DATA_TYPE(info)	((info) & 0xe0)
#define SPRDWL_DATA_OFFSET_MASK		0x1f
	unsigned char info1;
	/* the payload len include the size of this struct */
	unsigned short plen;
	/* the flow contrl shared by sta and p2p */
	unsigned char flow0;
	/* the sta flow contrl */
	unsigned char flow1;
	/* the p2p flow contrl */
	unsigned char flow2;
	/* flow3 0: share, 1: self */
	unsigned char flow3;
};

enum sprdwl_mode {
	SPRDWL_MODE_NONE,
	SPRDWL_MODE_STATION,
	SPRDWL_MODE_AP,

	SPRDWL_MODE_P2P_DEVICE = 4,
	SPRDWL_MODE_P2P_CLIENT,
	SPRDWL_MODE_P2P_GO,
	SPRDWL_MODE_MAX,
};

static inline int set_marlin_wakeup(unsigned int chn, unsigned int user_id)
{
       return SCI_MarlinWakeUp();
}

static inline void usleep_range(int a, int b)
{
}

static inline int sdio_chn_status(unsigned int chn, unsigned short *status)
{
       return SCI_SDIOGetReadyChannelBitmap(chn, status);
}

static inline int sdio_dev_write(unsigned int chn, void *data_buf,
                             unsigned int count)
{
#ifdef SDIO_BYTES_OPS
      if(chn == 3)return SCI_SDIOWriteSync(chn, data_buf, count);
        return SCI_SDIOWriteSyncForBlkLmt(chn, data_buf, count);
#else
       return SCI_SDIOWriteSync(chn, data_buf, count);
#endif
}

static inline void invalid_recv_flush(unsigned int chn)
{
}

static inline int sdiodev_readchn_init(unsigned int chn, void *callback,
                            unsigned char with_para)
{
      SCI_SDIORegisterChannel(chn, callback);

       return 0;
}

static inline int sdio_dev_read(unsigned int chn, void *read_buf,
                   unsigned int *count)
{

#ifdef SDIO_BYTES_OPS
       return SCI_SDIOReadSyncForBlkLmt(chn, read_buf, count);
#else
    return SCI_SDIOReadSync(chn, read_buf, count);
#endif
}

static inline unsigned char get_sdiohal_status(void)
{
       return 0;
}

int sdiodev_readchn_uninit(unsigned int chn);
void mdbg_at_cmd_read(void);
void mdbg_loopcheck_read(void);
void mdbg_sdio_read(void);


#endif /* __RTOS_DRV_SC2331_INF_H__ */

