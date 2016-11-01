#include "rtos_drv_sc2331.h"
#include "rtos_drv_sc2331_cmdevt.h"
#include "rtos_drv_sc2331_inf.h"
#include "rtos_drv_intf_common.h"
#include "gpio_adp.h"
#include "tcpip_def.h"

unsigned char rx_buf[RX_BUF_LEN];

SCI_SEMAPHORE_PTR thread_sem;
static unsigned short sprdwl_rx_data_process(struct sprdwl_priv *priv,
				      unsigned char *data, unsigned short len)
{
	struct eth_data_packet *hdr = data;

	if (hdr->proto == htons(PROTO_8021X)) {
		/* L2 packet */
		pr_info("Recv L2 packet.\n");
		rtos_drv_rx_eapol(priv->drv, data, len);
	} else {
		//pr_info("Recv data packet.len:%d \n",len);
		wifi_low_level_input(data, len);
	}

	return 0;
}
void sprdwl_notify_txrx(void)
{
	if (thread_sem != NULL)
		SCI_PutSemaphore(thread_sem);
}


static int sprdwl_rx_process(struct sprdwl_priv *priv,
			     unsigned char *buf, unsigned int max_len)
{
	struct msg_hdr *msg = NULL;
	unsigned char *data;
	unsigned short len;
	unsigned int used_len = 0;
	unsigned char event;

	if (buf == NULL || max_len == 0)
		return -1;

	buf += 8;		/*FIXME fixed this magic number */
	max_len -= 8;

	msg = (struct msg_hdr *)buf;

	while (used_len < max_len) {
		data = (unsigned char *)(msg + 1);
		len = msg->len;

		if (msg->type == 0x7F || msg->subtype == 0xFF)
			break;

		switch (msg->type) {
		case HOST_SC2331_PKT:
			data += msg->subtype;
			len -= msg->subtype;
			sprdwl_rx_data_process(priv, data, len);
			break;

		case SC2331_HOST_RSP:    
			sprdwl_rx_rsp_process(priv, (unsigned char *)msg, len); 
			break;
		case HOST_SC2331_CMD:   /* cp2 host event */
			event = msg->subtype;
			sprdwl_rx_event_process(priv, event, data, len);
			break;
		default:
			pr_error("%s unknown msg type %d.\n",
					__func__, msg->type);
			return -1;
		}

		used_len += sizeof(struct msg_hdr) + ALIGN_4BYTE(msg->len);

		msg = (struct msg_hdr *)(buf + used_len);
	}

	return 0;
}

unsigned int sprdwl_rx_thread(unsigned int argc, void *argv)
{
	int index, ret;
	unsigned int rx_len;
	int status;

	struct sprdwl_priv *priv = sprdwl_get_priv();

	while (1) {
		/* wait sdio data trigger */
		ret = SCI_GetSemaphore(thread_sem, SCI_WAIT_FOREVER);
		if (SCI_ERROR == ret)
			break;
		/* SDIO data get full data*/
		while (1) {
			status = SCI_GPIORead(MARLIN_GPIO_1);
			if(status == false)
				break;

			rx_len = RX_BUF_LEN;
			os_memset(rx_buf, 0, RX_BUF_LEN);
			ret = sprdwl_intf_rx(rx_buf, &rx_len);

			if (rx_len == 0 || ret < 0) {
				pr_info("%s (%d %d).sdio error.sleep 100ms \n", __func__,rx_len,ret);	
				SCI_Sleep(100);
				continue;
			}

			sprdwl_rx_process(priv, rx_buf, rx_len);
		}
	}

return 0;
}


int sprdwl_rx_init(void)
{
	int rx_thread_id =0;
	thread_sem = SCI_CreateSemaphore("sprdwl_txrx_signal", 0);
	if (thread_sem == NULL) {
		return -1;
	}
	rx_thread_id = SCI_CreateThread(
				"sprdwl_txrx_thread",
				NULL,
				sprdwl_rx_thread,
				0,
				NULL,
				1024,
				NULL,
				SCI_PRIORITY_NORMAL,
				SCI_PREEMPT,
				SCI_AUTO_START);
	
	if (rx_thread_id == 0)
		return -1;
	return 0;
}
