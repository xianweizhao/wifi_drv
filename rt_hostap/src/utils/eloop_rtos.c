/*
 * Event loop based on wait msgq  loop
 * Copyright (c) 2016-2019, xianweizhao <xianwei.zhao@spreadtrum.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include "includes.h"

#include "common.h"
#include "trace.h"
#include "list.h"
#include "eloop.h"

struct eloop_timeout {
	struct dl_list list;
	struct os_time time;
	void *eloop_data;
	void *user_data;
	int online;
	eloop_timeout_handler handler;
};

struct eloop_msg_q {
	SCI_MSG_QUEUE_PTR msg_q;
	char buf[MSG_MAX_LEN];
	recev_cb cb[MSG_TYPE_MAX];
	void *user_data[MSG_TYPE_MAX];
};

struct eloop_data {
	int terminate;
	struct eloop_timeout   timeout_cnt[MAX_TIMER_COUNT];
	struct dl_list timeout;
	struct eloop_msg_q msg_q;
};

static struct eloop_data eloop;

int eloop_init(void)
{
	struct eloop_msg_q *emsg_q = NULL;
	os_memset(&eloop, 0, sizeof(eloop));
	dl_list_init(&eloop.timeout);
	emsg_q = &eloop.msg_q;
	emsg_q->msg_q = SCI_CreateMsgQueue("eloop_msg_q",  ELOOP_MSG_LEN,  ELOOP_QUEUE_LEN);

	return 0;
}

SCI_MSG_QUEUE_PTR  eloop_register_msg_q(enum msg_type msg_type,  void *user_data, recev_cb cb)
{
	struct eloop_msg_q *emsg_q = NULL;
	if (msg_type > MSG_TYPE_MAX)
		return NULL;
	emsg_q = &eloop.msg_q;
	emsg_q->user_data[msg_type] = user_data;
	emsg_q->cb[msg_type] = cb;

	return emsg_q->msg_q;
}

int  eloop_unregister_msg_q(enum msg_type msg_type)
{
	struct eloop_msg_q *emsg_q = NULL;
	if (msg_type > MSG_TYPE_MAX)
		return -1;
	emsg_q = &eloop.msg_q;
	emsg_q->user_data[msg_type] = NULL;
	emsg_q->cb[msg_type] = NULL;
	return 0;
}


struct eloop_timeout *eloop_get_free_timer(void)
{
	int i = 0;

	for (i = 0; i < MAX_TIMER_COUNT; i++) {
		if (eloop.timeout_cnt[i].online != 1) {
			eloop.timeout_cnt[i].online = 1;
			return &eloop.timeout_cnt[i];
		}
	}
	return NULL;
}

static void  eloop_put_free_timer(struct eloop_timeout *timeout)
{
	timeout->online = 0;
}

int eloop_register_timeout(unsigned int secs, unsigned int usecs,
			   eloop_timeout_handler handler,
			   void *eloop_data, void *user_data)
{
	struct eloop_timeout *timeout, *tmp;

	timeout = eloop_get_free_timer();
	if (timeout == NULL)
		return -1;
	if (os_get_time(&timeout->time) < 0) {
		eloop_put_free_timer(timeout);
		return -1;
	}
	timeout->time.sec += secs;
	timeout->time.usec += usecs;
	while (timeout->time.usec >= 1000000) {
		timeout->time.sec++;
		timeout->time.usec -= 1000000;
	}
	timeout->eloop_data = eloop_data;
	timeout->user_data = user_data;
	timeout->handler = handler;

	/* Maintain timeouts in order of increasing time */
	dl_list_for_each(tmp, &eloop.timeout, struct eloop_timeout, list) {
		if (os_time_before(&timeout->time, &tmp->time)) {
			dl_list_add(tmp->list.prev, &timeout->list);
			return 0;
		}
	}
	dl_list_add_tail(&eloop.timeout, &timeout->list);

	return 0;
}


static void eloop_remove_timeout(struct eloop_timeout *timeout)
{
	dl_list_del(&timeout->list);
	eloop_put_free_timer(timeout);
}


int eloop_cancel_timeout(eloop_timeout_handler handler,
			 void *eloop_data, void *user_data)
{
	struct eloop_timeout *timeout, *prev;
	int removed = 0;

	dl_list_for_each_safe(timeout, prev, &eloop.timeout,
			      struct eloop_timeout, list) {
		if (timeout->handler == handler &&
		    (timeout->eloop_data == eloop_data ||
		     eloop_data == ELOOP_ALL_CTX) &&
		    (timeout->user_data == user_data ||
		     user_data == ELOOP_ALL_CTX)) {
			eloop_remove_timeout(timeout);
			removed++;
		}
	}

	return removed;
}


int eloop_is_timeout_registered(eloop_timeout_handler handler,
				void *eloop_data, void *user_data)
{
	struct eloop_timeout *tmp;

	dl_list_for_each(tmp, &eloop.timeout, struct eloop_timeout, list) {
		if (tmp->handler == handler &&
		    tmp->eloop_data == eloop_data &&
		    tmp->user_data == user_data)
			return 1;
	}

	return 0;
}

int eloop_deplete_timeout(unsigned int req_secs, unsigned int req_usecs,
			  eloop_timeout_handler handler, void *eloop_data,
			  void *user_data)
{
	struct os_time now, requested, remaining;
	struct eloop_timeout *tmp;

	dl_list_for_each(tmp, &eloop.timeout, struct eloop_timeout, list) {
		if (tmp->handler == handler &&
		    tmp->eloop_data == eloop_data &&
		    tmp->user_data == user_data) {
			requested.sec = req_secs;
			requested.usec = req_usecs;
			os_get_time(&now);
			os_time_sub(&tmp->time, &now, &remaining);
			if (os_time_before(&requested, &remaining)) {
				eloop_cancel_timeout(handler, eloop_data,
						     user_data);
				eloop_register_timeout(requested.sec,
						       requested.usec,
						       handler, eloop_data,
						       user_data);
				return 1;
			}
			return 0;
		}
	}

	return -1;
}

static int process_msg_q(int status)
{
	struct eloop_msg_q *emsg_q = NULL;
	int ret = 0;
	int type = 0;

	emsg_q = &eloop.msg_q;
	if (status == SCI_SUCCESS) {
		type = emsg_q->buf[0];
		if (type > MSG_TYPE_MAX)
			return ret;
		if (emsg_q->cb[type]) {
			ret = emsg_q->cb[type](emsg_q->user_data[type],
				     (char *)&emsg_q->buf);
		}
	}

	return ret;
}

void eloop_run(void)
{
	struct eloop_msg_q *emsg_q = NULL;
	struct os_time tv, now;
	int millsec = 0;
	int status = 0;
	emsg_q = &eloop.msg_q;
	printf("%s: enter\n",__func__);
	while (!eloop.terminate) {
		struct eloop_timeout *timeout;
		timeout = dl_list_first(&eloop.timeout, struct eloop_timeout,
					list);
		if (timeout) {
			os_get_time(&now);
			if (os_time_before(&now, &timeout->time))
				os_time_sub(&timeout->time, &now, &tv);
			else
				tv.sec = tv.usec = 0;

			millsec = 1000 * tv.sec + tv.usec/1000;
		} else {
			millsec = 0xffffffff;
		}
		os_memset(&emsg_q->buf, 0, MSG_MAX_LEN);
		printf("%s: recive msg time: %d\n",__func__, millsec);
		status = SCI_ReceiveMsg(emsg_q->msg_q,
					(char *)&emsg_q->buf, millsec);
		printf("%s: recive msg exit time: %d\n",__func__, millsec);
		/* check if some registered timeouts have occurred */
		timeout = dl_list_first(&eloop.timeout, struct eloop_timeout,
					list);
		if (timeout) {
			os_get_time(&now);
			if (!os_time_before(&now, &timeout->time)) {
				void *eloop_data = timeout->eloop_data;
				void *user_data = timeout->user_data;
				eloop_timeout_handler handler =
					timeout->handler;
				eloop_remove_timeout(timeout);
				handler(eloop_data, user_data);
			}
		}
		process_msg_q(status);
	}
}

void eloop_terminate(void)
{
	eloop.terminate = 1;
}

void eloop_destroy(void)
{
	struct eloop_timeout *timeout, *prev;
	struct os_time now;

	os_get_time(&now);
	dl_list_for_each_safe(timeout, prev, &eloop.timeout,
			      struct eloop_timeout, list) {
		int sec, usec;
		sec = timeout->time.sec - now.sec;
		usec = timeout->time.usec - now.usec;
		if (timeout->time.usec < now.usec) {
			sec--;
			usec += 1000000;
		}
		wpa_printf(MSG_INFO, "ELOOP: remaining timeout: %d.%06d "
			   "eloop_data=%p user_data=%p handler=%p",
			   sec, usec, timeout->eloop_data, timeout->user_data,
			   timeout->handler);
		wpa_trace_dump_funcname("eloop unregistered timeout handler",
					timeout->handler);
		wpa_trace_dump("eloop timeout", timeout);
		eloop_remove_timeout(timeout);
	}

	SCI_DeleteMsgQueue(eloop.msg_q.msg_q);
	eloop.msg_q.msg_q = NULL;
}

int eloop_terminated(void)
{
	return eloop.terminate;
}

