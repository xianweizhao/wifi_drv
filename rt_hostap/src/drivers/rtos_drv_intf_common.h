/*
 * Copyright (C) 2015 Spreadtrum Communications Inc.
 *
 * Authors	:
 * Keguang Zhang <keguang.zhang@spreadtrum.com>
 * Jingxiang Li <Jingxiang.li@spreadtrum.com>
 * Eason Xiang <eason@weenas.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __RTOS_DRV_INTF_COMMON_H__
#define __RTOS_DRV_INTF_COMMON_H__

struct sprdwl_priv;

struct sprdwl_if_ops {
	int (*tx)(void *data, unsigned int len);
	int (*rx)(void *data, unsigned int *len);
	void (*force_exit)(void);
	int (*is_exit)(void);
	int (*suspend)(void);
	int (*resume)(void);
};

struct sprdwl_if_ops *sprdwl_get_if_ops(void);

static inline int sprdwl_intf_tx(void *data, int len)
{
	return sprdwl_get_if_ops()->tx(data, len);
}

static inline int sprdwl_intf_rx(void *data, int *len)
{
	return sprdwl_get_if_ops()->rx(data, len);
}

static inline void sprdwl_intf_force_exit(struct sprdwl_priv *priv)
{
	sprdwl_get_if_ops()->force_exit();
}

static inline int sprdwl_intf_is_exit(void)
{
	return sprdwl_get_if_ops()->is_exit();
}

static inline int sprdwl_intf_suspend(void)
{
	struct sprdwl_if_ops *if_ops = sprdwl_get_if_ops();

	if (if_ops->suspend)
		return if_ops->suspend();

	return 0;
}

static inline int sprdwl_intf_resume(void)
{
	struct sprdwl_if_ops *if_ops = sprdwl_get_if_ops();

	if (if_ops->resume)
		return if_ops->resume();

	return 0;
}
extern int sprdwl_intf_init(struct sprdwl_priv *priv);
#endif
