/*
 * SHA1 implementation for NuttX
 * Copyright (c) 2016, Kelvin Cheung <keguang.zhang@gmail.com>
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


#include <string.h>
#include <nuttx/crypto/sha1.h>
#include "common.h"


/**
 * sha1_vector - SHA-1 hash for data vector
 * @num_elem: Number of elements in the data vector
 * @addr: Pointers to the data areas
 * @len: Lengths of the data blocks
 * @mac: Buffer for the hash
 * Returns: 0 on success, -1 of failure
 */
int sha1_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
	SHA1_CTX ctx;
	size_t i;

	SHA1_Init(&ctx);
	for (i = 0; i < num_elem; i++)
		SHA1_Update(&ctx, addr[i], len[i]);
	SHA1_Final(mac, &ctx);
	return 0;
}
