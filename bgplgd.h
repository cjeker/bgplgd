/*	$OpenBSD$ */
/*
 * Copyright (c) 2020 Claudio Jeker <claudio@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define QS_NEIGHBOR	1
#define QS_GROUP	2
#define QS_AS		3
#define QS_PREFIX	4
#define QS_COMMUNITY	5
#define QS_AF		6
#define QS_RIB		7
#define QS_OVS		8
#define QS_BEST		9
#define QS_ALL		10
#define QS_SHORTER	11
#define QS_ERROR	12
#define QS_MAX		13

#define QS_MASK_NEIGHBOR	((1 << QS_NEIGHBOR) | (1 << QS_GROUP))
#define QS_MASK_RIB						\
	((1 << QS_NEIGHBOR) | (1 << QS_GROUP) |	(1 << QS_AS) |	\
	(1 << QS_PREFIX) | (1 << QS_COMMUNITY) | (1 << QS_AF) |	\
	(1 << QS_RIB) | (1 << QS_OVS) | (1 << QS_BEST) |	\
	(1 << QS_ALL) | (1 << QS_SHORTER) | (1 << QS_ERROR))

struct lg_ctx {
	int		command;
	unsigned int	qs_mask;
	union	{
		char		*string;
		int		one;
	}		qs_args[QS_MAX];
};

int parse_querystring(char *, struct lg_ctx *);
