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

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "bgplgd.h"
#include "slowcgi.h"

enum qs_type {
	ONE,
	STRING,
	PREFIX,
	AS,
	COMMUNITY,
	FAMILY,
	OVS
};

const struct qs {
	unsigned int	qs;
	const char	*key;
	enum qs_type	type;
} qsargs[] = {
	{ QS_NEIGHBOR, "neighbor", STRING, },
	{ QS_GROUP, "group", STRING },
	{ QS_AS, "as", AS },
	{ QS_PREFIX, "prefix", PREFIX },
	{ QS_COMMUNITY, "community", COMMUNITY },
	{ QS_AF, "af", FAMILY },
	{ QS_RIB, "rib", STRING },
	{ QS_OVS, "ovs", OVS },
	{ QS_BEST, "best", ONE },
	{ QS_ALL, "all", ONE },
	{ QS_SHORTER, "or-shorter", ONE },
	{ QS_ERROR, "error", ONE },
	{ 0, NULL }
};

static int
hex(char x)
{
	if ('0' <= x && x <= '9')
		return x - '0';
	if ('a' <= x && x <= 'f')
		return x - 'a' + 10;
	else
		return x - 'A' + 10;
}

static char *
urldecode(char *s, size_t len)
{
	static char buf[256];
	size_t i, blen = 0;

	buf[0] = '\0';
	for (i = 0; i < len; i++) {
		if (blen >= sizeof(buf))
			return NULL;
		if (s[i] == '+') {
			buf[blen++] = ' ';
		} else if (s[i] == '%' && i + 2 < len) {
			if (isxdigit((unsigned char)s[i + 1]) &&
			    isxdigit((unsigned char)s[i + 2])) {
				char c;
				c = hex(s[i + 1]) << 4 | hex(s[i + 2]);
				/* replace NUL chars with space */
				if (c == 0)
					c = ' ';
				buf[blen++] = c;
				i += 2;
			} else
				buf[blen++] = s[i];
		} else {
			buf[blen++] = s[i];
		}
	}

	return buf;
}

static int
parse_value(struct lg_ctx *ctx, unsigned int key, enum qs_type type, char *val)
{
	/* val can only be NULL if urldecode failed. */
	if (val == NULL) {
		lwarnx("NULL QS value");
		return 400;
	}

	switch (type) {
	case ONE:
		if (strcmp("1", val) == 0) {
			ctx->qs_args[key].one = 1;
		} else if (strcmp("0", val) == 0) {
			/* silently ignored */
		} else {
			lwarnx("bad value %s expected 1", val);
			return 400;
		}
		break;
	case STRING:
		/* XXX limit string to subset of chars */
		if (ctx->qs_args[key].string) {
			lwarnx("STRING already set");
			return 400;
		}
		ctx->qs_args[key].string = strdup(val);
		if (ctx->qs_args[key].string == NULL) {
			lwarn("parse_value");
			return 500;
		}
		break;
	case PREFIX:
		break;
	case AS:
		break;
	case COMMUNITY:
		break;
	case FAMILY:
		if (ctx->qs_args[key].string != NULL) {
			lwarnx("duplicate FAMILY argument");
			return 400;
		}
		if (strcasecmp("ipv4", val) == 0 ||
		    strcasecmp("ipv6", val) == 0 ||
		    strcasecmp("vpnv4", val) == 0 ||
		    strcasecmp("vpnv6", val) == 0) {
			ctx->qs_args[key].string = strdup(val);
			if (ctx->qs_args[key].string == NULL) {
				lwarn("parse_value");
				return 500;
			}
		} else {
			lwarnx("bad FAMILY value %s", val);
			return 400;
		}
		break;
	case OVS:
		if (ctx->qs_args[key].string) {
			lwarnx("OVS already set");
			return 400;
		}
		if (strcmp("not-found", val) == 0 ||
		    strcmp("valid", val) == 0 ||
		    strcmp("invalid", val) == 0) {
			ctx->qs_args[key].string = strdup(val);
			if (ctx->qs_args[key].string == NULL) {
				lwarn("parse_value");
				return 500;
			}
		} else {
			lwarnx("bad OVS value %s", val);
			return 400;
		}
		break;
	}
	return 0;
}

int
parse_querystring(char *qs, struct lg_ctx *ctx)
{
	size_t len, i;
	int rv;

	while (qs && *qs) {
		len = strcspn(qs, "=");
		for (i = 0; qsargs[i].key != NULL; i++)
			if (strncmp(qsargs[i].key, qs, len) == 0)
				break;
		if (qsargs[i].key == NULL) {
			lwarnx("unknown QS key %.*s", (int)len, qs);
			return 400;
		}
		if (((1 << qsargs[i].qs) & ctx->qs_mask) == 0) {
			lwarnx("QS %s not allowed for command", qsargs[i].key);
			return 400;
		}
		if (qs[len] != '=') {
			lwarnx("QS %s without value", qsargs[i].key);
			return 400;
		}

		qs += len + 1;
		len = strcspn(qs, "&");

		if ((rv = parse_value(ctx, qsargs[i].qs, qsargs[i].type,
		    urldecode(qs, len))) != 0)
			return rv;

		qs += len;
		if (*qs == '&')
			qs++;
	}

	return 0;
}
