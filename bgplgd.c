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

#include <sys/queue.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "bgplgd.h"
#include "slowcgi.h"
#include "http.h"

#define NCMDARGS	4

const struct cmd {
	const char	*path;
	char		*args[NCMDARGS];
	unsigned int	qs_mask;
	int		barenbr;
} cmds[] = {
	{ "/summary", { "show", NULL }, 0 },
	{ "/nexthops", { "show", "nexthop", NULL }, 0 },
	{ "/neighbors", { "show", "neighbor", NULL }, QS_MASK_NEIGHBOR, 1 },
	{ "/rib", { "show", "rib", "detail", NULL }, QS_MASK_RIB },
	{ "/memory", { "show", "rib", "memory", NULL }, 0 },
	{ "/interfaces", { "show", "interfaces", NULL }, 0 },
	{ "/rtr", { "show", "rtr", NULL }, 0 },
	{ "/sets", { "show", "sets", NULL }, 0 },
	{ NULL }
};

static const char *
http_error(int *res)
{
	const struct http_error errors[] = HTTP_ERRORS;
	size_t i;

	for (i = 0; errors[i].error_code != 0; i++)
		if (errors[i].error_code == *res)
			return errors[i].error_name;

	/* unknown error - change to 500 */
	lwarnx("unknown http error %d", *res);
	*res = 500;
	return "Internal Server Error";
}

static void
error_response(int res)
{
	const char *type = "text/html";
	const char *errstr = http_error(&res);

	lwarnx("HTTP status %d: %s", res, errstr);

	printf(
	    "Content-Type: %s\n"
	    "Status: %d\n"
	    "Cache-Control: no-cache\n"
	    "\n"
	    "<!DOCTYPE html>\n"
	    "<html>\n"
	    " <head>\n"
	    "  <meta http-equiv=\"Content-Type\" "
	    "content=\"%s; charset=utf-8\"/>\n"
	    "  <title>%d %s</title>\n"
	    " </head>\n"
	    " <body>\n"
	    "  <h1>%d %s</h1>\n"
	    "  <hr>\n"
	    "  <address>OpenBSD bgplgd</address>\n"
	    " </body>\n"
	    "</html>\n",
	    type, res, type, res, errstr, res, errstr);

	exit(0);
}

static int
command_from_path(const char *path, struct lg_ctx *ctx)
{
	size_t i;

	for (i = 0; cmds[i].path != NULL; i++) {
		if (strcmp(cmds[i].path, path) == 0) {
			ctx->command = &cmds[i];
			ctx->qs_mask = cmds[i].qs_mask;
			return 0;
		}
	}
	return 404;
}

static int
prep_request(struct lg_ctx *ctx, const char *meth, const char *path,
    const char *qs)
{
	if (meth == NULL || path == NULL)
		return 500;
	if (strcmp(meth, "GET") != 0)
		return 405;

	if (command_from_path(path, ctx) != 0)
		return 404;

	if (parse_querystring(qs, ctx) != 0)
		return 400;

	return 0;
}


/*
 * Entry point from the FastCGI handler.
 * This runs as an own process and can use STDOUT and STDERR.
 */
void
call(const char *method, const char *pathinfo, const char *querystring)
{
	struct lg_ctx ctx;
	char *argv[64];
	size_t i, argc = 0;
	int res;

	memset(&ctx, 0, sizeof(ctx));
	if ((res = prep_request(&ctx, method, pathinfo, querystring)) != 0)
		error_response(res);

	argv[argc++] = bgpctlpath;
	argv[argc++] = "-j";
	argv[argc++] = "-s";
	argv[argc++] = "/var/www/run/bgpd.rsock";

	for (i = 0; ctx.command->args[i] != NULL; i++)
		argv[argc++] = ctx.command->args[i];

	argc = qs_argv(argv, argc, sizeof(argv) / sizeof(argv[0]), &ctx,
	    ctx.command->barenbr);

	argv[argc++] = NULL;

	for (i = 0; argv[i] != NULL; i++)
		ldebug("argv[%zu], %s", i, argv[i]);


	signal(SIGPIPE, SIG_DFL);

	/* Write server header first */
	printf("Content-type: application/json\r\n\r\n");
	fflush(stdout);

	execvp(bgpctlpath, argv);

	lerr(1, "failed to execute bgpctl");
}
