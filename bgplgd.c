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
#include <stdio.h>
#include <string.h>

#include "bgplgd.h"
#include "slowcgi.h"
#include "http.h"

const struct cmd {
	const char	*path;
	const char	*args[4];
	unsigned int	qs_mask;
} cmds[] = {
	{ "/summary", { "show", NULL }, 0 },
	{ "/nexthops", { "show", "nexthop", NULL }, 0 },
	{ "/neighbors", { "show", "neighbor", NULL }, QS_MASK_NEIGHBOR },
	{ "/rib", { "show", "rib", "detail", NULL }, QS_MASK_RIB },
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
error_response(struct request *c, int res)
{
	const char *type = "text/html";
	const char *errstr = http_error(&res);
	char buf[1024];

	snprintf(buf, sizeof(buf),
	    "Content-Type: %s\n"
	    "Status: %d\n"
	    "Cache-Control: no-cache\n"
	    "\n"
	    "<!DOCTYPE html>\n"
	    "<html>\n"
	    " <head>\n"
	    "  <meta http-equiv=\"Content-Type\" "
	    "content=\"%s; charset=utf-8\"/>\n"
	    "  <title>404 Not Found</title>\n"
	    " </head>\n"
	    " <body>\n"
	    "  <h1>%d %s</h1>\n"
	    "  <hr>\n"
	    "  <address>OpenBSD bgplgd</address>\n"
	    " </body>\n"
	    "</html>\n",
	    type, res, type, res, errstr);

	create_data_record(c, FCGI_STDOUT, buf, strlen(buf));
	create_end_record(c);
}

static int
command_from_path(char *path, struct lg_ctx *ctx)
{
	size_t i;

	for (i = 0; cmds[i].path != NULL; i++) {
		if (strcmp(cmds[i].path, path) == 0) {
			ctx->command = i;
			ctx->qs_mask = cmds[i].qs_mask;
			return 0;
		}
	}
	return 404;
}

static int
prep_request(struct request *c, struct lg_ctx *ctx)
{
	char *meth, *path, *qs;

	meth = env_get(c, "REQUEST_METHOD");
	path = env_get(c, "PATH_INFO");
	qs = env_get(c, "QUERY_STRING");
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

static void
do_bgpctl(struct request *c, struct lg_ctx *ctx)
{
	char buf[128];
	const char data[] =
	    "Content-type: text/html\r\n\r\n<html><head></head><body>here we need stuff<br>\r\n";
	const char end[] = "</body></html>";

	ldebug("here we need stuff");
	create_data_record(c, FCGI_STDOUT, data, sizeof(data) - 1);

	snprintf(buf, sizeof(buf), "%s=%s<br>\r\n",
	     "PATH_INFO", env_get(c, "PATH_INFO"));
	create_data_record(c, FCGI_STDOUT, buf, strlen(buf));
	snprintf(buf, sizeof(buf), "%s=%s<br>\r\n",
	    "QUERY_STRING", env_get(c, "QUERY_STRING"));
	create_data_record(c, FCGI_STDOUT, buf, strlen(buf));
	snprintf(buf, sizeof(buf), "%s=%s<br>\r\n",
	    "SERVER_NAME", env_get(c, "SERVER_NAME"));
	create_data_record(c, FCGI_STDOUT, buf, strlen(buf));
	snprintf(buf, sizeof(buf), "%s=%s<br>\r\n",
	    "REQUEST_METHOD", env_get(c, "REQUEST_METHOD"));
	create_data_record(c, FCGI_STDOUT, buf, strlen(buf));
	create_data_record(c, FCGI_STDOUT, end, sizeof(end) - 1);

	create_end_record(c);
}

/*
 * Fork a new CGI process to handle the request, translating
 * between FastCGI parameter records and CGI's environment variables,
 * as well as between the CGI process' stdin/stdout and the
 * corresponding FastCGI records.
 */
void
exec_cgi(struct request *c)
{
	struct lg_ctx ctx;
	int res;

	memset(&ctx, 0, sizeof(ctx));
	if ((res = prep_request(c, &ctx)) != 0) {
		error_response(c, res);
		return;
	}
	do_bgpctl(c, &ctx);
	return;
}

