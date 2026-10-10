/* Test-only pkgr_io_t backend: random reads of a remote file through HTTP "GET ... Range:" on the
 * PS5 console web file manager (http://host:port/fs?path=<urlencoded>). Only GET requests are
 * ever sent. Plain TCP, keep-alive with reconnect + retry, small aligned-chunk LRU cache. */
#ifndef WUP_HTTP_RANGE_H
#define WUP_HTTP_RANGE_H

#include "pkg_reader.h"

/* base_url "http://host:port". Probes the size with a one-byte range GET. 0 on success. */
int http_range_open(const char *base_url, const char *remote_path, pkgr_io_t *io, char *err, size_t errlen);
/* Statistics of an io returned by http_range_open (ctx = io->ctx). */
void http_range_stats(const void *ctx, uint64_t *bytes, uint64_t *requests);

#endif
