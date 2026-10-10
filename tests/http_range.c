/* See http_range.h. Test-only; never built into the daemon. */
#define _POSIX_C_SOURCE 200809L
#include "http_range.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET sock_t;
#define SOCK_BAD INVALID_SOCKET
#define sock_close closesocket
#else
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
typedef int sock_t;
#define SOCK_BAD (-1)
#define sock_close close
#endif

#define CHUNK (1u << 20)
#define NCHUNK 16
#define MAX_REQ (8u << 20)

typedef struct {
    int64_t idx;
    uint64_t tick;
    uint8_t *buf;
    size_t len;
} chunk_t;

typedef struct {
    char host[128], port[16], target[2048];
    uint64_t size;
    sock_t s;
    uint8_t rb[4096]; /* socket read buffer */
    size_t rpos, rlen;
    chunk_t ch[NCHUNK];
    uint64_t tick, bytes, requests;
} http_t;

static void net_init(void) {
#ifdef _WIN32
    static int done;
    if (!done) {
        WSADATA w;
        WSAStartup(MAKEWORD(2, 2), &w);
        done = 1;
    }
#endif
}

static void h_disconnect(http_t *h) {
    if (h->s != SOCK_BAD) sock_close(h->s);
    h->s = SOCK_BAD;
    h->rpos = h->rlen = 0;
}

static int h_connect(http_t *h) {
    struct addrinfo hints, *res = NULL, *a;
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    if (getaddrinfo(h->host, h->port, &hints, &res)) return -1;
    for (a = res; a; a = a->ai_next) {
        sock_t s = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (s == SOCK_BAD) continue;
#ifndef _WIN32
        struct timeval tv = {30, 0};
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
#endif
        if (!connect(s, a->ai_addr, (int)a->ai_addrlen)) {
            h->s = s;
            freeaddrinfo(res);
            return 0;
        }
        sock_close(s);
    }
    freeaddrinfo(res);
    return -1;
}

static int h_send(http_t *h, const char *b, size_t n) {
    while (n) {
        int r = (int)send(h->s, b, (int)n, 0);
        if (r <= 0) return -1;
        b += r;
        n -= (size_t)r;
    }
    return 0;
}

/* buffered read of 1..n bytes; -1 on error/EOF */
static int h_recv(http_t *h, uint8_t *dst, size_t n) {
    if (h->rpos == h->rlen) {
        if (n >= sizeof h->rb) { /* large body read straight into the caller's buffer */
            int r = (int)recv(h->s, (char *)dst, (int)(n > (1u << 20) ? (1u << 20) : n), 0);
            return r <= 0 ? -1 : r;
        }
        int r = (int)recv(h->s, (char *)h->rb, (int)sizeof h->rb, 0);
        if (r <= 0) return -1;
        h->rpos = 0;
        h->rlen = (size_t)r;
    }
    size_t k = h->rlen - h->rpos < n ? h->rlen - h->rpos : n;
    memcpy(dst, h->rb + h->rpos, k);
    h->rpos += k;
    return (int)k;
}

/* One GET with Range a..b (inclusive) into buf (cap >= b-a+1). Sets *total from Content-Range. */
static int h_get_once(http_t *h, uint64_t a, uint64_t b, uint8_t *buf, uint64_t *total) {
    char req[2600];
    if (h->s == SOCK_BAD && h_connect(h)) return -1;
    int rl = snprintf(req, sizeof req,
                      "GET %s HTTP/1.1\r\nHost: %s:%s\r\nRange: bytes=%llu-%llu\r\nConnection: keep-alive\r\n\r\n",
                      h->target, h->host, h->port, (unsigned long long)a, (unsigned long long)b);
    if (rl <= 0 || (size_t)rl >= sizeof req || h_send(h, req, (size_t)rl)) return -1;
    char line[512];
    size_t ll = 0;
    int status = 0, first = 1, close_after = 0;
    long long clen = -1, cr_total = -1, cr_a = -1, cr_b = -1;
    for (;;) {
        uint8_t c;
        if (h_recv(h, &c, 1) != 1) return -1;
        if (c != '\n') {
            if (ll < sizeof line - 1 && c != '\r') line[ll++] = (char)c;
            continue;
        }
        line[ll] = 0;
        if (ll == 0 && !first) break;
        if (first) {
            if (sscanf(line, "HTTP/%*d.%*d %d", &status) != 1) return -1;
            first = 0;
        } else {
            for (char *q = line; *q && *q != ':'; q++) *q = (char)tolower((unsigned char)*q);
            if (!strncmp(line, "content-length:", 15)) clen = atoll(line + 15);
            else if (!strncmp(line, "content-range:", 14))
                sscanf(line + 14, " bytes %lld-%lld/%lld", &cr_a, &cr_b, &cr_total);
            else if (!strncmp(line, "connection:", 11) && strstr(line + 11, "close")) close_after = 1;
            else if (!strncmp(line, "transfer-encoding:", 18)) return -1; /* chunked is not supported */
        }
        ll = 0;
    }
    if (status != 206 || clen < 0 || cr_a != (long long)a || cr_total < 0 || clen != cr_b - cr_a + 1 ||
        (uint64_t)clen != b - a + 1)
        return -1;
    size_t got = 0;
    while (got < (size_t)clen) {
        int r = h_recv(h, buf + got, (size_t)clen - got);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    if (close_after) h_disconnect(h);
    if (total) *total = (uint64_t)cr_total;
    h->bytes += got;
    h->requests++;
    return 0;
}

static int h_get(http_t *h, uint64_t a, uint64_t b, uint8_t *buf, uint64_t *total) {
    for (int t = 0; t < 4; t++) {
        if (!h_get_once(h, a, b, buf, total)) return 0;
        h_disconnect(h); /* retry on a fresh connection */
    }
    return -1;
}

static int http_pread(void *ctx, uint64_t off, void *buf, size_t n) {
    http_t *h = ctx;
    uint8_t *out = buf;
    if (off > h->size || n > h->size - off) return -1;
    while (n) {
        if (n >= CHUNK) { /* big read: straight into the caller's buffer, no caching */
            size_t k = n > MAX_REQ ? MAX_REQ : n;
            if (h_get(h, off, off + k - 1, out, NULL)) return -1;
            out += k;
            off += k;
            n -= k;
            continue;
        }
        int64_t ci = (int64_t)(off / CHUNK);
        chunk_t *c = NULL;
        for (int i = 0; i < NCHUNK; i++)
            if (h->ch[i].idx == ci) {
                c = &h->ch[i];
                break;
            }
        if (!c) {
            chunk_t *victim = &h->ch[0];
            for (int i = 0; i < NCHUNK; i++) { /* empty slot first, else least recently used */
                if (h->ch[i].idx < 0) {
                    victim = &h->ch[i];
                    break;
                }
                if (h->ch[i].tick < victim->tick) victim = &h->ch[i];
            }
            uint64_t a = (uint64_t)ci * CHUNK, b = a + CHUNK - 1;
            if (b >= h->size) b = h->size - 1;
            if (!victim->buf && !(victim->buf = malloc(CHUNK))) return -1;
            victim->idx = -1;
            if (h_get(h, a, b, victim->buf, NULL)) return -1;
            victim->idx = ci;
            victim->len = (size_t)(b - a + 1);
            c = victim;
        }
        c->tick = ++h->tick;
        size_t o = (size_t)(off - (uint64_t)ci * CHUNK);
        if (o >= c->len) return -1;
        size_t k = c->len - o < n ? c->len - o : n;
        memcpy(out, c->buf + o, k);
        out += k;
        off += k;
        n -= k;
    }
    return 0;
}

static void http_close(void *ctx) {
    http_t *h = ctx;
    h_disconnect(h);
    for (int i = 0; i < NCHUNK; i++) free(h->ch[i].buf);
    free(h);
}

void http_range_stats(const void *ctx, uint64_t *bytes, uint64_t *requests) {
    const http_t *h = ctx;
    *bytes = h->bytes;
    *requests = h->requests;
}

static int open_fail(http_t *h, char *err, size_t errlen, const char *msg) {
    snprintf(err, errlen, "%s", msg);
    free(h);
    return -1;
}

int http_range_open(const char *base_url, const char *remote_path, pkgr_io_t *io, char *err, size_t errlen) {
    http_t *h = calloc(1, sizeof *h);
    if (!h) return -1;
    h->s = SOCK_BAD;
    for (int i = 0; i < NCHUNK; i++) h->ch[i].idx = -1;
    net_init();
    if (strncmp(base_url, "http://", 7)) return open_fail(h, err, errlen, "only http:// URLs are supported");
    const char *hp = base_url + 7;
    const char *colon = strchr(hp, ':'), *slash = strchr(hp, '/');
    size_t hl = colon ? (size_t)(colon - hp) : slash ? (size_t)(slash - hp) : strlen(hp);
    if (hl == 0 || hl >= sizeof h->host) return open_fail(h, err, errlen, "bad host");
    memcpy(h->host, hp, hl);
    if (colon) {
        size_t pl = (slash ? (size_t)(slash - colon) : strlen(colon)) - 1;
        if (pl == 0 || pl >= sizeof h->port) return open_fail(h, err, errlen, "bad port");
        memcpy(h->port, colon + 1, pl);
    } else {
        strcpy(h->port, "80");
    }
    size_t t = (size_t)snprintf(h->target, sizeof h->target, "/fs?path=");
    for (const unsigned char *q = (const unsigned char *)remote_path; *q; q++) {
        if (t + 4 >= sizeof h->target) return open_fail(h, err, errlen, "path too long");
        if (isalnum(*q) || *q == '-' || *q == '_' || *q == '.' || *q == '~') h->target[t++] = (char)*q;
        else t += (size_t)snprintf(h->target + t, 4, "%%%02X", *q);
    }
    h->target[t] = 0;
    uint8_t b0;
    uint64_t total = 0;
    if (h_get(h, 0, 0, &b0, &total) || total == 0) {
        snprintf(err, errlen, "cannot reach %s (range probe failed)", base_url);
        http_close(h);
        return -1;
    }
    h->size = total;
    io->pread = http_pread;
    io->close = http_close;
    io->ctx = h;
    io->size = total;
    return 0;
}
