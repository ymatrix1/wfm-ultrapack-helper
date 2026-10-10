/* Test driver for the FIH (native PS5 package) path of src/pkg_reader.c.
 *   fih_driver kraken <span.bin> <flags> <first_chunk_comp> <dstlen>   -> SHA256 <hex>
 *   fih_driver console <http://host:port> <remote .pkg path> [random_reads]
 *       opens the package through the HTTP range backend (tests/http_range.c) and prints
 *       machine-readable lines (see fih-test.js): OPEN / INFO / PARAM_* / FILE / PNG / ELF /
 *       RANDOM / MBPS / STATS. Exit 0 only if the driver's own checks passed.
 *   fih_driver local <pkg file> [random_reads]      same, for a package on a local disk. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "crypto.h"
#include "http_range.h"
#include "kraken.h"
#include "pkg_reader.h"

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}

static uint64_t rng = 0x9E3779B97F4A7C15ull;
static uint64_t rnd(void) {
    rng ^= rng << 13;
    rng ^= rng >> 7;
    rng ^= rng << 17;
    return rng;
}

static void hex(const uint8_t *b, size_t n, char *out) {
    for (size_t i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", b[i]);
    out[2 * n] = 0;
}

static int g_fail;
static const void *g_http; /* http_range ctx (console mode) */

static void print_http(const char *tag) {
    uint64_t b, r;
    if (!g_http) return;
    http_range_stats(g_http, &b, &r);
    printf("HTTP %s bytes=%llu requests=%llu\n", tag, (unsigned long long)b, (unsigned long long)r);
}

#define CHECK(cond, ...)                                      \
    do {                                                      \
        if (!(cond)) {                                        \
            printf("FAIL " __VA_ARGS__);                      \
            printf("\n");                                     \
            g_fail = 1;                                       \
        }                                                     \
    } while (0)

static int do_kraken(char **av) {
    FILE *f = fopen(av[0], "rb");
    if (!f) return 2;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *src = malloc((size_t)n);
    size_t dl = (size_t)atol(av[3]);
    uint8_t *dst = malloc(dl);
    if (!src || !dst || fread(src, 1, (size_t)n, f) != (size_t)n) return 2;
    fclose(f);
    int r = kraken_decode_block(src, (size_t)n, (int)strtol(av[1], NULL, 0), atoi(av[2]), dst, dl);
    if (r) {
        printf("FAIL kraken status %d\n", r);
        return 1;
    }
    uint8_t h[32];
    char hx[65];
    sha256(dst, dl, h);
    hex(h, 32, hx);
    printf("SHA256 %s\n", hx);
    free(src);
    free(dst);
    return 0;
}

static long find_entry(pkgr_t *p, const char *path) {
    size_t n = pkgr_entry_count(p);
    for (size_t i = 0; i < n; i++)
        if (!strcmp(pkgr_entry(p, i)->path, path)) return (long)i;
    return -1;
}

static uint32_t crc_table[256];
static uint32_t crc32_buf(const uint8_t *b, size_t n) {
    uint32_t c = 0xFFFFFFFFu;
    if (!crc_table[1])
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t v = i;
            for (int k = 0; k < 8; k++) v = v & 1 ? 0xEDB88320u ^ (v >> 1) : v >> 1;
            crc_table[i] = v;
        }
    for (size_t i = 0; i < n; i++) c = crc_table[(c ^ b[i]) & 0xFF] ^ (c >> 8);
    return ~c;
}

static uint32_t rbe32(const uint8_t *p) { return (uint32_t)p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3]; }

/* reads a whole file in 256 KiB chunks (the converter's access pattern); caller frees *out */
static int read_whole(pkgr_t *p, const char *path, uint8_t **out, uint64_t *size, double *secs) {
    long i = find_entry(p, path);
    if (i < 0) {
        printf("FAIL missing %s\n", path);
        return -1;
    }
    uint64_t sz = pkgr_entry(p, (size_t)i)->size;
    uint8_t *b = malloc(sz ? (size_t)sz : 1);
    if (!b) return -1;
    double t0 = now();
    for (uint64_t pos = 0; pos < sz;) {
        size_t k = sz - pos < 262144 ? (size_t)(sz - pos) : 262144;
        int64_t r = pkgr_read(p, (size_t)i, pos, b + pos, k);
        if (r != (int64_t)k) {
            printf("FAIL read %s at %llu -> %lld\n", path, (unsigned long long)pos, (long long)r);
            free(b);
            return -1;
        }
        pos += k;
    }
    *secs = now() - t0;
    *out = b;
    *size = sz;
    return 0;
}

static void random_reads(pkgr_t *p, const char *path, const uint8_t *truth, uint64_t sz, int n, int *okc) {
    static const size_t odd[] = {4093, 70001, 262144 + 13, 1, 131071, 65537};
    long i = find_entry(p, path);
    uint8_t *a = malloc(700000), *b = malloc(700000);
    if (i < 0 || !a || !b) {
        g_fail = 1;
        return;
    }
    for (int r = 0; r < n; r++) {
        uint64_t off = rnd() % sz;
        size_t len = 1 + (size_t)(rnd() % 600000);
        if (len > sz - off) len = (size_t)(sz - off);
        if (pkgr_read(p, (size_t)i, off, a, len) != (int64_t)len) {
            printf("FAIL random read %s off=%llu len=%zu\n", path, (unsigned long long)off, len);
            g_fail = 1;
            break;
        }
        size_t step = odd[rnd() % 6], got = 0;
        while (got < len) {
            size_t k = len - got < step ? len - got : step;
            if (pkgr_read(p, (size_t)i, off + got, b + got, k) != (int64_t)k) break;
            got += k;
        }
        if (got != len || memcmp(a, b, len) || memcmp(a, truth + off, len)) {
            printf("FAIL random mismatch %s off=%llu len=%zu step=%zu\n", path, (unsigned long long)off, len, step);
            g_fail = 1;
            break;
        }
        (*okc)++;
    }
    free(a);
    free(b);
}

static int do_open(const char *label, pkgr_io_t *io, const char *local, int nrand) {
    pkgr_t *p = NULL;
    char err[256];
    double t0 = now();
    int rc = io ? pkgr_open_io(io, &p, err, sizeof err) : pkgr_open(local, NULL, &p, err, sizeof err);
    if (rc) {
        printf("FAIL open: %s\n", err);
        return 1;
    }
    double topen = now() - t0;
    (void)label;
    printf("OPEN_MS %.0f\n", topen * 1000);
    pkgr_info_t info;
    pkgr_info(p, &info);
    size_t ne = pkgr_entry_count(p), nd = 0, nf = 0;
    for (size_t i = 0; i < ne; i++) {
        if (pkgr_entry(p, i)->is_dir) nd++;
        else nf++;
    }
    printf("INFO format=%s content_id=%s entries=%zu files=%zu dirs=%zu total=%llu image=%llu spans=%llu\n", info.format,
           info.content_id, ne, nf, nd, (unsigned long long)pkgr_total_size(p), (unsigned long long)info.image_size,
           (unsigned long long)info.spans);

    /* parents must precede children */
    for (size_t i = 0; i < ne && !g_fail; i++) {
        const char *s = pkgr_entry(p, i)->path, *sl = strrchr(s, '/');
        if (!sl) continue;
        char *par = strndup(s, (size_t)(sl - s));
        long pi = par ? find_entry(p, par) : -1;
        if (pi < 0 || (size_t)pi >= i) printf("FAIL parent order for %s\n", s), g_fail = 1;
        free(par);
        if (i > 3000) break; /* find_entry is linear: spot check the first entries only */
    }

    long pj = find_entry(p, "sce_sys/param.json");
    if (pj < 0) {
        printf("FAIL no sce_sys/param.json\n");
        g_fail = 1;
    } else {
        uint64_t sz = pkgr_entry(p, (size_t)pj)->size;
        uint8_t *b = malloc((size_t)sz + 1);
        if (b && pkgr_read(p, (size_t)pj, 0, b, (size_t)sz) == (int64_t)sz) {
            char *hx = malloc(2 * (size_t)sz + 1);
            hex(b, (size_t)sz, hx);
            printf("PARAM_HEX %s\n", hx);
            free(hx);
        } else {
            printf("FAIL read param.json\n");
            g_fail = 1;
        }
        free(b);
    }

    static const char *files[] = {"watermark_img.png", "contents/0/0/6J2QN", "contents/0/0/6VFRJ", "eboot.bin"};
    uint8_t *keep[4] = {0};
    uint64_t keepsz[4] = {0};
    double dec_secs = 0;
    uint64_t dec_bytes = 0;
    for (int k = 0; k < 4; k++) {
        double secs;
        if (read_whole(p, files[k], &keep[k], &keepsz[k], &secs)) {
            g_fail = 1;
            continue;
        }
        uint8_t h[32];
        char hx[65];
        sha256(keep[k], (size_t)keepsz[k], h);
        hex(h, 32, hx);
        printf("FILE %s %llu %s %.2f\n", files[k], (unsigned long long)keepsz[k], hx, secs);
        if (k == 3) {
            dec_secs = secs;
            dec_bytes = keepsz[k];
        }
    }
    if (keep[0]) { /* PNG: signature + every chunk CRC */
        const uint8_t *d = keep[0];
        uint64_t n = keepsz[0], pos = 8;
        int good = n > 8 && !memcmp(d, "\x89PNG\r\n\x1a\n", 8);
        while (good && pos + 12 <= n) {
            uint32_t ln = rbe32(d + pos);
            if (pos + 12 + ln > n || crc32_buf(d + pos + 4, 4 + (size_t)ln) != rbe32(d + pos + 8 + ln)) good = 0;
            pos += 12 + ln;
        }
        printf("PNG %s\n", good && pos == n ? "OK" : "FAIL");
        if (!(good && pos == n)) g_fail = 1;
    }
    if (keep[3]) {
        const uint8_t *d = keep[3];
        int self = !memcmp(d, "\x54\x14\xf5\xee", 4);
        int elf = keepsz[3] > 0x1a5 && !memcmp(d + 0x1a0, "\x7f" "ELF", 4) && d[0x1a4] == 2;
        printf("ELF self=%d elf64=%d\n", self, elf);
        if (!self || !elf) g_fail = 1;
        printf("MBPS %.1f\n", (double)dec_bytes / 1e6 / (dec_secs > 0 ? dec_secs : 1));
    }
    int okc = 0;
    if (keep[3]) random_reads(p, files[3], keep[3], keepsz[3], nrand, &okc);
    if (keep[2]) random_reads(p, files[2], keep[2], keepsz[2], nrand / 4 + 1, &okc);
    printf("RANDOM %d %s\n", okc, g_fail ? "FAIL" : "OK");
    pkgr_info(p, &info);
    printf("STATS stored=%llu zero=%llu kraken=%llu\n", (unsigned long long)info.spans_stored,
           (unsigned long long)info.spans_zero, (unsigned long long)info.spans_kraken);
    for (int k = 0; k < 4; k++) free(keep[k]);
    print_http("total");
    pkgr_close(p);
    return g_fail;
}

int main(int argc, char **argv) {
    if (argc < 3) return 2;
    crypto_init();
    if (!strcmp(argv[1], "kraken") && argc >= 6) return do_kraken(argv + 2);
    if (!strcmp(argv[1], "local")) return do_open("local", NULL, argv[2], argc > 3 ? atoi(argv[3]) : 200);
    if (!strcmp(argv[1], "console") && argc >= 4) {
        pkgr_io_t io;
        char err[256];
        if (http_range_open(argv[2], argv[3], &io, err, sizeof err)) {
            printf("UNREACHABLE %s\n", err);
            return 3;
        }
        g_http = io.ctx;
        return do_open("console", &io, NULL, argc > 4 ? atoi(argv[4]) : 200);
    }
    return 2;
}
