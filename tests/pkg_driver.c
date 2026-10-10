/* Test driver for src/pkg_reader.c.
 *   pkg_driver <pkg> [passcode|-] [random_reads]
 * Prints:  ENTRIES <n> TOTAL <bytes>
 *          D <path>                      (directories)
 *          F <path> <size> <sha256hex>   (each file read whole in odd-sized chunks)
 *          MBPS <n>                      (throughput of the whole-file pass)
 *          RANDOM <n> OK | RANDOM FAIL ...
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "crypto.h"
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

static const size_t chunks[] = {1, 4093, 65537, 4096, 7, 131071, 262144 + 13, 100003};

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    const char *pass = argc > 2 && strcmp(argv[2], "-") ? argv[2] : NULL;
    int nrand = argc > 3 ? atoi(argv[3]) : 300;
    pkgr_t *p;
    char err[256];
    if (pkgr_open(argv[1], pass, &p, err, sizeof err)) {
        printf("OPENFAIL %s\n", err);
        return 1;
    }
    size_t n = pkgr_entry_count(p);
    printf("ENTRIES %zu TOTAL %llu\n", n, (unsigned long long)pkgr_total_size(p));
    uint8_t *buf = malloc(1 << 20);
    uint8_t *buf2 = malloc(1 << 20);
    double t0 = now();
    uint64_t bytes = 0;
    size_t ci = 0;
    for (size_t i = 0; i < n; i++) {
        const pkgr_entry_t *e = pkgr_entry(p, i);
        if (e->is_dir) {
            printf("D %s\n", e->path);
            continue;
        }
        sha256_ctx c;
        sha256_init(&c);
        uint64_t off = 0;
        while (off < e->size) {
            size_t want = chunks[ci++ % (sizeof chunks / sizeof *chunks)];
            int64_t r = pkgr_read(p, i, off, buf, want);
            if (r <= 0) {
                printf("READFAIL %s at %llu (%lld)\n", e->path, (unsigned long long)off, (long long)r);
                return 1;
            }
            sha256_update(&c, buf, (size_t)r);
            off += (uint64_t)r;
        }
        uint8_t d[32];
        sha256_final(&c, d);
        printf("F %s %llu ", e->path, (unsigned long long)e->size);
        for (int k = 0; k < 32; k++) printf("%02x", d[k]);
        printf("\n");
        bytes += e->size;
    }
    double dt = now() - t0;
    printf("MBPS %.1f\n", (double)bytes / 1048576.0 / (dt > 1e-9 ? dt : 1e-9));

    /* random access: one big read vs the same range via odd-sized pieces, across block boundaries */
    int fails = 0, done = 0;
    for (int k = 0; k < nrand && n; k++) {
        size_t i = rnd() % n;
        const pkgr_entry_t *e = pkgr_entry(p, i);
        if (e->is_dir || e->size == 0) continue;
        uint64_t off;
        size_t len = 1 + rnd() % 200000;
        if (rnd() & 1) { /* straddle a 64 KiB boundary */
            uint64_t b = (rnd() % (e->size / 65536 + 1)) * 65536;
            off = b > 20 ? b - 1 - rnd() % 20 : 0;
        } else {
            off = rnd() % e->size;
        }
        uint64_t expect = off >= e->size ? 0 : (e->size - off < len ? e->size - off : len);
        int64_t r = pkgr_read(p, i, off, buf, len);
        if (r != (int64_t)expect) {
            printf("RANDOM FAIL %s off=%llu len=%zu got=%lld want=%llu\n", e->path, (unsigned long long)off, len,
                   (long long)r, (unsigned long long)expect);
            fails++;
            continue;
        }
        size_t got = 0, step = 1 + rnd() % 9000;
        while (got < expect) {
            size_t w = step < expect - got ? step : (size_t)(expect - got);
            if (pkgr_read(p, i, off + got, buf2 + got, w) != (int64_t)w) break;
            got += w;
        }
        if (got != expect || memcmp(buf, buf2, (size_t)expect)) {
            printf("RANDOM FAIL %s off=%llu len=%zu mismatch\n", e->path, (unsigned long long)off, len);
            fails++;
        }
        done++;
    }
    for (size_t i = 0; i < n; i++) {
        const pkgr_entry_t *e = pkgr_entry(p, i);
        if (!e->is_dir && (pkgr_read(p, i, e->size, buf, 10) != 0 || pkgr_read(p, i, e->size + 5, buf, 10) != 0)) {
            printf("RANDOM FAIL EOF %s\n", e->path);
            fails++;
        }
    }
    if (pkgr_read(p, n + 3, 0, buf, 1) != -1) {
        printf("RANDOM FAIL badindex\n");
        fails++;
    }
    if (fails) return 1;
    printf("RANDOM %d OK\n", done);
    pkgr_close(p);
    free(buf);
    free(buf2);
    return 0;
}
