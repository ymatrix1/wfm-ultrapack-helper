/* Test driver for src/crypto.c. Reads commands from stdin, one per line, with
 * hex arguments ("-" = empty), writes hex results (or ERR) to stdout:
 *   sha256 <msg>
 *   hmac <key> <msg>
 *   aesenc <key16> <block16>      aesdec <key16> <block16>
 *   xtsdec|xtsenc <k1> <k2> <sector-decimal> <sector_size> <data>
 *   bench                         (64 MiB XTS decrypt, prints "MBPS <n>")
 *   threads                       (concurrent first-use AES vector check)
 */
#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "crypto.h"

#define THREAD_COUNT 32
static pthread_barrier_t start_barrier;

static void *thread_aes(void *arg) {
    static const uint8_t key[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    static const uint8_t plain[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    static const uint8_t cipher[16] = {
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
        0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
    aes128_ctx ctx;
    uint8_t out[16];
    int *failed = arg;
    pthread_barrier_wait(&start_barrier);
    /* Mix explicit initialization and lazy initialization through key setup. */
    if (*failed) crypto_init();
    *failed = 0;
    aes128_set_key(&ctx, key);
    aes128_encrypt_block(&ctx, plain, out);
    if (memcmp(out, cipher, sizeof out)) *failed = 1;
    aes128_decrypt_block(&ctx, cipher, out);
    if (memcmp(out, plain, sizeof out)) *failed = 1;
    return NULL;
}

static void threads(void) {
    pthread_t tids[THREAD_COUNT];
    int failed[THREAD_COUNT], result = 0;
    if (pthread_barrier_init(&start_barrier, NULL, THREAD_COUNT)) exit(2);
    for (int i = 0; i < THREAD_COUNT; i++) {
        failed[i] = i & 1;
        if (pthread_create(&tids[i], NULL, thread_aes, &failed[i])) exit(2);
    }
    for (int i = 0; i < THREAD_COUNT; i++) {
        if (pthread_join(tids[i], NULL)) exit(2);
        result |= failed[i];
    }
    pthread_barrier_destroy(&start_barrier);
    puts(result ? "ERR" : "OK");
}

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static uint8_t *unhex(const char *s, size_t *len) {
    size_t n = strcmp(s, "-") == 0 ? 0 : strlen(s), i;
    uint8_t *b = malloc(n / 2 + 1);
    if (!b) exit(2);
    for (i = 0; i + 1 < n + 1 && 2 * i < n; i++) b[i] = (uint8_t)((hexval(s[2 * i]) << 4) | hexval(s[2 * i + 1]));
    *len = n / 2;
    return b;
}

static void puthex(const uint8_t *b, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

static void bench(void) {
    size_t len = 64u << 20, i;
    uint8_t *buf = malloc(len), k1[16], k2[16];
    struct timespec a, b;
    double sec;
    if (!buf) exit(2);
    for (i = 0; i < len; i++) buf[i] = (uint8_t)(i * 31 + (i >> 8));
    for (i = 0; i < 16; i++) { k1[i] = (uint8_t)(i + 1); k2[i] = (uint8_t)(0xa0 + i); }
    clock_gettime(CLOCK_MONOTONIC, &a);
    if (aes_xts_decrypt(k1, k2, 0, 0x1000, buf, buf, len) != 0) { printf("ERR\n"); exit(1); }
    clock_gettime(CLOCK_MONOTONIC, &b);
    sec = (double)(b.tv_sec - a.tv_sec) + (double)(b.tv_nsec - a.tv_nsec) / 1e9;
    printf("MBPS %.1f\n", 64.0 / sec);
    free(buf);
}

int main(void) {
    char *line = NULL, *tok[8];
    size_t cap = 0;
    ssize_t got;
    while ((got = getline(&line, &cap, stdin)) >= 0) {
        int nt = 0;
        char *p = strtok(line, " \r\n");
        size_t l0, l1, l2, l3;
        uint8_t *a, *b, *c, *o;
        while (p && nt < 8) { tok[nt++] = p; p = strtok(NULL, " \r\n"); }
        if (nt == 0) continue;
        if (!strcmp(tok[0], "sha256") && nt == 2) {
            uint8_t out[32];
            a = unhex(tok[1], &l0);
            sha256(a, l0, out); puthex(out, 32); free(a);
        } else if (!strcmp(tok[0], "hmac") && nt == 3) {
            uint8_t out[32];
            a = unhex(tok[1], &l0); b = unhex(tok[2], &l1);
            hmac_sha256(a, l0, b, l1, out); puthex(out, 32); free(a); free(b);
        } else if ((!strcmp(tok[0], "aesenc") || !strcmp(tok[0], "aesdec")) && nt == 3) {
            aes128_ctx cx;
            uint8_t out[16];
            a = unhex(tok[1], &l0); b = unhex(tok[2], &l1);
            aes128_set_key(&cx, a);
            if (tok[0][3] == 'e') aes128_encrypt_block(&cx, b, out);
            else aes128_decrypt_block(&cx, b, out);
            puthex(out, 16); free(a); free(b);
        } else if ((!strcmp(tok[0], "xtsdec") || !strcmp(tok[0], "xtsenc")) && nt == 6) {
            int rc;
            a = unhex(tok[1], &l0); b = unhex(tok[2], &l1); c = unhex(tok[5], &l3);
            l2 = (size_t)strtoull(tok[4], NULL, 10);
            o = malloc(l3 + 1);
            if (!o) exit(2);
            if (tok[0][3] == 'd') rc = aes_xts_decrypt(a, b, strtoull(tok[3], NULL, 10), l2, c, o, l3);
            else rc = aes_xts_encrypt(a, b, strtoull(tok[3], NULL, 10), l2, c, o, l3);
            if (rc) printf("ERR\n"); else if (l3) puthex(o, l3); else printf("\n");
            free(a); free(b); free(c); free(o);
        } else if (!strcmp(tok[0], "threads")) {
            threads();
        } else if (!strcmp(tok[0], "bench")) {
            bench();
        } else {
            printf("BADCMD\n");
        }
        fflush(stdout);
    }
    free(line);
    return 0;
}
