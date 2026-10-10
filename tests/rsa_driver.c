/* Test driver for src/rsa.c and the SHA-1 / AES-CBC parts of src/crypto.c.
 * Reads commands from stdin, one per line, hex arguments ("-" = empty),
 * writes hex results (or ERR) to stdout:
 *   sha1 <msg>
 *   sha1chunks <chunk> <msg>        (streaming API with fixed chunk size)
 *   cbcdec|cbcenc <key16> <iv16> <data>
 *   rsapriv <n> <p> <q> <dp> <dq> <qinv> <in256>
 *   rsapkcs1|rsaoaep <n> <p> <q> <dp> <dq> <qinv> <in256>   (private op + unpad)
 *   unpkcs1|unoaep <em256>
 *   bench <n> <p> <q> <dp> <dq> <qinv> <in256>   (prints "MS <ms per op>")
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "crypto.h"
#include "rsa.h"

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
    for (i = 0; 2 * i < n; i++) b[i] = (uint8_t)((hexval(s[2 * i]) << 4) | hexval(s[2 * i + 1]));
    *len = n / 2;
    return b;
}

static void puthex(const uint8_t *b, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

/* tok[first..first+5] = n p q dp dq qinv; returns 0 on success */
static int load_key(char **tok, int first, rsa2048_key_t *k) {
    size_t l;
    uint8_t *a;
    a = unhex(tok[first], &l); if (l != 256) return -1; memcpy(k->n, a, 256); free(a);
    a = unhex(tok[first + 1], &l); if (l != 128) return -1; memcpy(k->p, a, 128); free(a);
    a = unhex(tok[first + 2], &l); if (l != 128) return -1; memcpy(k->q, a, 128); free(a);
    a = unhex(tok[first + 3], &l); if (l != 128) return -1; memcpy(k->dp, a, 128); free(a);
    a = unhex(tok[first + 4], &l); if (l != 128) return -1; memcpy(k->dq, a, 128); free(a);
    a = unhex(tok[first + 5], &l); if (l != 128) return -1; memcpy(k->qinv, a, 128); free(a);
    return 0;
}

int main(void) {
    char *line = NULL, *tok[10];
    size_t cap = 0;
    ssize_t got;
    while ((got = getline(&line, &cap, stdin)) >= 0) {
        int nt = 0;
        char *p = strtok(line, " \r\n");
        size_t l0, l1, l2;
        uint8_t *a, *b, *c, *o;
        while (p && nt < 10) { tok[nt++] = p; p = strtok(NULL, " \r\n"); }
        if (nt == 0) continue;
        if (!strcmp(tok[0], "sha1") && nt == 2) {
            uint8_t out[20];
            a = unhex(tok[1], &l0);
            sha1(a, l0, out); puthex(out, 20); free(a);
        } else if (!strcmp(tok[0], "sha1chunks") && nt == 3) {
            uint8_t out[20];
            sha1_ctx cx;
            size_t step = (size_t)strtoull(tok[1], NULL, 10), off;
            a = unhex(tok[2], &l0);
            sha1_init(&cx);
            for (off = 0; off < l0; off += step) sha1_update(&cx, a + off, l0 - off < step ? l0 - off : step);
            sha1_final(&cx, out); puthex(out, 20); free(a);
        } else if ((!strcmp(tok[0], "cbcdec") || !strcmp(tok[0], "cbcenc")) && nt == 4) {
            int rc;
            a = unhex(tok[1], &l0); b = unhex(tok[2], &l1); c = unhex(tok[3], &l2);
            o = malloc(l2 + 1);
            if (!o) exit(2);
            if (tok[0][3] == 'd') rc = aes128_cbc_decrypt(a, b, c, o, l2);
            else rc = aes128_cbc_encrypt(a, b, c, o, l2);
            if (rc) printf("ERR\n"); else if (l2) puthex(o, l2); else printf("\n");
            free(a); free(b); free(c); free(o);
        } else if (!strcmp(tok[0], "rsapriv") && nt == 8) {
            rsa2048_key_t k;
            uint8_t out[256];
            a = unhex(tok[7], &l0);
            if (load_key(tok, 1, &k) || l0 != 256 || rsa2048_private_op(&k, a, out)) printf("ERR\n");
            else puthex(out, 256);
            free(a);
        } else if ((!strcmp(tok[0], "rsapkcs1") || !strcmp(tok[0], "rsaoaep")) && nt == 8) {
            rsa2048_key_t k;
            uint8_t em[256], msg[256];
            size_t ml = 0;
            int rc;
            a = unhex(tok[7], &l0);
            if (load_key(tok, 1, &k) || l0 != 256 || rsa2048_private_op(&k, a, em)) rc = -1;
            else if (tok[0][3] == 'p') rc = rsa_unpad_pkcs1_v15(em, msg, &ml);
            else rc = rsa_unpad_oaep_sha1(em, msg, &ml);
            if (rc) printf("ERR\n"); else if (ml) puthex(msg, ml); else printf("\n");
            free(a);
        } else if ((!strcmp(tok[0], "unpkcs1") || !strcmp(tok[0], "unoaep")) && nt == 2) {
            uint8_t msg[256];
            size_t ml = 0;
            int rc;
            a = unhex(tok[1], &l0);
            if (l0 != 256) rc = -1;
            else if (tok[0][2] == 'p') rc = rsa_unpad_pkcs1_v15(a, msg, &ml);
            else rc = rsa_unpad_oaep_sha1(a, msg, &ml);
            if (rc) printf("ERR\n"); else if (ml) puthex(msg, ml); else printf("\n");
            free(a);
        } else if (!strcmp(tok[0], "bench") && nt == 8) {
            rsa2048_key_t k;
            uint8_t out[256];
            struct timespec t0, t1;
            int i, reps = 20;
            a = unhex(tok[7], &l0);
            if (load_key(tok, 1, &k) || l0 != 256) { printf("ERR\n"); free(a); continue; }
            clock_gettime(CLOCK_MONOTONIC, &t0);
            for (i = 0; i < reps; i++) rsa2048_private_op(&k, a, out);
            clock_gettime(CLOCK_MONOTONIC, &t1);
            printf("MS %.3f\n", ((double)(t1.tv_sec - t0.tv_sec) * 1e3 + (double)(t1.tv_nsec - t0.tv_nsec) / 1e6) / reps);
            free(a);
        } else {
            printf("BADCMD\n");
        }
        fflush(stdout);
    }
    free(line);
    return 0;
}
