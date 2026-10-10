#include "crypto.h"

#include <pthread.h>
#include <string.h>

/* ---------------- SHA-256 ---------------- */

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(uint32_t h[8], const uint8_t *p) {
    uint32_t w[64], a, b, c, d, e, f, g, hh, t1, t2;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[4 * i] << 24) | ((uint32_t)p[4 * i + 1] << 16) |
               ((uint32_t)p[4 * i + 2] << 8) | (uint32_t)p[4 * i + 3];
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ROR32(w[i - 15], 7) ^ ROR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROR32(w[i - 2], 17) ^ ROR32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4]; f = h[5]; g = h[6]; hh = h[7];
    for (i = 0; i < 64; i++) {
        t1 = hh + (ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
        t2 = (ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

void sha256_init(sha256_ctx *c) {
    static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(c->h, iv, sizeof iv);
    c->total = 0;
    c->buflen = 0;
}

void sha256_update(sha256_ctx *c, const uint8_t *data, size_t len) {
    c->total += len;
    if (c->buflen) {
        size_t n = 64 - c->buflen;
        if (n > len) n = len;
        memcpy(c->buf + c->buflen, data, n);
        c->buflen += n; data += n; len -= n;
        if (c->buflen < 64) return;
        sha256_block(c->h, c->buf);
        c->buflen = 0;
    }
    while (len >= 64) { sha256_block(c->h, data); data += 64; len -= 64; }
    if (len) { memcpy(c->buf, data, len); c->buflen = len; }
}

void sha256_final(sha256_ctx *c, uint8_t out[32]) {
    uint64_t bits = c->total * 8;
    uint8_t pad[72];
    size_t padlen = (c->buflen < 56) ? 56 - c->buflen : 120 - c->buflen;
    int i;
    memset(pad, 0, sizeof pad);
    pad[0] = 0x80;
    for (i = 0; i < 8; i++) pad[padlen + i] = (uint8_t)(bits >> (56 - 8 * i));
    sha256_update(c, pad, padlen + 8);
    for (i = 0; i < 8; i++) {
        out[4 * i] = (uint8_t)(c->h[i] >> 24);
        out[4 * i + 1] = (uint8_t)(c->h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(c->h[i] >> 8);
        out[4 * i + 3] = (uint8_t)c->h[i];
    }
}

void sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, data, len);
    sha256_final(&c, out);
}

void hmac_sha256(const uint8_t *key, size_t klen, const uint8_t *msg, size_t mlen,
                 uint8_t out[32]) {
    uint8_t k[64], pad[64], inner[32];
    sha256_ctx c;
    size_t i;
    memset(k, 0, sizeof k);
    if (klen > 64) sha256(key, klen, k);
    else if (klen) memcpy(k, key, klen);
    for (i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
    sha256_init(&c);
    sha256_update(&c, pad, 64);
    sha256_update(&c, msg, mlen);
    sha256_final(&c, inner);
    for (i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5c;
    sha256_init(&c);
    sha256_update(&c, pad, 64);
    sha256_update(&c, inner, 32);
    sha256_final(&c, out);
}

/* ---------------- AES-128 ---------------- */

static uint8_t SBOX[256], ISBOX[256];
static uint32_t TE0[256], TD0[256];
static pthread_once_t tables_once = PTHREAD_ONCE_INIT;

static uint8_t xt(uint8_t x) { return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0)); }
static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t r = 0;
    while (b) { if (b & 1) r ^= a; a = xt(a); b >>= 1; }
    return r;
}
static uint8_t rotl8(uint8_t x, int n) { return (uint8_t)((x << n) | (x >> (8 - n))); }
static uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

static void init_tables(void) {
    int i;
    uint8_t p = 1, q = 1;
    /* S-box via the standard multiplicative-inverse walk over GF(2^8) */
    do {
        p = (uint8_t)(p ^ (p << 1) ^ ((p & 0x80) ? 0x1b : 0));
        q ^= (uint8_t)(q << 1); q ^= (uint8_t)(q << 2); q ^= (uint8_t)(q << 4);
        if (q & 0x80) q ^= 0x09;
        SBOX[p] = (uint8_t)(q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4) ^ 0x63);
    } while (p != 1);
    SBOX[0] = 0x63;
    for (i = 0; i < 256; i++) ISBOX[SBOX[i]] = (uint8_t)i;
    for (i = 0; i < 256; i++) {
        uint8_t s = SBOX[i], si = ISBOX[i];
        TE0[i] = (uint32_t)gmul(s, 2) | ((uint32_t)s << 8) | ((uint32_t)s << 16) |
                 ((uint32_t)gmul(s, 3) << 24);
        TD0[i] = (uint32_t)gmul(si, 14) | ((uint32_t)gmul(si, 9) << 8) |
                 ((uint32_t)gmul(si, 13) << 16) | ((uint32_t)gmul(si, 11) << 24);
    }
}

void crypto_init(void) {
    pthread_once(&tables_once, init_tables);
}

static uint32_t ld32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void st32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

void aes128_set_key(aes128_ctx *c, const uint8_t key[16]) {
    static const uint8_t rcon[10] = {1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
    int i, r;
    crypto_init();
    for (i = 0; i < 4; i++) c->ek[i] = ld32(key + 4 * i);
    for (i = 4; i < 44; i++) {
        uint32_t t = c->ek[i - 1];
        if ((i & 3) == 0) {
            t = (t >> 8) | (t << 24); /* RotWord on a little-endian word */
            t = (uint32_t)SBOX[t & 0xff] | ((uint32_t)SBOX[(t >> 8) & 0xff] << 8) |
                ((uint32_t)SBOX[(t >> 16) & 0xff] << 16) | ((uint32_t)SBOX[t >> 24] << 24);
            t ^= rcon[i / 4 - 1];
        }
        c->ek[i] = c->ek[i - 4] ^ t;
    }
    for (r = 0; r <= 10; r++) {
        for (i = 0; i < 4; i++) {
            uint32_t w = c->ek[4 * (10 - r) + i];
            if (r > 0 && r < 10)
                w = TD0[SBOX[w & 0xff]] ^ rotl32(TD0[SBOX[(w >> 8) & 0xff]], 8) ^
                    rotl32(TD0[SBOX[(w >> 16) & 0xff]], 16) ^ rotl32(TD0[SBOX[w >> 24]], 24);
            c->dk[4 * r + i] = w;
        }
    }
}

#define SB4(T, a, b, c, d) \
    ((uint32_t)T[(a) & 0xff] | ((uint32_t)T[((b) >> 8) & 0xff] << 8) | \
     ((uint32_t)T[((c) >> 16) & 0xff] << 16) | ((uint32_t)T[(d) >> 24] << 24))

void aes128_encrypt_block(const aes128_ctx *c, const uint8_t in[16], uint8_t out[16]) {
    const uint32_t *rk = c->ek;
    uint32_t s0 = ld32(in) ^ rk[0], s1 = ld32(in + 4) ^ rk[1], s2 = ld32(in + 8) ^ rk[2],
             s3 = ld32(in + 12) ^ rk[3], t0, t1, t2, t3;
    int r;
    for (r = 1; r < 10; r++) {
        rk += 4;
        t0 = TE0[s0 & 0xff] ^ rotl32(TE0[(s1 >> 8) & 0xff], 8) ^ rotl32(TE0[(s2 >> 16) & 0xff], 16) ^ rotl32(TE0[s3 >> 24], 24) ^ rk[0];
        t1 = TE0[s1 & 0xff] ^ rotl32(TE0[(s2 >> 8) & 0xff], 8) ^ rotl32(TE0[(s3 >> 16) & 0xff], 16) ^ rotl32(TE0[s0 >> 24], 24) ^ rk[1];
        t2 = TE0[s2 & 0xff] ^ rotl32(TE0[(s3 >> 8) & 0xff], 8) ^ rotl32(TE0[(s0 >> 16) & 0xff], 16) ^ rotl32(TE0[s1 >> 24], 24) ^ rk[2];
        t3 = TE0[s3 & 0xff] ^ rotl32(TE0[(s0 >> 8) & 0xff], 8) ^ rotl32(TE0[(s1 >> 16) & 0xff], 16) ^ rotl32(TE0[s2 >> 24], 24) ^ rk[3];
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }
    rk += 4;
    st32(out, SB4(SBOX, s0, s1, s2, s3) ^ rk[0]);
    st32(out + 4, SB4(SBOX, s1, s2, s3, s0) ^ rk[1]);
    st32(out + 8, SB4(SBOX, s2, s3, s0, s1) ^ rk[2]);
    st32(out + 12, SB4(SBOX, s3, s0, s1, s2) ^ rk[3]);
}

void aes128_decrypt_block(const aes128_ctx *c, const uint8_t in[16], uint8_t out[16]) {
    const uint32_t *rk = c->dk;
    uint32_t s0 = ld32(in) ^ rk[0], s1 = ld32(in + 4) ^ rk[1], s2 = ld32(in + 8) ^ rk[2],
             s3 = ld32(in + 12) ^ rk[3], t0, t1, t2, t3;
    int r;
    for (r = 1; r < 10; r++) {
        rk += 4;
        t0 = TD0[s0 & 0xff] ^ rotl32(TD0[(s3 >> 8) & 0xff], 8) ^ rotl32(TD0[(s2 >> 16) & 0xff], 16) ^ rotl32(TD0[s1 >> 24], 24) ^ rk[0];
        t1 = TD0[s1 & 0xff] ^ rotl32(TD0[(s0 >> 8) & 0xff], 8) ^ rotl32(TD0[(s3 >> 16) & 0xff], 16) ^ rotl32(TD0[s2 >> 24], 24) ^ rk[1];
        t2 = TD0[s2 & 0xff] ^ rotl32(TD0[(s1 >> 8) & 0xff], 8) ^ rotl32(TD0[(s0 >> 16) & 0xff], 16) ^ rotl32(TD0[s3 >> 24], 24) ^ rk[2];
        t3 = TD0[s3 & 0xff] ^ rotl32(TD0[(s2 >> 8) & 0xff], 8) ^ rotl32(TD0[(s1 >> 16) & 0xff], 16) ^ rotl32(TD0[s0 >> 24], 24) ^ rk[3];
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }
    rk += 4;
    st32(out, SB4(ISBOX, s0, s3, s2, s1) ^ rk[0]);
    st32(out + 4, SB4(ISBOX, s1, s0, s3, s2) ^ rk[1]);
    st32(out + 8, SB4(ISBOX, s2, s1, s0, s3) ^ rk[2]);
    st32(out + 12, SB4(ISBOX, s3, s2, s1, s0) ^ rk[3]);
}

/* ---------------- AES-128-XTS ---------------- */

static int xts_crypt(int decrypt, const uint8_t key1[16], const uint8_t key2[16], uint64_t sector,
                     size_t sector_size, const uint8_t *in, uint8_t *out, size_t len) {
    aes128_ctx dc, tc;
    if (sector_size == 0 || (sector_size & 15) || (len & 15)) return -1;
    if (len == 0) return 0;
    aes128_set_key(&dc, key1);
    aes128_set_key(&tc, key2);
    while (len) {
        size_t n = len < sector_size ? len : sector_size, i;
        uint8_t iv[16], tw[16], blk[16];
        uint64_t lo, hi;
        int j;
        memset(iv, 0, 16);
        for (j = 0; j < 8; j++) iv[j] = (uint8_t)(sector >> (8 * j));
        aes128_encrypt_block(&tc, iv, tw);
        lo = (uint64_t)ld32(tw) | ((uint64_t)ld32(tw + 4) << 32);
        hi = (uint64_t)ld32(tw + 8) | ((uint64_t)ld32(tw + 12) << 32);
        for (i = 0; i < n; i += 16) {
            uint64_t carry;
            for (j = 0; j < 16; j++) {
                tw[j] = (uint8_t)((j < 8 ? lo : hi) >> (8 * (j & 7)));
                blk[j] = in[i + j] ^ tw[j];
            }
            if (decrypt) aes128_decrypt_block(&dc, blk, blk);
            else aes128_encrypt_block(&dc, blk, blk);
            for (j = 0; j < 16; j++) out[i + j] = blk[j] ^ tw[j];
            /* tweak *= alpha in GF(2^128), little-endian */
            carry = hi >> 63;
            hi = (hi << 1) | (lo >> 63);
            lo = (lo << 1) ^ (carry ? 0x87 : 0);
        }
        in += n; out += n; len -= n; sector++;
    }
    return 0;
}

int aes_xts_decrypt(const uint8_t key1[16], const uint8_t key2[16], uint64_t sector,
                    size_t sector_size, const uint8_t *in, uint8_t *out, size_t len) {
    return xts_crypt(1, key1, key2, sector, sector_size, in, out, len);
}

int aes_xts_encrypt(const uint8_t key1[16], const uint8_t key2[16], uint64_t sector,
                    size_t sector_size, const uint8_t *in, uint8_t *out, size_t len) {
    return xts_crypt(0, key1, key2, sector, sector_size, in, out, len);
}

/* ---------------- AES-128-CBC ---------------- */

int aes128_cbc_decrypt(const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, uint8_t *out,
                       size_t len) {
    aes128_ctx cx;
    uint8_t prev[16], cur[16], tmp[16];
    size_t off;
    int i;
    if (len % 16) return -1;
    aes128_set_key(&cx, key);
    memcpy(prev, iv, 16);
    for (off = 0; off < len; off += 16) {
        memcpy(cur, in + off, 16); /* save ciphertext: in may alias out */
        aes128_decrypt_block(&cx, cur, tmp);
        for (i = 0; i < 16; i++) out[off + i] = (uint8_t)(tmp[i] ^ prev[i]);
        memcpy(prev, cur, 16);
    }
    return 0;
}

int aes128_cbc_encrypt(const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, uint8_t *out,
                       size_t len) {
    aes128_ctx cx;
    uint8_t prev[16], tmp[16];
    size_t off;
    int i;
    if (len % 16) return -1;
    aes128_set_key(&cx, key);
    memcpy(prev, iv, 16);
    for (off = 0; off < len; off += 16) {
        for (i = 0; i < 16; i++) tmp[i] = (uint8_t)(in[off + i] ^ prev[i]);
        aes128_encrypt_block(&cx, tmp, prev);
        memcpy(out + off, prev, 16);
    }
    return 0;
}

/* ---------------- SHA-1 ---------------- */

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static void sha1_block(uint32_t h[5], const uint8_t *p) {
    uint32_t w[80], a, b, c, d, e, f, k, t;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[4 * i] << 24) | ((uint32_t)p[4 * i + 1] << 16) |
               ((uint32_t)p[4 * i + 2] << 8) | (uint32_t)p[4 * i + 3];
    for (i = 16; i < 80; i++) w[i] = ROL32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4];
    for (i = 0; i < 80; i++) {
        if (i < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
        else { f = b ^ c ^ d; k = 0xca62c1d6; }
        t = ROL32(a, 5) + f + e + k + w[i];
        e = d; d = c; c = ROL32(b, 30); b = a; a = t;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

void sha1_init(sha1_ctx *c) {
    c->h[0] = 0x67452301; c->h[1] = 0xefcdab89; c->h[2] = 0x98badcfe;
    c->h[3] = 0x10325476; c->h[4] = 0xc3d2e1f0;
    c->total = 0;
    c->buflen = 0;
}

void sha1_update(sha1_ctx *c, const uint8_t *data, size_t len) {
    c->total += len;
    if (c->buflen) {
        size_t n = 64 - c->buflen;
        if (n > len) n = len;
        memcpy(c->buf + c->buflen, data, n);
        c->buflen += n; data += n; len -= n;
        if (c->buflen < 64) return;
        sha1_block(c->h, c->buf);
        c->buflen = 0;
    }
    while (len >= 64) { sha1_block(c->h, data); data += 64; len -= 64; }
    if (len) { memcpy(c->buf, data, len); c->buflen = len; }
}

void sha1_final(sha1_ctx *c, uint8_t out[20]) {
    uint64_t bits = c->total * 8;
    uint8_t pad[72];
    size_t padlen = (c->buflen < 56) ? 56 - c->buflen : 120 - c->buflen;
    int i;
    memset(pad, 0, sizeof pad);
    pad[0] = 0x80;
    for (i = 0; i < 8; i++) pad[padlen + i] = (uint8_t)(bits >> (56 - 8 * i));
    sha1_update(c, pad, padlen + 8);
    for (i = 0; i < 5; i++) {
        out[4 * i] = (uint8_t)(c->h[i] >> 24);
        out[4 * i + 1] = (uint8_t)(c->h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(c->h[i] >> 8);
        out[4 * i + 3] = (uint8_t)c->h[i];
    }
}

void sha1(const uint8_t *data, size_t len, uint8_t out[20]) {
    sha1_ctx c;
    sha1_init(&c);
    sha1_update(&c, data, len);
    sha1_final(&c, out);
}
