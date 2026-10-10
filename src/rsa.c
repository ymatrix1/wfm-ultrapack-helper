#include "rsa.h"

#include <string.h>

#include "crypto.h"

#define MAXL 32 /* limbs of a 1024-bit prime */

typedef uint32_t limb;

static void be_to_limbs(const uint8_t *b, size_t nbytes, limb *r) {
    size_t nl = nbytes / 4, i;
    for (i = 0; i < nl; i++) {
        const uint8_t *p = b + nbytes - 4 * (i + 1);
        r[i] = ((limb)p[0] << 24) | ((limb)p[1] << 16) | ((limb)p[2] << 8) | p[3];
    }
}

static void limbs_to_be(const limb *r, size_t nl, uint8_t *b) {
    size_t i;
    for (i = 0; i < nl; i++) {
        uint8_t *p = b + 4 * (nl - 1 - i);
        p[0] = (uint8_t)(r[i] >> 24); p[1] = (uint8_t)(r[i] >> 16);
        p[2] = (uint8_t)(r[i] >> 8); p[3] = (uint8_t)r[i];
    }
}

/* a >= b ? */
static int geq(const limb *a, const limb *b, int n) {
    int i;
    for (i = n - 1; i >= 0; i--) {
        if (a[i] != b[i]) return a[i] > b[i];
    }
    return 1;
}

static limb sub_n(limb *r, const limb *a, const limb *b, int n) {
    uint64_t borrow = 0;
    int i;
    for (i = 0; i < n; i++) {
        uint64_t d = (uint64_t)a[i] - b[i] - borrow;
        r[i] = (limb)d;
        borrow = (d >> 32) & 1;
    }
    return (limb)borrow;
}

static limb add_n(limb *r, const limb *a, const limb *b, int n) {
    uint64_t carry = 0;
    int i;
    for (i = 0; i < n; i++) {
        uint64_t s = (uint64_t)a[i] + b[i] + carry;
        r[i] = (limb)s;
        carry = s >> 32;
    }
    return (limb)carry;
}

/* r = x mod m, bit-serial (x has xl limbs, m has n limbs, m's top limb != 0).
 * r must not alias x. */
static void mod_reduce(limb *r, const limb *x, int xl, const limb *m, int n) {
    int i, bit;
    memset(r, 0, sizeof(limb) * (size_t)n);
    for (i = xl - 1; i >= 0; i--) {
        for (bit = 31; bit >= 0; bit--) {
            limb top = r[n - 1] >> 31, c = (x[i] >> bit) & 1, t;
            int j;
            for (j = 0; j < n; j++) { t = r[j] >> 31; r[j] = (r[j] << 1) | c; c = t; }
            if (top || geq(r, m, n)) sub_n(r, r, m, n);
        }
    }
}

typedef struct {
    int n;
    limb m[MAXL];
    limb r2[MAXL]; /* R^2 mod m, R = 2^(32n) */
    limb n0;       /* -m^-1 mod 2^32 */
} mont_t;

/* r = a*b/R mod m (CIOS). r may alias a or b. */
static void mont_mul(const mont_t *mc, limb *r, const limb *a, const limb *b) {
    int n = mc->n, i, j;
    limb t[MAXL + 2];
    memset(t, 0, sizeof t);
    for (i = 0; i < n; i++) {
        uint64_t c = 0, s;
        limb mq;
        for (j = 0; j < n; j++) {
            s = (uint64_t)t[j] + (uint64_t)a[j] * b[i] + c;
            t[j] = (limb)s; c = s >> 32;
        }
        s = (uint64_t)t[n] + c;
        t[n] = (limb)s; t[n + 1] = (limb)(s >> 32);
        mq = t[0] * mc->n0;
        s = (uint64_t)t[0] + (uint64_t)mq * mc->m[0];
        c = s >> 32;
        for (j = 1; j < n; j++) {
            s = (uint64_t)t[j] + (uint64_t)mq * mc->m[j] + c;
            t[j - 1] = (limb)s; c = s >> 32;
        }
        s = (uint64_t)t[n] + c;
        t[n - 1] = (limb)s;
        t[n] = t[n + 1] + (limb)(s >> 32);
    }
    if (t[n] || geq(t, mc->m, n)) sub_n(r, t, mc->m, n);
    else memcpy(r, t, sizeof(limb) * (size_t)n);
}

static int mont_init(mont_t *mc, const limb *m, int n) {
    limb inv = m[0];
    int i;
    if (!(m[0] & 1) || m[n - 1] == 0) return -1;
    for (i = 0; i < 5; i++) inv *= 2 - m[0] * inv; /* Newton: m^-1 mod 2^32 */
    mc->n = n;
    mc->n0 = (limb)(0u - inv);
    memcpy(mc->m, m, sizeof(limb) * (size_t)n);
    /* R^2 mod m: start with 1, double 64*n times with reduction */
    memset(mc->r2, 0, sizeof mc->r2);
    mc->r2[0] = 1;
    for (i = 0; i < 64 * n; i++) {
        limb top = mc->r2[n - 1] >> 31, c = 0, t;
        int j;
        for (j = 0; j < n; j++) { t = mc->r2[j] >> 31; mc->r2[j] = (mc->r2[j] << 1) | c; c = t; }
        if (top || geq(mc->r2, mc->m, n)) sub_n(mc->r2, mc->r2, mc->m, n);
    }
    return 0;
}

/* r = x^e mod m. x < m. e has n limbs. */
static void mont_exp(const mont_t *mc, limb *r, const limb *x, const limb *e) {
    int n = mc->n, i, bit;
    limb xm[MAXL], acc[MAXL], one[MAXL];
    memset(one, 0, sizeof one);
    one[0] = 1;
    mont_mul(mc, xm, x, mc->r2);
    mont_mul(mc, acc, one, mc->r2); /* Montgomery form of 1 */
    for (i = n - 1; i >= 0; i--) {
        for (bit = 31; bit >= 0; bit--) {
            mont_mul(mc, acc, acc, acc);
            if ((e[i] >> bit) & 1) mont_mul(mc, acc, acc, xm);
        }
    }
    mont_mul(mc, r, acc, one);
}

int rsa2048_private_op(const rsa2048_key_t *k, const uint8_t in[256], uint8_t out[256]) {
    enum { H = MAXL };
    limb c[2 * H], nn[2 * H], p[H], q[H], dp[H], dq[H], qi[H], qr[H];
    limb cp[H], cq[H], mp[H], mq[H], mr[H], h[H], res[2 * H];
    mont_t mc;
    uint64_t carry;
    int i, j;

    be_to_limbs(in, 256, c);
    be_to_limbs(k->n, 256, nn);
    if (geq(c, nn, 2 * H)) return -1;
    be_to_limbs(k->p, 128, p); be_to_limbs(k->q, 128, q);
    be_to_limbs(k->dp, 128, dp); be_to_limbs(k->dq, 128, dq);
    be_to_limbs(k->qinv, 128, qi);

    /* mq = (c mod q)^dq mod q */
    if (mont_init(&mc, q, H) != 0) return -1;
    mod_reduce(cq, c, 2 * H, q, H);
    mont_exp(&mc, mq, cq, dq);

    /* mp = (c mod p)^dp mod p */
    if (mont_init(&mc, p, H) != 0) return -1;
    mod_reduce(cp, c, 2 * H, p, H);
    mont_exp(&mc, mp, cp, dp);

    /* h = qinv * (mp - mq) mod p */
    mod_reduce(mr, mq, H, p, H);
    if (sub_n(h, mp, mr, H)) add_n(h, h, p, H);
    mod_reduce(qr, qi, H, p, H);
    mont_mul(&mc, qr, qr, mc.r2); /* qinv in Montgomery form */
    mont_mul(&mc, h, qr, h);      /* qinv*R * diff / R = qinv*diff */

    /* res = mq + h*q */
    memset(res, 0, sizeof res);
    for (i = 0; i < H; i++) {
        carry = 0;
        for (j = 0; j < H; j++) {
            uint64_t s = (uint64_t)res[i + j] + (uint64_t)h[i] * q[j] + carry;
            res[i + j] = (limb)s; carry = s >> 32;
        }
        res[i + H] = (limb)carry;
    }
    carry = 0;
    for (i = 0; i < 2 * H; i++) {
        uint64_t s = (uint64_t)res[i] + (i < H ? mq[i] : 0) + carry;
        res[i] = (limb)s; carry = s >> 32;
    }
    limbs_to_be(res, 2 * H, out);
    return 0;
}

/* ---------------- padding ---------------- */

int rsa_unpad_pkcs1_v15(const uint8_t em[256], uint8_t *out, size_t *outlen) {
    size_t i = 2;
    if (em[0] != 0x00 || em[1] != 0x02) return -1;
    while (i < 256 && em[i] != 0) i++;
    if (i >= 256 || i < 10) return -1; /* no separator, or PS shorter than 8 */
    i++;
    memcpy(out, em + i, 256 - i);
    *outlen = 256 - i;
    return 0;
}

static void mgf1_sha1(const uint8_t *seed, size_t slen, uint8_t *mask, size_t mlen) {
    uint32_t ctr = 0;
    size_t off = 0;
    while (off < mlen) {
        sha1_ctx c;
        uint8_t cb[4], d[20];
        size_t n = mlen - off < 20 ? mlen - off : 20;
        cb[0] = (uint8_t)(ctr >> 24); cb[1] = (uint8_t)(ctr >> 16);
        cb[2] = (uint8_t)(ctr >> 8); cb[3] = (uint8_t)ctr;
        sha1_init(&c);
        sha1_update(&c, seed, slen);
        sha1_update(&c, cb, 4);
        sha1_final(&c, d);
        memcpy(mask + off, d, n);
        off += n; ctr++;
    }
}

int rsa_unpad_oaep_sha1(const uint8_t em[256], uint8_t *out, size_t *outlen) {
    uint8_t seed[20], db[235], lhash[20], mask[235], bad;
    size_t i, idx = 0;
    int found = 0;
    if (em[0] != 0x00) return -1;
    memcpy(seed, em + 1, 20);
    memcpy(db, em + 21, 235);
    mgf1_sha1(db, 235, mask, 20);
    for (i = 0; i < 20; i++) seed[i] ^= mask[i];
    mgf1_sha1(seed, 20, mask, 235);
    for (i = 0; i < 235; i++) db[i] ^= mask[i];
    sha1(NULL, 0, lhash);
    bad = 0;
    for (i = 0; i < 20; i++) bad |= (uint8_t)(db[i] ^ lhash[i]);
    for (i = 20; i < 235 && !found; i++) {
        if (db[i] == 0x01) { found = 1; idx = i + 1; }
        else if (db[i] != 0x00) bad |= 1;
    }
    if (bad || !found) return -1;
    memcpy(out, db + idx, 235 - idx);
    *outlen = 235 - idx;
    return 0;
}
