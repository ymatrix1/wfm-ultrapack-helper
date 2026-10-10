/* RSA-2048 private-key operation (CRT) and padding removal. Portable C99,
 * 32-bit limbs, Montgomery multiplication. Not constant-time; intended for
 * deriving keys from package files, not for protecting secrets from local
 * attackers. All numbers are big-endian byte strings. */
#ifndef WUP_RSA_H
#define WUP_RSA_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t n[256], p[128], q[128], dp[128], dq[128], qinv[128];
} rsa2048_key_t;

/* out = in^d mod n, computed via CRT. `in` must be < n. Returns 0 on success,
 * -1 if in >= n or the key is malformed (p or q even or with a zero top limb;
 * n == p*q is not verified). in and out may alias. */
int rsa2048_private_op(const rsa2048_key_t *k, const uint8_t in[256], uint8_t out[256]);

/* Remove PKCS#1 v1.5 type-2 (encryption) padding from a 256-byte block.
 * `out` must have room for 245 bytes. Returns 0 on success (*outlen set),
 * -1 on bad padding. */
int rsa_unpad_pkcs1_v15(const uint8_t em[256], uint8_t *out, size_t *outlen);

/* Remove RSAES-OAEP padding (SHA-1, MGF1-SHA1, empty label). `out` must have
 * room for 214 bytes. Returns 0 on success (*outlen set), -1 on failure. */
int rsa_unpad_oaep_sha1(const uint8_t em[256], uint8_t *out, size_t *outlen);

#endif
