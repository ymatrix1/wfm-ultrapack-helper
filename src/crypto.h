/* Small self-contained crypto primitives (no OpenSSL, portable C99).
 * SHA-1, SHA-256, HMAC-SHA256, AES-128 block cipher, AES-128-XTS, AES-128-CBC.
 * Not hardened against timing side channels (table-based AES); intended for
 * reading package files, not for protecting secrets from local attackers. */
#ifndef WUP_CRYPTO_H
#define WUP_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t h[8];
    uint64_t total; /* bytes processed */
    uint8_t buf[64];
    size_t buflen;
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const uint8_t *data, size_t len);
void sha256_final(sha256_ctx *c, uint8_t out[32]);
void sha256(const uint8_t *data, size_t len, uint8_t out[32]);

void hmac_sha256(const uint8_t *key, size_t klen, const uint8_t *msg, size_t mlen,
                 uint8_t out[32]);

/* AES-128. Lookup tables are initialized once, safely across threads.
 * crypto_init() is optional; aes128_set_key() also calls it lazily. */
typedef struct {
    uint32_t ek[44]; /* encryption round keys */
    uint32_t dk[44]; /* decryption round keys (equivalent inverse cipher) */
} aes128_ctx;

void crypto_init(void);
void aes128_set_key(aes128_ctx *c, const uint8_t key[16]);
void aes128_encrypt_block(const aes128_ctx *c, const uint8_t in[16], uint8_t out[16]);
void aes128_decrypt_block(const aes128_ctx *c, const uint8_t in[16], uint8_t out[16]);

/* AES-128-XTS (IEEE 1619). key1 = data key, key2 = tweak key. The tweak for
 * each sector is the 64-bit little-endian sector index (zero padded to 16
 * bytes); `sector` is the index of the first sector in `in`. Sectors are
 * `sector_size` bytes (multiple of 16, e.g. 0x1000); the final sector may be
 * shorter. len must be a multiple of 16 (no ciphertext stealing). in and out
 * may be the same buffer. Returns 0 on success, -1 on invalid arguments. */
int aes_xts_decrypt(const uint8_t key1[16], const uint8_t key2[16], uint64_t sector,
                    size_t sector_size, const uint8_t *in, uint8_t *out, size_t len);
int aes_xts_encrypt(const uint8_t key1[16], const uint8_t key2[16], uint64_t sector,
                    size_t sector_size, const uint8_t *in, uint8_t *out, size_t len);

/* AES-128-CBC without padding. len must be a multiple of 16. in and out may be
 * the same buffer. Returns 0 on success, -1 on invalid arguments. */
int aes128_cbc_decrypt(const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, uint8_t *out,
                       size_t len);
int aes128_cbc_encrypt(const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, uint8_t *out,
                       size_t len);

/* SHA-1 (needed for the RSA-OAEP / IMAGE_KEY chain; not for new designs). */
typedef struct {
    uint32_t h[5];
    uint64_t total; /* bytes processed */
    uint8_t buf[64];
    size_t buflen;
} sha1_ctx;

void sha1_init(sha1_ctx *c);
void sha1_update(sha1_ctx *c, const uint8_t *data, size_t len);
void sha1_final(sha1_ctx *c, uint8_t out[20]);
void sha1(const uint8_t *data, size_t len, uint8_t out[20]);

#endif
