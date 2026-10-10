/* Kraken (newLZ) block decoder for PS5 FIH/NAPS packages. See kraken.c (GPL-3.0 port). */
#ifndef WUP_KRAKEN_H
#define WUP_KRAKEN_H

#include <stddef.h>
#include <stdint.h>

/* Decodes one header-less NAPS span. flags = ((even&4)?2:0)|((even&2)?1:0)|((odd&4)?32:0)|((odd&2)?16:0);
 * first_chunk_comp = compressed size of the first 128 KiB chunk (only for dstlen > 128 KiB, else 0).
 * Returns 0 on success, nonzero on malformed/unsupported input. */
int kraken_decode_block(const uint8_t *payload, size_t srclen, int flags, int first_chunk_comp, uint8_t *dst,
                        size_t dstlen);

#endif
