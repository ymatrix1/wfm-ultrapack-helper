/* Private to pkg_reader.c: native PS5 "FIH" (7F 46 49 48) package reader.
 *
 *   package file (FIH header, embedded big-endian CNT at the tail)
 *     -> outer PFS @0x10000 (PlaintextNoAuth only, 64 KiB blocks)
 *        files pfs_image.dat (NAPS packed) + naps_pkg_layout.dat (span plan)
 *     -> NAPS spans (256 KiB uncompressed units: stored / zero / Kraken)  = logical image
 *     -> inner PPR-PFS (direct offsets) -> /app0 tree
 * Not thread safe per handle (span cache is mutated by reads). */
#ifndef WUP_FIH_READER_H
#define WUP_FIH_READER_H

#include <stddef.h>
#include <stdint.h>

#include "pkg_reader.h"

typedef struct fih fih_t;

/* Takes ownership of *io (io->close is called on close, and also if open fails). Returns 0 or -1 + message. */
int fih_open(const pkgr_io_t *io, fih_t **out, char *err, size_t errlen);
void fih_close(fih_t *f);

const char *fih_content_id(const fih_t *f);
uint64_t fih_image_size(const fih_t *f);
uint64_t fih_span_count(const fih_t *f);
void fih_decode_stats(const fih_t *f, uint64_t *stored, uint64_t *zero, uint64_t *kraken);

/* Embedded CNT entry by id: absolute package offset and size. 0 = found. */
int fih_cnt_find(const fih_t *f, uint32_t id, uint64_t *off, uint64_t *size);
/* Raw read of the package file (for CNT-resident entries). 0 / -1. */
int fih_raw_read(fih_t *f, uint64_t off, void *buf, size_t n);
/* Read of the decoded logical image. 0 / -1. */
int fih_read(fih_t *f, uint64_t off, void *buf, size_t n);

/* Directory walk of the inner PFS. cb returns 0 = continue, 1 = skip (do not descend into a dir), -1 = abort.
 * Parents are reported before their children. dirprefix is "" at the root, no leading/trailing slash. */
typedef int (*fih_walk_cb)(void *ctx, const char *dirprefix, const uint8_t *name, size_t nl, int is_dir,
                           uint64_t size, uint64_t logical_off);
int fih_walk(fih_t *f, fih_walk_cb cb, void *ctx, char *err, size_t errlen);

#endif
