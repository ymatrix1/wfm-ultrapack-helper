/* Random-access, no-extraction reader for PS4-family "fake" PKGs (LibOrbisPkg
 * layout, as shipped by PS5 homebrew). Presents the /app0 tree plus the
 * CNT-resident files (param.sfo, icon0.png, ...) as virtual files under
 * sce_sys/. Nothing is written to disk; every pkgr_read decrypts/decompresses
 * only what it needs (small per-handle caches, heap only).
 *
 * Thread-compatible: distinct handles may be used from distinct threads; a
 * single handle must not be used concurrently (caches are mutated on read).
 *
 * Also opens native PS5 "FIH" packages (magic 7F 46 49 48) whose outer PFS is
 * PlaintextNoAuth (no keys involved) through the same API: the NAPS/Kraken inner
 * image is decoded on demand (fih_reader.c); the passcode is ignored. The /app0 tree
 * is exposed the same way, plus sce_sys/param.json from the embedded CNT.
 *
 * EKPFS: tried from the passcode first (ComputeKeys), then, if rsa.h is
 * available at build time, through the RSA IMAGE_KEY chain (FakeKeyset). */
#ifndef WUP_PKG_READER_H
#define WUP_PKG_READER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct pkgr pkgr_t;

/* Pluggable random-access byte source for FIH packages (a local file, an HTTP range
 * client in tests, ...). pread must either fill all n bytes (return 0) or fail (-1).
 * close may be NULL. pkgr_open_io takes ownership of the io (close is called on
 * pkgr_close, and also when pkgr_open_io fails). */
typedef struct {
    int (*pread)(void *ctx, uint64_t off, void *buf, size_t n);
    void (*close)(void *ctx);
    void *ctx;
    uint64_t size; /* total size of the package in bytes */
} pkgr_io_t;

typedef struct {
    const char *format;     /* "7FCNT" or "FIH" */
    const char *content_id; /* NUL-terminated */
    uint64_t image_size;    /* FIH: decoded logical image size; else 0 */
    uint64_t spans;         /* FIH: number of NAPS spans; else 0 */
    uint64_t spans_stored, spans_zero, spans_kraken; /* FIH: spans decoded so far, per codec */
} pkgr_info_t;

typedef struct {
    const char *path;  /* relative to /app0, forward slashes, no leading slash */
    uint64_t size;     /* bytes (0 for directories) */
    bool is_dir;
} pkgr_entry_t;

/* passcode: NULL = default (32 x '0'). Returns 0 on success; on failure returns
 * -1, *out = NULL and err (if non-NULL) holds a message. */
int pkgr_open(const char *path, const char *passcode, pkgr_t **out, char *err, size_t errlen);
/* FIH only (a 7FCNT package needs a real file: use pkgr_open). */
int pkgr_open_io(const pkgr_io_t *io, pkgr_t **out, char *err, size_t errlen);
void pkgr_close(pkgr_t *p);
void pkgr_info(pkgr_t *p, pkgr_info_t *info);

size_t pkgr_entry_count(pkgr_t *p);
/* Valid until pkgr_close; NULL if i is out of range. Parents precede children. */
const pkgr_entry_t *pkgr_entry(pkgr_t *p, size_t i);
/* Sum of the sizes of all non-directory entries. */
uint64_t pkgr_total_size(pkgr_t *p);

/* Reads up to len bytes at offset of file entry entry_index. Returns the number
 * of bytes read (short only at EOF, 0 at/after EOF), or -1 on error (bad index,
 * directory, I/O or decode failure). */
int64_t pkgr_read(pkgr_t *p, size_t entry_index, uint64_t offset, void *buf, size_t len);

#endif
