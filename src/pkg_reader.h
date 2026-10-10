/* Random-access, no-extraction reader for PS4-family "fake" PKGs (LibOrbisPkg
 * layout, as shipped by PS5 homebrew). Presents the /app0 tree plus the
 * CNT-resident files (param.sfo, icon0.png, ...) as virtual files under
 * sce_sys/. Nothing is written to disk; every pkgr_read decrypts/decompresses
 * only what it needs (small per-handle caches, heap only).
 *
 * Thread-compatible: distinct handles may be used from distinct threads; a
 * single handle must not be used concurrently (caches are mutated on read).
 *
 * EKPFS: tried from the passcode first (ComputeKeys), then, if rsa.h is
 * available at build time, through the RSA IMAGE_KEY chain (FakeKeyset). */
#ifndef WUP_PKG_READER_H
#define WUP_PKG_READER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct pkgr pkgr_t;

typedef struct {
    const char *path;  /* relative to /app0, forward slashes, no leading slash */
    uint64_t size;     /* bytes (0 for directories) */
    bool is_dir;
} pkgr_entry_t;

/* passcode: NULL = default (32 x '0'). Returns 0 on success; on failure returns
 * -1, *out = NULL and err (if non-NULL) holds a message. */
int pkgr_open(const char *path, const char *passcode, pkgr_t **out, char *err, size_t errlen);
void pkgr_close(pkgr_t *p);

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
