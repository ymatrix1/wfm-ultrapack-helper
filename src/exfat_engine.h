#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct exfat_file_node {
  char *name;
  char *rel_path;
  uint64_t file_id;   /* opaque id handed back to exfat_src_ops_t.read */
  bool declared;      /* internal: false while a dir was only synthesized from a child path */
  bool is_dir;
  uint64_t size;
  uint32_t first_cluster;
  uint32_t cluster_count;
  struct exfat_file_node **children;
  size_t child_count;
  size_t child_cap;
} exfat_file_node_t;

typedef void (*convert_progress_cb)(uint64_t total, uint64_t done, void *user_data);
typedef bool (*convert_cancel_cb)(void *user_data);

/* Sink receives the image strictly in offset order. Return 0 on success, nonzero on failure. */
typedef int (*exfat_sink_fn)(const void *buf, size_t len, void *ctx);
/* Called once before the first sink call with the exact final image size in bytes. */
typedef int (*exfat_begin_fn)(uint64_t total_bytes, void *ctx);

/* Random-access data source for file contents.
 * read() must copy exactly `len` bytes of file `file_id` starting at `offset` into buf and return the
 * number of bytes delivered (0..len), or a negative value on error. Anything other than `len` is treated as
 * a failed/short read and aborts the conversion. For each file the writer calls read() with strictly
 * increasing, contiguous offsets starting at 0, in chunks of at most 256 KiB, only for files with size > 0. */
typedef struct exfat_src_ops {
  int (*read)(void *ctx, uint64_t file_id, uint64_t offset, void *buf, size_t len);
} exfat_src_ops_t;

/* One node of a caller-provided flat listing. Entries may come in any order; missing parent
 * directories are synthesized. path is relative, forward slashes, UTF-8 (empty components ignored;
 * OS-metadata names such as .DS_Store / Thumbs.db / "._*" are dropped like in the folder path, together
 * with everything beneath them; directories that existed only to hold a dropped entry are not synthesized).
 * size is ignored for directories; file_id is ignored for directories. */
typedef struct exfat_listing_entry {
  const char *path;
  uint64_t size;
  bool is_dir;
  uint64_t file_id;
} exfat_listing_entry_t;

/* Stream a listing + data source as an exFAT image through a sink (same bytes as the folder path would
 * produce for an equivalent tree). begin_fn may be NULL. Returns 0, -1 on error, -2 on cancel. */
int convert_listing_to_exfat_stream(const exfat_listing_entry_t *entries, size_t count,
                                    const exfat_src_ops_t *ops, void *ops_ctx,
                                    exfat_begin_fn begin_fn, exfat_sink_fn sink_fn, void *sink_ctx,
                                    convert_progress_cb progress_cb, convert_cancel_cb cancel_cb,
                                    void *user_data, char *err_msg, size_t err_len);

/* Same, written to a file (removed on failure). */
int convert_listing_to_exfat(const exfat_listing_entry_t *entries, size_t count,
                             const exfat_src_ops_t *ops, void *ops_ctx, const char *out_image_path,
                             convert_progress_cb progress_cb, convert_cancel_cb cancel_cb,
                             void *user_data, char *err_msg, size_t err_len);

/* Stream a folder as an exFAT image through a sink; no staging file. begin_fn may be NULL.
 * Returns 0, -1 on error, -2 on cancel. Caller handles cleanup of whatever the sink wrote. */
int convert_folder_to_exfat_stream(const char *source_dir, exfat_begin_fn begin_fn,
                                   exfat_sink_fn sink_fn, void *sink_ctx,
                                   convert_progress_cb progress_cb, convert_cancel_cb cancel_cb,
                                   void *user_data, char *err_msg, size_t err_len);

/* Convert a folder structure directly to an in-memory streamed exFAT image */
int convert_folder_to_exfat(const char *source_dir, const char *out_image_path,
                            convert_progress_cb progress_cb, convert_cancel_cb cancel_cb,
                            void *user_data, char *err_msg, size_t err_len);

/* Free allocated node tree */
void free_exfat_tree(exfat_file_node_t *root);

#ifdef __cplusplus
}
#endif
