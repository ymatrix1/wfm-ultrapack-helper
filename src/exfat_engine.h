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
  char *abs_path;
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
