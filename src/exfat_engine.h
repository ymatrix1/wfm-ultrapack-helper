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

/* Convert a folder structure directly to an in-memory streamed exFAT image */
int convert_folder_to_exfat(const char *source_dir, const char *out_image_path,
                            convert_progress_cb progress_cb, convert_cancel_cb cancel_cb,
                            void *user_data, char *err_msg, size_t err_len);

/* Free allocated node tree */
void free_exfat_tree(exfat_file_node_t *root);

#ifdef __cplusplus
}
#endif
