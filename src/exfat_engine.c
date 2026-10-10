#include "exfat_engine.h"
#include "exfat_upcase.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#define BYTES_PER_SECTOR 512U
#define BYTES_PER_SECTOR_SHIFT 9U
#define FAT_OFFSET_SECTORS 128U
#define NUMBER_OF_FATS 1U
#define FAT_ENTRY_EOC 0xFFFFFFFFU
#define FAT_ENTRY_MEDIA 0xFFFFFFF8U
#define CLUSTER_SIZE (64U * 1024U)
#define VOLUME_SERIAL 0x4D6B5046U /* "MkPF" */
#define FIXED_TIMESTAMP (((2024 - 1980) << 25) | (1 << 21) | (1 << 16))

#define ATTR_DIRECTORY 0x10U
#define ATTR_ARCHIVE   0x20U
#define FLAG_ALLOCATION_POSSIBLE 0x01U
#define NAME_CHARS_PER_ENTRY 15U
#define BITMAP_FIRST_CLUSTER 2U

static uint32_t ceil_div32(uint64_t a, uint32_t b) {
  return (uint32_t)((a + b - 1) / b);
}

static uint32_t align_up32(uint32_t v, uint32_t align) {
  return ceil_div32(v, align) * align;
}

static void put16_le(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)(v & 0xFF);
  p[1] = (uint8_t)((v >> 8) & 0xFF);
}

static void put32_le(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v & 0xFF);
  p[1] = (uint8_t)((v >> 8) & 0xFF);
  p[2] = (uint8_t)((v >> 16) & 0xFF);
  p[3] = (uint8_t)((v >> 24) & 0xFF);
}

static void put64_le(uint8_t *p, uint64_t v) {
  put32_le(p, (uint32_t)(v & 0xFFFFFFFFU));
  put32_le(p + 4, (uint32_t)(v >> 32));
}

static bool is_ignored(const char *name) {
  if (!strcmp(name, ".") || !strcmp(name, "..") || !strcmp(name, ".DS_Store") ||
      !strcmp(name, "Thumbs.db") || !strncmp(name, "._", 2)) {
    return true;
  }
  return false;
}

static int node_cmp(const void *a, const void *b) {
  const exfat_file_node_t *na = *(const exfat_file_node_t **)a;
  const exfat_file_node_t *nb = *(const exfat_file_node_t **)b;
  return strcasecmp(na->name, nb->name);
}

static exfat_file_node_t *create_node(const char *name, const char *rel, const char *abs, bool is_dir, uint64_t sz) {
  exfat_file_node_t *n = (exfat_file_node_t *)calloc(1, sizeof(exfat_file_node_t));
  if (!n) return NULL;
  n->name = strdup(name);
  n->rel_path = strdup(rel ? rel : "");
  if (abs) n->abs_path = strdup(abs);
  n->is_dir = is_dir;
  n->size = sz;
  return n;
}

void free_exfat_tree(exfat_file_node_t *root) {
  if (!root) return;
  for (size_t i = 0; i < root->child_count; i++) {
    free_exfat_tree(root->children[i]);
  }
  free(root->children);
  free(root->name);
  free(root->rel_path);
  if (root->abs_path) free(root->abs_path);
  free(root);
}

static int scan_directory(const char *abs_dir, const char *rel_dir, exfat_file_node_t *parent) {
  DIR *d = opendir(abs_dir);
  if (!d) return -1;
  struct dirent *ent;

  while ((ent = readdir(d)) != NULL) {
    if (is_ignored(ent->d_name)) continue;

    char sub_abs[4096];
    char sub_rel[4096];
    snprintf(sub_abs, sizeof(sub_abs), "%s/%s", abs_dir, ent->d_name);
    if (rel_dir && rel_dir[0]) {
      snprintf(sub_rel, sizeof(sub_rel), "%s/%s", rel_dir, ent->d_name);
    } else {
      snprintf(sub_rel, sizeof(sub_rel), "%s", ent->d_name);
    }

    struct stat st;
    if (stat(sub_abs, &st) != 0) continue;

    bool is_dir = S_ISDIR(st.st_mode);
    uint64_t sz = is_dir ? 0 : (uint64_t)st.st_size;

    exfat_file_node_t *child = create_node(ent->d_name, sub_rel, sub_abs, is_dir, sz);
    if (!child) { closedir(d); return -1; }

    if (parent->child_count >= parent->child_cap) {
      size_t new_cap = parent->child_cap ? parent->child_cap * 2 : 16;
      exfat_file_node_t **arr = (exfat_file_node_t **)realloc(parent->children, new_cap * sizeof(exfat_file_node_t *));
      if (!arr) { free_exfat_tree(child); closedir(d); return -1; }
      parent->children = arr;
      parent->child_cap = new_cap;
    }
    parent->children[parent->child_count++] = child;

    if (is_dir) {
      scan_directory(sub_abs, sub_rel, child);
    }
  }

  closedir(d);
  if (parent->child_count > 1) {
    qsort(parent->children, parent->child_count, sizeof(exfat_file_node_t *), node_cmp);
  }
  return 0;
}

static uint32_t directory_entry_count(const exfat_file_node_t *node, bool is_root) {
  uint32_t count = is_root ? 3 : 0; /* root has Label + Bitmap + Upcase */
  for (size_t i = 0; i < node->child_count; i++) {
    const exfat_file_node_t *c = node->children[i];
    uint32_t name_len = (uint32_t)strlen(c->name);
    uint32_t name_entries = ceil_div32(name_len, NAME_CHARS_PER_ENTRY);
    count += 2 + name_entries;
  }
  return count;
}

static uint32_t calc_node_clusters(const exfat_file_node_t *node, bool is_root) {
  if (node->is_dir) {
    uint32_t entries = directory_entry_count(node, is_root);
    uint32_t bytes = entries * 32U;
    uint32_t cl = ceil_div32(bytes, CLUSTER_SIZE);
    return cl ? cl : 1;
  }
  return ceil_div32(node->size, CLUSTER_SIZE);
}

static void count_all_clusters(const exfat_file_node_t *node, uint32_t *acc) {
  for (size_t i = 0; i < node->child_count; i++) {
    const exfat_file_node_t *c = node->children[i];
    *acc += calc_node_clusters(c, false);
    if (c->is_dir) {
      count_all_clusters(c, acc);
    }
  }
}

static void assign_clusters_recursive(exfat_file_node_t *node, uint32_t *next_cluster) {
  for (size_t i = 0; i < node->child_count; i++) {
    exfat_file_node_t *c = node->children[i];
    c->cluster_count = calc_node_clusters(c, false);
    if (c->cluster_count > 0 && (c->is_dir || c->size > 0)) {
      c->first_cluster = *next_cluster;
      *next_cluster += c->cluster_count;
    }
    if (c->is_dir) {
      assign_clusters_recursive(c, next_cluster);
    }
  }
}

static uint16_t exfat_name_hash(const char *name) {
  uint16_t h = 0;
  for (const char *p = name; *p; p++) {
    uint16_t ch = (uint8_t)toupper((unsigned char)*p);
    uint8_t b0 = (uint8_t)(ch & 0xFF);
    uint8_t b1 = 0;
    h = (uint16_t)((((h << 15) | (h >> 1)) & 0xFFFF) + b0);
    h = (uint16_t)((((h << 15) | (h >> 1)) & 0xFFFF) + b1);
  }
  return h;
}

static uint16_t entry_set_checksum(const uint8_t *entries, size_t len) {
  uint16_t cs = 0;
  for (size_t i = 0; i < len; i++) {
    if (i == 2 || i == 3) continue; /* SetChecksum field */
    cs = (uint16_t)((((cs << 15) | (cs >> 1)) & 0xFFFF) + entries[i]);
  }
  return cs;
}

static size_t build_file_entries(const exfat_file_node_t *child, uint8_t *out, size_t cap) {
  uint32_t name_len = (uint32_t)strlen(child->name);
  uint32_t name_entries = ceil_div32(name_len, NAME_CHARS_PER_ENTRY);
  size_t total_len = (2 + name_entries) * 32U;
  if (total_len > cap) return 0;

  memset(out, 0, total_len);
  /* File directory entry */
  out[0] = 0x85;
  out[1] = (uint8_t)(1 + name_entries);
  put16_le(out + 4, child->is_dir ? ATTR_DIRECTORY : ATTR_ARCHIVE);
  put32_le(out + 8, FIXED_TIMESTAMP);
  put32_le(out + 12, FIXED_TIMESTAMP);
  put32_le(out + 16, FIXED_TIMESTAMP);

  /* Stream extension entry */
  uint8_t *stream = out + 32;
  stream[0] = 0xC0;
  bool has_alloc = (child->first_cluster >= 2);
  stream[1] = has_alloc ? FLAG_ALLOCATION_POSSIBLE : 0x00;
  stream[3] = (uint8_t)name_len;
  put16_le(stream + 4, exfat_name_hash(child->name));
  uint64_t data_len = child->is_dir ? ((uint64_t)child->cluster_count * CLUSTER_SIZE) : child->size;
  put64_le(stream + 8, data_len);
  put32_le(stream + 20, has_alloc ? child->first_cluster : 0);
  put64_le(stream + 24, data_len);

  /* File name entries */
  for (uint32_t i = 0; i < name_entries; i++) {
    uint8_t *ne = out + (2 + i) * 32;
    ne[0] = 0xC1;
    for (uint32_t k = 0; k < 15; k++) {
      uint32_t pos = i * 15 + k;
      if (pos < name_len) {
        put16_le(ne + 2 + k * 2, (uint8_t)child->name[pos]);
      } else {
        put16_le(ne + 2 + k * 2, 0);
      }
    }
  }

  uint16_t cs = entry_set_checksum(out, total_len);
  put16_le(out + 2, cs);
  return total_len;
}

static int write_directory_cluster(FILE *fout, const exfat_file_node_t *dir, bool is_root,
                                  uint32_t bitmap_first_cluster, uint32_t cluster_count,
                                  uint32_t bitmap_clusters) {
  size_t buf_size = dir->cluster_count * CLUSTER_SIZE;
  uint8_t *buf = (uint8_t *)calloc(1, buf_size);
  if (!buf) return -1;

  size_t offset = 0;
  if (is_root) {
    /* Volume label */
    buf[offset] = 0x83;
    offset += 32;

    /* Allocation bitmap */
    buf[offset] = 0x81;
    put32_le(buf + offset + 20, bitmap_first_cluster);
    put64_le(buf + offset + 24, ceil_div32(cluster_count, 8));
    offset += 32;

    /* Up-case table */
    buf[offset] = 0x82;
    put32_le(buf + offset + 4, UPCASE_CHECKSUM);
    put32_le(buf + offset + 20, bitmap_first_cluster + bitmap_clusters);
    put64_le(buf + offset + 24, UPCASE_TABLE_LEN);
    offset += 32;
  }

  for (size_t i = 0; i < dir->child_count; i++) {
    size_t wrote = build_file_entries(dir->children[i], buf + offset, buf_size - offset);
    offset += wrote;
  }

  size_t nw = fwrite(buf, 1, buf_size, fout);
  free(buf);
  return (nw == buf_size) ? 0 : -1;
}

static void fat_chain(uint8_t *fat, uint32_t first, uint32_t count) {
  for (uint32_t i = 0; i < count - 1; i++) {
    put32_le(fat + (first + i) * 4, first + i + 1);
  }
  put32_le(fat + (first + count - 1) * 4, FAT_ENTRY_EOC);
}

static void fat_walk_chains(uint8_t *fat, const exfat_file_node_t *n) {
  if (n->first_cluster >= 2 && n->cluster_count > 0) {
    fat_chain(fat, n->first_cluster, n->cluster_count);
  }
  for (size_t i = 0; i < n->child_count; i++) {
    fat_walk_chains(fat, n->children[i]);
  }
}

static int write_tree_content(FILE *fout, const exfat_file_node_t *dir,
                              convert_progress_cb progress_cb, convert_cancel_cb cancel_cb,
                              void *user_data, uint64_t total_bytes, uint64_t *done_bytes,
                              uint32_t bitmap_first, uint32_t cluster_count, uint32_t bitmap_clusters) {
  /* Write children files, and recurse on subdirs */
  for (size_t i = 0; i < dir->child_count; i++) {
    if (cancel_cb && cancel_cb(user_data)) return -2;
    exfat_file_node_t *c = dir->children[i];

    if (c->is_dir) {
      if (write_directory_cluster(fout, c, false, bitmap_first, cluster_count, bitmap_clusters) != 0) {
        return -1;
      }
      *done_bytes += (uint64_t)c->cluster_count * CLUSTER_SIZE;
      if (progress_cb) progress_cb(total_bytes, *done_bytes, user_data);

      int ret = write_tree_content(fout, c, progress_cb, cancel_cb, user_data,
                                  total_bytes, done_bytes, bitmap_first, cluster_count, bitmap_clusters);
      if (ret != 0) return ret;
    } else {
      /* Stream file body directly into output with zero disk staging */
      if (c->size > 0 && c->abs_path) {
        FILE *fin = fopen(c->abs_path, "rb");
        if (!fin) return -1;

        uint8_t buffer[64 * 1024];
        uint64_t rem = c->size;
        while (rem > 0) {
          if (cancel_cb && cancel_cb(user_data)) { fclose(fin); return -2; }
          size_t chunk = (rem > sizeof(buffer)) ? sizeof(buffer) : (size_t)rem;
          if (fread(buffer, 1, chunk, fin) != chunk) { fclose(fin); return -1; }
          if (fwrite(buffer, 1, chunk, fout) != chunk) { fclose(fin); return -1; }
          rem -= chunk;
          *done_bytes += chunk;
          if (progress_cb) progress_cb(total_bytes, *done_bytes, user_data);
        }
        fclose(fin);

        /* Pad file allocation to cluster boundary */
        uint64_t alloc_sz = (uint64_t)c->cluster_count * CLUSTER_SIZE;
        if (alloc_sz > c->size) {
          size_t pad = (size_t)(alloc_sz - c->size);
          uint8_t zero_pad[4096] = {0};
          while (pad > 0) {
            size_t p = (pad > sizeof(zero_pad)) ? sizeof(zero_pad) : pad;
            if (fwrite(zero_pad, 1, p, fout) != p) return -1;
            pad -= p;
          }
        }
      }
    }
  }
  return 0;
}

int convert_folder_to_exfat(const char *source_dir, const char *out_image_path,
                            convert_progress_cb progress_cb, convert_cancel_cb cancel_cb,
                            void *user_data, char *err_msg, size_t err_len) {
  exfat_file_node_t *root = create_node("", "", NULL, true, 0);
  if (!root) {
    snprintf(err_msg, err_len, "Failed to allocate exFAT root node");
    return -1;
  }

  if (scan_directory(source_dir, "", root) != 0) {
    snprintf(err_msg, err_len, "Failed to scan source directory: %s", strerror(errno));
    free_exfat_tree(root);
    return -1;
  }

  uint32_t spc = CLUSTER_SIZE / BYTES_PER_SECTOR;
  uint8_t spc_shift = 0;
  for (uint32_t v = spc; v > 1; v >>= 1) spc_shift++;

  uint32_t upcase_clusters = ceil_div32(UPCASE_TABLE_LEN, CLUSTER_SIZE);
  root->cluster_count = calc_node_clusters(root, true);

  uint32_t content_clusters = root->cluster_count + upcase_clusters;
  count_all_clusters(root, &content_clusters);

  uint32_t bitmap_clusters = 1;
  while (1) {
    uint32_t total_c = bitmap_clusters + content_clusters;
    uint32_t need = ceil_div32(ceil_div32(total_c, 8), CLUSTER_SIZE);
    if (need == bitmap_clusters) break;
    bitmap_clusters = need;
  }

  uint32_t cluster_count = bitmap_clusters + content_clusters;
  uint32_t next_cluster = BITMAP_FIRST_CLUSTER + bitmap_clusters + upcase_clusters;
  root->first_cluster = next_cluster;
  next_cluster += root->cluster_count;

  assign_clusters_recursive(root, &next_cluster);

  uint32_t fat_entries = cluster_count + 2;
  uint32_t fat_len_sectors = align_up32(ceil_div32(fat_entries * 4, BYTES_PER_SECTOR), spc);
  uint32_t heap_offset = align_up32(FAT_OFFSET_SECTORS + fat_len_sectors * NUMBER_OF_FATS, spc);
  uint64_t volume_length_sectors = (uint64_t)heap_offset + (uint64_t)cluster_count * spc;
  uint64_t total_bytes = volume_length_sectors * BYTES_PER_SECTOR;

  FILE *fout = fopen(out_image_path, "wb");
  if (!fout) {
    snprintf(err_msg, err_len, "Failed to create output file: %s", strerror(errno));
    free_exfat_tree(root);
    return -1;
  }

  /* 1. Build Main Boot Region (12 sectors) */
  uint8_t boot_region[12 * BYTES_PER_SECTOR];
  memset(boot_region, 0, sizeof(boot_region));
  boot_region[0] = 0xEB; boot_region[1] = 0x76; boot_region[2] = 0x90;
  memcpy(boot_region + 3, "EXFAT   ", 8);
  put64_le(boot_region + 72, volume_length_sectors);
  put32_le(boot_region + 80, FAT_OFFSET_SECTORS);
  put32_le(boot_region + 84, fat_len_sectors);
  put32_le(boot_region + 88, heap_offset);
  put32_le(boot_region + 92, cluster_count);
  put32_le(boot_region + 96, root->first_cluster);
  put32_le(boot_region + 100, VOLUME_SERIAL);
  put16_le(boot_region + 104, 0x0100);
  boot_region[108] = BYTES_PER_SECTOR_SHIFT;
  boot_region[109] = spc_shift;
  boot_region[110] = NUMBER_OF_FATS;
  boot_region[111] = 0x80;
  boot_region[112] = 0xFF;
  put16_le(boot_region + 510, 0xAA55);

  for (int i = 1; i <= 8; i++) {
    put32_le(boot_region + (i + 1) * BYTES_PER_SECTOR - 4, 0xAA550000U);
  }

  uint32_t boot_csum = 0;
  for (size_t i = 0; i < 11 * BYTES_PER_SECTOR; i++) {
    if (i == 106 || i == 107 || i == 112) continue;
    boot_csum = (((boot_csum << 31) | (boot_csum >> 1)) & 0xFFFFFFFFU) + boot_region[i];
  }
  for (size_t i = 0; i < BYTES_PER_SECTOR; i += 4) {
    put32_le(boot_region + 11 * BYTES_PER_SECTOR + i, boot_csum);
  }

  /* Write Main + Backup Boot Sector */
  fwrite(boot_region, 1, sizeof(boot_region), fout);
  fwrite(boot_region, 1, sizeof(boot_region), fout);

  /* Pad to FAT offset */
  size_t pad_to_fat = (FAT_OFFSET_SECTORS - 24) * BYTES_PER_SECTOR;
  uint8_t zero_buf[4096] = {0};
  while (pad_to_fat > 0) {
    size_t p = (pad_to_fat > sizeof(zero_buf)) ? sizeof(zero_buf) : pad_to_fat;
    fwrite(zero_buf, 1, p, fout);
    pad_to_fat -= p;
  }

  /* 2. Write FAT */
  size_t fat_bytes = fat_len_sectors * BYTES_PER_SECTOR;
  uint8_t *fat = (uint8_t *)calloc(1, fat_bytes);
  if (!fat) { fclose(fout); free_exfat_tree(root); return -1; }
  put32_le(fat, FAT_ENTRY_MEDIA);
  put32_le(fat + 4, FAT_ENTRY_EOC);

  fat_chain(fat, BITMAP_FIRST_CLUSTER, bitmap_clusters);
  fat_chain(fat, BITMAP_FIRST_CLUSTER + bitmap_clusters, upcase_clusters);
  fat_walk_chains(fat, root);

  fwrite(fat, 1, fat_bytes, fout);
  free(fat);

  /* Pad to Heap Offset */
  size_t pad_to_heap = (heap_offset - (FAT_OFFSET_SECTORS + fat_len_sectors * NUMBER_OF_FATS)) * BYTES_PER_SECTOR;
  while (pad_to_heap > 0) {
    size_t p = (pad_to_heap > sizeof(zero_buf)) ? sizeof(zero_buf) : pad_to_heap;
    fwrite(zero_buf, 1, p, fout);
    pad_to_heap -= p;
  }

  /* 3. Cluster Heap: Allocation Bitmap */
  size_t bmap_bytes = align_up32(ceil_div32(cluster_count, 8), CLUSTER_SIZE);
  uint8_t *bitmap = (uint8_t *)calloc(1, bmap_bytes);
  if (!bitmap) { fclose(fout); free_exfat_tree(root); return -1; }
  for (uint32_t bit = 0; bit < cluster_count; bit++) {
    bitmap[bit / 8] |= (uint8_t)(1 << (bit % 8));
  }
  fwrite(bitmap, 1, bmap_bytes, fout);
  free(bitmap);

  /* 4. Up-case table */
  size_t upcase_pad = upcase_clusters * CLUSTER_SIZE - UPCASE_TABLE_LEN;
  fwrite(UPCASE_TABLE, 1, UPCASE_TABLE_LEN, fout);
  while (upcase_pad > 0) {
    size_t p = (upcase_pad > sizeof(zero_buf)) ? sizeof(zero_buf) : upcase_pad;
    fwrite(zero_buf, 1, p, fout);
    upcase_pad -= p;
  }

  /* 5. Root Directory */
  if (write_directory_cluster(fout, root, true, BITMAP_FIRST_CLUSTER, cluster_count, bitmap_clusters) != 0) {
    fclose(fout);
    free_exfat_tree(root);
    return -1;
  }

  /* 6. Recursive Content & Files */
  uint64_t done_bytes = (uint64_t)heap_offset * BYTES_PER_SECTOR +
                        (uint64_t)(bitmap_clusters + upcase_clusters + root->cluster_count) * CLUSTER_SIZE;
  int res = write_tree_content(fout, root, progress_cb, cancel_cb, user_data,
                               total_bytes, &done_bytes, BITMAP_FIRST_CLUSTER, cluster_count, bitmap_clusters);

  fclose(fout);
  free_exfat_tree(root);

  if (res == -2) {
    snprintf(err_msg, err_len, "Conversion cancelled by user");
    unlink(out_image_path);
    return -2;
  } else if (res != 0) {
    snprintf(err_msg, err_len, "Failed writing exFAT tree stream");
    unlink(out_image_path);
    return -1;
  }

  if (progress_cb) progress_cb(total_bytes, total_bytes, user_data);
  return 0;
}
