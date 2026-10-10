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

/* OS-generated metadata never packed into an image; mirrors IGNORED_NAMES in
 * ps5-ultrapack backend/mkpfs/utils.py (case-insensitive, "._*" by prefix). */
static bool is_ignored(const char *name) {
  static const char *const ignored[] = {
    ".", "..",
    ".ds_store", ".spotlight-v100", ".trashes", ".fseventsd", ".temporaryitems",
    ".documentrevisions-v100", ".apdisk", "__macosx", ".volumeicon.icns",
    ".localized", ".appledouble", ".lsoverride", "icon\r",
    "thumbs.db", "ehthumbs.db", "desktop.ini", "$recycle.bin",
    "system volume information",
  };
  if (!strncmp(name, "._", 2)) return true;
  for (size_t i = 0; i < sizeof(ignored) / sizeof(ignored[0]); i++) {
    if (!strcasecmp(name, ignored[i])) return true;
  }
  return false;
}

/* UTF-8 to UTF-16 conversion for exFAT directory names */
static size_t utf8_to_utf16(const char *utf8, uint16_t *utf16, size_t max_utf16) {
  size_t in_len = strlen(utf8);
  size_t i = 0;
  size_t out_len = 0;

  while (i < in_len && out_len < max_utf16) {
    uint32_t cp = 0;
    unsigned char c = (unsigned char)utf8[i];

    if (c < 0x80) {
      cp = c;
      i += 1;
    } else if ((c & 0xE0) == 0xC0) {
      if (i + 1 >= in_len) break;
      cp = ((c & 0x1F) << 6) | (utf8[i + 1] & 0x3F);
      i += 2;
    } else if ((c & 0xF0) == 0xE0) {
      if (i + 2 >= in_len) break;
      cp = ((c & 0x0F) << 12) | ((utf8[i + 1] & 0x3F) << 6) | (utf8[i + 2] & 0x3F);
      i += 3;
    } else if ((c & 0xF8) == 0xF0) {
      if (i + 3 >= in_len) break;
      cp = ((c & 0x07) << 18) | ((utf8[i + 1] & 0x3F) << 12) | ((utf8[i + 2] & 0x3F) << 6) | (utf8[i + 3] & 0x3F);
      i += 4;
    } else {
      i += 1;
      continue;
    }

    if (cp <= 0xFFFF) {
      utf16[out_len++] = (uint16_t)cp;
    } else if (cp <= 0x10FFFF) {
      if (out_len + 2 > max_utf16) break;
      cp -= 0x10000;
      utf16[out_len++] = (uint16_t)(0xD800 + (cp >> 10));
      utf16[out_len++] = (uint16_t)(0xDC00 + (cp & 0x3FF));
    }
  }
  return out_len;
}

static uint16_t upcase_lookup(uint16_t ch) {
  if (ch * 2 + 1 < sizeof(UPCASE_TABLE)) {
    return (uint16_t)UPCASE_TABLE[ch * 2] | ((uint16_t)UPCASE_TABLE[ch * 2 + 1] << 8);
  }
  return ch;
}

static uint16_t exfat_name_hash(const uint16_t *utf16, size_t len) {
  uint16_t h = 0;
  for (size_t i = 0; i < len; i++) {
    uint16_t ch = upcase_lookup(utf16[i]);
    uint8_t b0 = (uint8_t)(ch & 0xFF);
    uint8_t b1 = (uint8_t)(ch >> 8);
    h = (uint16_t)((((h << 15) | (h >> 1)) & 0xFFFF) + b0);
    h = (uint16_t)((((h << 15) | (h >> 1)) & 0xFFFF) + b1);
  }
  return h;
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
  if (!n->name) { free(n); return NULL; }
  n->rel_path = strdup(rel ? rel : "");
  if (!n->rel_path) { free(n->name); free(n); return NULL; }
  if (abs) {
    n->abs_path = strdup(abs);
    if (!n->abs_path) { free(n->rel_path); free(n->name); free(n); return NULL; }
  }
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

    /* Use lstat to avoid following recursive symlinks */
    struct stat st;
    if (lstat(sub_abs, &st) != 0) {
      closedir(d);
      return -1;
    }
    if (S_ISLNK(st.st_mode)) {
      /* Skip symlinks to prevent loops and bad targets */
      continue;
    }

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
      if (scan_directory(sub_abs, sub_rel, child) != 0) {
        closedir(d);
        return -1;
      }
    }
  }

  closedir(d);
  if (parent->child_count > 1) {
    qsort(parent->children, parent->child_count, sizeof(exfat_file_node_t *), node_cmp);
    /* Detect case-insensitive duplicates */
    for (size_t i = 1; i < parent->child_count; i++) {
      if (!strcasecmp(parent->children[i - 1]->name, parent->children[i]->name)) {
        return -1; /* Duplicate entry under exFAT */
      }
    }
  }
  return 0;
}

static uint32_t directory_entry_count(const exfat_file_node_t *node, bool is_root) {
  uint32_t count = is_root ? 3 : 0; /* root has Label + Bitmap + Upcase */
  for (size_t i = 0; i < node->child_count; i++) {
    const exfat_file_node_t *c = node->children[i];
    uint16_t u16[260];
    size_t u16_len = utf8_to_utf16(c->name, u16, 255);
    uint32_t name_entries = ceil_div32((uint32_t)u16_len, NAME_CHARS_PER_ENTRY);
    count += 2 + name_entries;
  }
  return count;
}

static uint32_t calc_node_clusters(const exfat_file_node_t *node, bool is_root) {
  if (node->is_dir) {
    uint32_t entries = directory_entry_count(node, is_root);
    uint64_t bytes = (uint64_t)entries * 32U;
    return (uint32_t)ceil_div32(bytes ? bytes : 32U, CLUSTER_SIZE);
  }
  if (node->size == 0) return 0;
  return (uint32_t)ceil_div32(node->size, CLUSTER_SIZE);
}

static void count_all_clusters(const exfat_file_node_t *node, uint32_t *total) {
  for (size_t i = 0; i < node->child_count; i++) {
    exfat_file_node_t *c = node->children[i];
    *total += calc_node_clusters(c, false);
    if (c->is_dir) {
      count_all_clusters(c, total);
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

static uint16_t entry_set_checksum(const uint8_t *entries, size_t len) {
  uint16_t cs = 0;
  for (size_t i = 0; i < len; i++) {
    if (i == 2 || i == 3) continue; /* SetChecksum field */
    cs = (uint16_t)((((cs << 15) | (cs >> 1)) & 0xFFFF) + entries[i]);
  }
  return cs;
}

static size_t build_file_entries(const exfat_file_node_t *child, uint8_t *out, size_t cap) {
  uint16_t u16[260];
  size_t u16_len = utf8_to_utf16(child->name, u16, 255);
  uint32_t name_entries = ceil_div32((uint32_t)u16_len, NAME_CHARS_PER_ENTRY);
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
  stream[3] = (uint8_t)u16_len;
  put16_le(stream + 4, exfat_name_hash(u16, u16_len));
  uint64_t data_len = child->is_dir ? ((uint64_t)child->cluster_count * CLUSTER_SIZE) : child->size;
  put64_le(stream + 8, data_len);
  put32_le(stream + 20, has_alloc ? child->first_cluster : 0);
  put64_le(stream + 24, data_len);

  /* File name entries in UTF-16 LE */
  for (uint32_t i = 0; i < name_entries; i++) {
    uint8_t *ne = out + (2 + i) * 32;
    ne[0] = 0xC1;
    for (uint32_t k = 0; k < 15; k++) {
      uint32_t pos = i * 15 + k;
      if (pos < u16_len) {
        put16_le(ne + 2 + k * 2, u16[pos]);
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
    /* Volume label: empty, as in the reference mkpfs writer */
    buf[offset] = 0x83;
    offset += 32;

    /* Allocation Bitmap Directory Entry */
    buf[offset] = 0x81;
    buf[offset + 1] = 0;
    put32_le(buf + offset + 20, bitmap_first_cluster);
    put64_le(buf + offset + 24, (uint64_t)ceil_div32(cluster_count, 8));
    offset += 32;

    /* Up-case Table Directory Entry */
    buf[offset] = 0x82;
    buf[offset + 1] = 0;
    put32_le(buf + offset + 4, UPCASE_CHECKSUM);
    put32_le(buf + offset + 20, bitmap_first_cluster + bitmap_clusters);
    put64_le(buf + offset + 24, UPCASE_TABLE_LEN);
    offset += 32;
  }

  for (size_t i = 0; i < dir->child_count; i++) {
    const exfat_file_node_t *child = dir->children[i];
    uint8_t entry_buf[32 * 20];
    size_t elen = build_file_entries(child, entry_buf, sizeof(entry_buf));
    if (elen == 0 || offset + elen > buf_size) {
      free(buf);
      return -1;
    }
    memcpy(buf + offset, entry_buf, elen);
    offset += elen;
  }

  size_t written = fwrite(buf, 1, buf_size, fout);
  free(buf);
  return (written == buf_size) ? 0 : -1;
}

static int write_tree_content(FILE *fout, const exfat_file_node_t *dir,
                              convert_progress_cb progress_cb, convert_cancel_cb cancel_cb,
                              void *user_data, uint64_t total_bytes, uint64_t *done_bytes,
                              uint32_t bitmap_first, uint32_t cluster_count, uint32_t bitmap_clusters,
                              uint8_t *copy_buf, size_t copy_buf_sz) {
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
                                  total_bytes, done_bytes, bitmap_first, cluster_count, bitmap_clusters,
                                  copy_buf, copy_buf_sz);
      if (ret != 0) return ret;
    } else {
      /* Stream file body directly into output */
      if (c->size > 0 && c->abs_path) {
        FILE *fin = fopen(c->abs_path, "rb");
        if (!fin) return -1;

        uint64_t rem = c->size;
        while (rem > 0) {
          if (cancel_cb && cancel_cb(user_data)) { fclose(fin); return -2; }
          size_t chunk = (rem > copy_buf_sz) ? copy_buf_sz : (size_t)rem;
          if (fread(copy_buf, 1, chunk, fin) != chunk) { fclose(fin); return -1; }
          if (fwrite(copy_buf, 1, chunk, fout) != chunk) { fclose(fin); return -1; }
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

/* Link `count` contiguous clusters starting at `first` into a FAT chain. */
static void fat_chain(uint8_t *fat, uint32_t first, uint32_t count) {
  if (!count) return;
  for (uint32_t i = 0; i + 1 < count; i++) {
    put32_le(fat + (size_t)(first + i) * 4, first + i + 1);
  }
  put32_le(fat + (size_t)(first + count - 1) * 4, FAT_ENTRY_EOC);
}

static void fat_walk_chains(uint8_t *fat, const exfat_file_node_t *n) {
  if (n->first_cluster >= 2 && n->cluster_count > 0) {
    fat_chain(fat, n->first_cluster, n->cluster_count);
  }
  for (size_t i = 0; i < n->child_count; i++) {
    fat_walk_chains(fat, n->children[i]);
  }
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
    snprintf(err_msg, err_len, "Failed scanning source directory (symlink loop, duplicate, or unreadable file)");
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

  for (size_t s = 1; s <= 8; s++) {
    put16_le(boot_region + s * BYTES_PER_SECTOR + 510, 0xAA55);
  }

  uint32_t bchk = 0;
  for (size_t i = 0; i < 11 * BYTES_PER_SECTOR; i++) {
    if (i == 106 || i == 107 || i == 112) continue;
    bchk = ((bchk << 31) | (bchk >> 1)) + boot_region[i];
  }
  for (size_t i = 0; i < BYTES_PER_SECTOR; i += 4) {
    put32_le(boot_region + 11 * BYTES_PER_SECTOR + i, bchk);
  }

  if (fwrite(boot_region, 1, sizeof(boot_region), fout) != sizeof(boot_region) ||
      fwrite(boot_region, 1, sizeof(boot_region), fout) != sizeof(boot_region)) {
    snprintf(err_msg, err_len, "Failed writing boot sectors: %s", strerror(errno));
    fclose(fout); free_exfat_tree(root); unlink(out_image_path);
    return -1;
  }

  /* Pad to FAT offset */
  size_t pad_to_fat = (FAT_OFFSET_SECTORS - 24) * BYTES_PER_SECTOR;
  uint8_t zero_buf[4096] = {0};
  while (pad_to_fat > 0) {
    size_t p = (pad_to_fat > sizeof(zero_buf)) ? sizeof(zero_buf) : pad_to_fat;
    if (fwrite(zero_buf, 1, p, fout) != p) {
      snprintf(err_msg, err_len, "Failed writing VBR padding");
      fclose(fout); free_exfat_tree(root); unlink(out_image_path);
      return -1;
    }
    pad_to_fat -= p;
  }

  /* 2. Write FAT */
  size_t fat_bytes = fat_len_sectors * BYTES_PER_SECTOR;
  uint8_t *fat = (uint8_t *)calloc(1, fat_bytes);
  if (!fat) { fclose(fout); free_exfat_tree(root); unlink(out_image_path); return -1; }
  put32_le(fat + 0, FAT_ENTRY_MEDIA);
  put32_le(fat + 4, FAT_ENTRY_EOC);
  fat_chain(fat, BITMAP_FIRST_CLUSTER, bitmap_clusters);
  fat_chain(fat, BITMAP_FIRST_CLUSTER + bitmap_clusters, upcase_clusters);
  fat_walk_chains(fat, root);

  if (fwrite(fat, 1, fat_bytes, fout) != fat_bytes) {
    snprintf(err_msg, err_len, "Failed writing FAT");
    free(fat); fclose(fout); free_exfat_tree(root); unlink(out_image_path);
    return -1;
  }
  free(fat);

  /* Pad to Heap Offset */
  size_t pad_to_heap = (heap_offset - (FAT_OFFSET_SECTORS + fat_len_sectors * NUMBER_OF_FATS)) * BYTES_PER_SECTOR;
  while (pad_to_heap > 0) {
    size_t p = (pad_to_heap > sizeof(zero_buf)) ? sizeof(zero_buf) : pad_to_heap;
    if (fwrite(zero_buf, 1, p, fout) != p) {
      snprintf(err_msg, err_len, "Failed writing heap padding");
      fclose(fout); free_exfat_tree(root); unlink(out_image_path);
      return -1;
    }
    pad_to_heap -= p;
  }

  /* 3. Cluster Heap: Allocation Bitmap */
  size_t bmap_bytes = align_up32(ceil_div32(cluster_count, 8), CLUSTER_SIZE);
  uint8_t *bitmap = (uint8_t *)calloc(1, bmap_bytes);
  if (!bitmap) { fclose(fout); free_exfat_tree(root); unlink(out_image_path); return -1; }
  for (uint32_t bit = 0; bit < cluster_count; bit++) {
    bitmap[bit / 8] |= (uint8_t)(1 << (bit % 8));
  }
  if (fwrite(bitmap, 1, bmap_bytes, fout) != bmap_bytes) {
    snprintf(err_msg, err_len, "Failed writing bitmap");
    free(bitmap); fclose(fout); free_exfat_tree(root); unlink(out_image_path);
    return -1;
  }
  free(bitmap);

  /* 4. Up-case table */
  size_t upcase_pad = upcase_clusters * CLUSTER_SIZE - UPCASE_TABLE_LEN;
  if (fwrite(UPCASE_TABLE, 1, UPCASE_TABLE_LEN, fout) != UPCASE_TABLE_LEN) {
    snprintf(err_msg, err_len, "Failed writing upcase table");
    fclose(fout); free_exfat_tree(root); unlink(out_image_path);
    return -1;
  }
  while (upcase_pad > 0) {
    size_t p = (upcase_pad > sizeof(zero_buf)) ? sizeof(zero_buf) : upcase_pad;
    if (fwrite(zero_buf, 1, p, fout) != p) {
      snprintf(err_msg, err_len, "Failed writing upcase padding");
      fclose(fout); free_exfat_tree(root); unlink(out_image_path);
      return -1;
    }
    upcase_pad -= p;
  }

  /* 5. Root Directory */
  if (write_directory_cluster(fout, root, true, BITMAP_FIRST_CLUSTER, cluster_count, bitmap_clusters) != 0) {
    fclose(fout);
    free_exfat_tree(root);
    unlink(out_image_path);
    return -1;
  }

  /* 6. Recursive Content & Files */
  uint8_t *heap_copy_buf = (uint8_t *)malloc(CLUSTER_SIZE);
  if (!heap_copy_buf) {
    fclose(fout);
    free_exfat_tree(root);
    unlink(out_image_path);
    return -1;
  }

  uint64_t done_bytes = (uint64_t)heap_offset * BYTES_PER_SECTOR +
                        (uint64_t)(bitmap_clusters + upcase_clusters + root->cluster_count) * CLUSTER_SIZE;
  int res = write_tree_content(fout, root, progress_cb, cancel_cb, user_data,
                               total_bytes, &done_bytes, BITMAP_FIRST_CLUSTER, cluster_count, bitmap_clusters,
                               heap_copy_buf, CLUSTER_SIZE);

  free(heap_copy_buf);
  free_exfat_tree(root);

  if (res == -2) {
    snprintf(err_msg, err_len, "Conversion cancelled by user");
    fclose(fout);
    unlink(out_image_path);
    return -2;
  } else if (res != 0) {
    snprintf(err_msg, err_len, "Failed writing exFAT tree stream: %s", strerror(errno));
    fclose(fout);
    unlink(out_image_path);
    return -1;
  }

  if (fclose(fout) != 0) {
    snprintf(err_msg, err_len, "Failed flushing output exFAT image: %s", strerror(errno));
    unlink(out_image_path);
    return -1;
  }

  if (progress_cb) progress_cb(total_bytes, total_bytes, user_data);
  return 0;
}
