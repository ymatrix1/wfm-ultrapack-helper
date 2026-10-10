#include "convert_engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include "miniz.h"

/* Minimal high-performance zlib streaming to outer PFSC format (.ffpfsc)
 * PFSC file structure:
 *  - 0x00..0x30: Header
 *  - 0x400..0x10000: Block offset table (64-bit uint64 per 64 KiB block)
 *  - 0x10000..: Compressed data chunks
 */

int convert_image_to_ffpfsc(const char *in_image_path, const char *out_ffpfsc_path,
                            convert_progress_cb progress_cb, convert_cancel_cb cancel_cb,
                            void *user_data, char *err_msg, size_t err_len) {
  FILE *fin = fopen(in_image_path, "rb");
  if (!fin) {
    snprintf(err_msg, err_len, "Cannot open source image: %s", strerror(errno));
    return -1;
  }

  struct stat st;
  if (fstat(fileno(fin), &st) != 0) {
    snprintf(err_msg, err_len, "Cannot stat source image: %s", strerror(errno));
    fclose(fin);
    return -1;
  }

  uint64_t total_input_size = (uint64_t)st.st_size;
  uint32_t block_count = (uint32_t)((total_input_size + PFSC_LOGICAL_BLOCK_SIZE - 1) / PFSC_LOGICAL_BLOCK_SIZE);
  uint64_t logical_size = (uint64_t)block_count * PFSC_LOGICAL_BLOCK_SIZE;

  /* Dynamically size initial data offset so table never overflows */
  size_t table_bytes = (size_t)(block_count + 1) * sizeof(uint64_t);
  uint64_t initial_data_offset = PFSC_INITIAL_DATA_OFFSET;
  while (initial_data_offset < PFSC_BLOCK_OFFSETS_OFFSET + table_bytes) {
    initial_data_offset += PFSC_LOGICAL_BLOCK_SIZE;
  }

  FILE *fout = fopen(out_ffpfsc_path, "wb+");
  if (!fout) {
    snprintf(err_msg, err_len, "Cannot create target .ffpfsc: %s", strerror(errno));
    fclose(fin);
    return -1;
  }

  /* 1. Reserve PFSC header and block offsets */
  uint8_t zero_buf[4096] = {0};
  size_t header_pad = (size_t)initial_data_offset;
  while (header_pad > 0) {
    size_t p = (header_pad > sizeof(zero_buf)) ? sizeof(zero_buf) : header_pad;
    if (fwrite(zero_buf, 1, p, fout) != p) {
      fclose(fin); fclose(fout);
      unlink(out_ffpfsc_path);
      return -1;
    }
    header_pad -= p;
  }

  /* Allocate table for block offsets */
  uint64_t *offsets = (uint64_t *)calloc(block_count + 1, sizeof(uint64_t));
  if (!offsets) {
    snprintf(err_msg, err_len, "Out of memory for block table");
    fclose(fin); fclose(fout);
    unlink(out_ffpfsc_path);
    return -1;
  }

  uint64_t current_out_offset = initial_data_offset;
  uint8_t in_buf[PFSC_LOGICAL_BLOCK_SIZE];
  uint8_t out_buf[PFSC_LOGICAL_BLOCK_SIZE * 2];

  uint64_t processed_in = 0;

  for (uint32_t b = 0; b < block_count; b++) {
    if (cancel_cb && cancel_cb(user_data)) {
      snprintf(err_msg, err_len, "Conversion cancelled by user");
      free(offsets); fclose(fin); fclose(fout);
      unlink(out_ffpfsc_path);
      return -2;
    }

    size_t nread = fread(in_buf, 1, sizeof(in_buf), fin);
    if (nread == 0) break;

    /* If partial block, zero-pad remainder so logical block is always 64 KiB */
    if (nread < sizeof(in_buf)) {
      memset(in_buf + nread, 0, sizeof(in_buf) - nread);
    }

    offsets[b] = current_out_offset;

    /* Compress block via zlib */
    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    if (deflateInit(&strm, Z_DEFAULT_COMPRESSION) != Z_OK) {
      snprintf(err_msg, err_len, "deflateInit failed");
      free(offsets); fclose(fin); fclose(fout);
      unlink(out_ffpfsc_path);
      return -1;
    }

    strm.avail_in = sizeof(in_buf);
    strm.next_in = in_buf;
    strm.avail_out = sizeof(out_buf);
    strm.next_out = out_buf;

    int ret = deflate(&strm, Z_FINISH);
    size_t comp_sz = sizeof(out_buf) - strm.avail_out;
    deflateEnd(&strm);

    if (ret != Z_STREAM_END || comp_sz >= sizeof(in_buf)) {
      /* Store uncompressed block directly as a full 64 KiB block */
      if (fwrite(in_buf, 1, sizeof(in_buf), fout) != sizeof(in_buf)) {
        free(offsets); fclose(fin); fclose(fout);
        unlink(out_ffpfsc_path);
        return -1;
      }
      current_out_offset += sizeof(in_buf);
    } else {
      if (fwrite(out_buf, 1, comp_sz, fout) != comp_sz) {
        free(offsets); fclose(fin); fclose(fout);
        unlink(out_ffpfsc_path);
        return -1;
      }
      current_out_offset += comp_sz;
    }

    processed_in += nread;
    if (progress_cb) progress_cb(total_input_size, processed_in, user_data);
  }

  offsets[block_count] = current_out_offset;

  /* 2. Write Header at offset 0 */
  uint8_t hdr[PFSC_HEADER_SIZE];
  memset(hdr, 0, sizeof(hdr));
  hdr[0] = 'P'; hdr[1] = 'F'; hdr[2] = 'S'; hdr[3] = 'C'; /* 0x43534650 */
  hdr[8] = 6;
  /* Logical block size */
  hdr[16] = 0; hdr[17] = 0; hdr[18] = 1; hdr[19] = 0; /* 0x10000 = 64 KiB LE */
  hdr[20] = 0; hdr[21] = 0; hdr[22] = 1; hdr[23] = 0;
  /* Block count */
  uint32_t boff_ptr = PFSC_BLOCK_OFFSETS_OFFSET;
  uint32_t data_off_ptr = (uint32_t)initial_data_offset;
  memcpy(hdr + 24, &boff_ptr, 4);
  memcpy(hdr + 28, &data_off_ptr, 4);
  memcpy(hdr + 32, &logical_size, 8);

  if (fseek(fout, 0, SEEK_SET) != 0 || fwrite(hdr, 1, sizeof(hdr), fout) != sizeof(hdr)) {
    snprintf(err_msg, err_len, "Failed writing PFSC header");
    free(offsets); fclose(fin); fclose(fout);
    unlink(out_ffpfsc_path);
    return -1;
  }

  /* 3. Write Offset Table starting at 0x400 */
  if (fseek(fout, PFSC_BLOCK_OFFSETS_OFFSET, SEEK_SET) != 0) {
    snprintf(err_msg, err_len, "Failed seeking to block offset table");
    free(offsets); fclose(fin); fclose(fout);
    unlink(out_ffpfsc_path);
    return -1;
  }
  for (uint32_t b = 0; b <= block_count; b++) {
    if (fwrite(&offsets[b], sizeof(uint64_t), 1, fout) != 1) {
      snprintf(err_msg, err_len, "Failed writing offset table");
      free(offsets); fclose(fin); fclose(fout);
      unlink(out_ffpfsc_path);
      return -1;
    }
  }

  free(offsets);
  fclose(fin);
  if (fclose(fout) != 0) {
    snprintf(err_msg, err_len, "Failed flushing output file: %s", strerror(errno));
    unlink(out_ffpfsc_path);
    return -1;
  }
  return 0;
}

int run_conversion(const char *source_path, const char *dest_path, const char *format_str,
                   convert_progress_cb progress_cb, convert_cancel_cb cancel_cb,
                   void *user_data, char *err_msg, size_t err_len) {
  struct stat st;
  if (stat(source_path, &st) != 0) {
    snprintf(err_msg, err_len, "Source path does not exist: %s", strerror(errno));
    return -1;
  }

  bool is_exfat_target = (format_str && !strcasecmp(format_str, "exfat"));

  /* Path construction for output */
  char target_file[4096];
  const char *base = strrchr(source_path, '/');
  base = base ? base + 1 : source_path;
  char clean_name[256];
  strncpy(clean_name, base, sizeof(clean_name) - 1);
  clean_name[sizeof(clean_name) - 1] = '\0';
  char *ext = strrchr(clean_name, '.');
  if (ext) *ext = '\0';

  if (is_exfat_target) {
    snprintf(target_file, sizeof(target_file), "%s/%s.exfat", dest_path, clean_name);
  } else {
    snprintf(target_file, sizeof(target_file), "%s/%s.ffpfsc", dest_path, clean_name);
  }

  if (S_ISDIR(st.st_mode)) {
    if (is_exfat_target) {
      /* Direct folder -> .exfat */
      return convert_folder_to_exfat(source_path, target_file, progress_cb, cancel_cb,
                                     user_data, err_msg, err_len);
    } else {
      /* Folder -> .ffpfsc: generate exfat in streaming pipeline */
      char temp_exfat[4096];
      snprintf(temp_exfat, sizeof(temp_exfat), "%s/%s.tmp.exfat", dest_path, clean_name);
      int ret = convert_folder_to_exfat(source_path, temp_exfat, progress_cb, cancel_cb,
                                        user_data, err_msg, err_len);
      if (ret != 0) return ret;

      ret = convert_image_to_ffpfsc(temp_exfat, target_file, progress_cb, cancel_cb,
                                    user_data, err_msg, err_len);
      unlink(temp_exfat);
      return ret;
    }
  } else {
    /* If source is an exfat/raw image file and target is ffpfsc */
    if (!is_exfat_target) {
      return convert_image_to_ffpfsc(source_path, target_file, progress_cb, cancel_cb,
                                     user_data, err_msg, err_len);
    } else {
      /* Direct copy / repack */
      snprintf(err_msg, err_len, "Source is already an image file; cannot convert to exfat");
      return -1;
    }
  }
}
