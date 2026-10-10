#include "convert_engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include "miniz.h"

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

static uint64_t pfsc_data_offset(uint32_t block_count) {
  size_t table_bytes = (size_t)(block_count + 1) * sizeof(uint64_t);
  uint64_t off = PFSC_INITIAL_DATA_OFFSET;
  while (off < PFSC_BLOCK_OFFSETS_OFFSET + table_bytes) {
    off += PFSC_LOGICAL_BLOCK_SIZE;
  }
  return off;
}

/* Backpatch PFSC header and block offset table. Returns 0 or -1 (err_msg set). */
static int pfsc_write_header(FILE *fout, const uint64_t *offsets, uint32_t block_count,
                             uint64_t initial_data_offset, uint64_t logical_size,
                             char *err_msg, size_t err_len) {
  uint8_t hdr[PFSC_HEADER_SIZE];
  memset(hdr, 0, sizeof(hdr));
  hdr[0] = 'P'; hdr[1] = 'F'; hdr[2] = 'S'; hdr[3] = 'C'; /* 0x43534650 */
  hdr[8] = 6;
  put32_le(hdr + 0x0C, PFSC_LOGICAL_BLOCK_SIZE);
  put64_le(hdr + 0x10, PFSC_LOGICAL_BLOCK_SIZE);
  put64_le(hdr + 0x18, PFSC_BLOCK_OFFSETS_OFFSET);
  put64_le(hdr + 0x20, initial_data_offset);
  put64_le(hdr + 0x28, logical_size);

  if (fseek(fout, 0, SEEK_SET) != 0 || fwrite(hdr, 1, sizeof(hdr), fout) != sizeof(hdr)) {
    snprintf(err_msg, err_len, "Failed writing PFSC header: %s", strerror(errno));
    return -1;
  }
  if (fseek(fout, PFSC_BLOCK_OFFSETS_OFFSET, SEEK_SET) != 0) {
    snprintf(err_msg, err_len, "Failed seeking to block offset table: %s", strerror(errno));
    return -1;
  }
  for (uint32_t b = 0; b <= block_count; b++) {
    uint8_t obuf[8];
    put64_le(obuf, offsets[b]);
    if (fwrite(obuf, 1, 8, fout) != 8) {
      snprintf(err_msg, err_len, "Failed writing offset table: %s", strerror(errno));
      return -1;
    }
  }
  return 0;
}

/* Compress one full 64 KiB logical block (reusing strm) and write it; advances *out_off. */
static int pfsc_emit_block(z_stream *strm, const uint8_t *in_buf, uint8_t *out_buf,
                           FILE *fout, uint64_t *out_off, char *err_msg, size_t err_len) {
  deflateReset(strm);
  strm->avail_in = PFSC_LOGICAL_BLOCK_SIZE;
  strm->next_in = (Bytef *)in_buf;
  strm->avail_out = PFSC_LOGICAL_BLOCK_SIZE * 2;
  strm->next_out = out_buf;

  int ret = deflate(strm, Z_FINISH);
  size_t comp_sz = (PFSC_LOGICAL_BLOCK_SIZE * 2) - strm->avail_out;

  if (ret != Z_STREAM_END || comp_sz >= PFSC_LOGICAL_BLOCK_SIZE) {
    /* Store uncompressed block directly as a full 64 KiB block */
    if (fwrite(in_buf, 1, PFSC_LOGICAL_BLOCK_SIZE, fout) != PFSC_LOGICAL_BLOCK_SIZE) {
      snprintf(err_msg, err_len, "Failed writing block to disk (disk full?): %s", strerror(errno));
      return -1;
    }
    *out_off += PFSC_LOGICAL_BLOCK_SIZE;
  } else {
    if (fwrite(out_buf, 1, comp_sz, fout) != comp_sz) {
      snprintf(err_msg, err_len, "Failed writing compressed block (disk full?): %s", strerror(errno));
      return -1;
    }
    *out_off += comp_sz;
  }
  return 0;
}

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
  if (total_input_size == 0) {
    snprintf(err_msg, err_len, "Source image is empty (0 bytes)");
    fclose(fin);
    return -1;
  }

  uint32_t block_count = (uint32_t)((total_input_size + PFSC_LOGICAL_BLOCK_SIZE - 1) / PFSC_LOGICAL_BLOCK_SIZE);
  uint64_t logical_size = (uint64_t)block_count * PFSC_LOGICAL_BLOCK_SIZE;

  /* Dynamically size initial data offset so table never overflows */
  uint64_t initial_data_offset = pfsc_data_offset(block_count);

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
      snprintf(err_msg, err_len, "Failed writing header padding: %s", strerror(errno));
      fclose(fin); fclose(fout);
      unlink(out_ffpfsc_path);
      return -1;
    }
    header_pad -= p;
  }

  /* Allocate table for block offsets */
  uint64_t *offsets = (uint64_t *)calloc(block_count + 1, sizeof(uint64_t));
  if (!offsets) {
    snprintf(err_msg, err_len, "Out of memory for block table (%u blocks)", block_count);
    fclose(fin); fclose(fout);
    unlink(out_ffpfsc_path);
    return -1;
  }

  /* Allocate 64 KiB / 128 KiB compression buffers on heap */
  uint8_t *in_buf = (uint8_t *)malloc(PFSC_LOGICAL_BLOCK_SIZE);
  uint8_t *out_buf = (uint8_t *)malloc(PFSC_LOGICAL_BLOCK_SIZE * 2);
  if (!in_buf || !out_buf) {
    snprintf(err_msg, err_len, "Out of memory for zlib buffers");
    free(in_buf); free(out_buf); free(offsets);
    fclose(fin); fclose(fout); unlink(out_ffpfsc_path);
    return -1;
  }

  uint64_t current_out_offset = initial_data_offset;
  uint64_t processed_in = 0;

  z_stream strm;
  memset(&strm, 0, sizeof(strm));
  if (deflateInit(&strm, Z_DEFAULT_COMPRESSION) != Z_OK) {
    snprintf(err_msg, err_len, "deflateInit failed");
    free(in_buf); free(out_buf); free(offsets);
    fclose(fin); fclose(fout); unlink(out_ffpfsc_path);
    return -1;
  }

  int convert_res = 0;

  for (uint32_t b = 0; b < block_count; b++) {
    if (cancel_cb && cancel_cb(user_data)) {
      snprintf(err_msg, err_len, "Conversion cancelled by user");
      convert_res = -2;
      break;
    }

    size_t nread = fread(in_buf, 1, PFSC_LOGICAL_BLOCK_SIZE, fin);
    if (nread == 0 && ferror(fin)) {
      snprintf(err_msg, err_len, "Error reading source image: %s", strerror(errno));
      convert_res = -1;
      break;
    }

    /* If partial block, zero-pad remainder so logical block is always 64 KiB */
    if (nread < PFSC_LOGICAL_BLOCK_SIZE) {
      memset(in_buf + nread, 0, PFSC_LOGICAL_BLOCK_SIZE - nread);
    }

    offsets[b] = current_out_offset;

    if (pfsc_emit_block(&strm, in_buf, out_buf, fout, &current_out_offset, err_msg, err_len) != 0) {
      convert_res = -1;
      break;
    }

    processed_in += nread;
    if (progress_cb) progress_cb(total_input_size, processed_in, user_data);
  }

  deflateEnd(&strm);
  free(in_buf);
  free(out_buf);

  if (convert_res != 0) {
    free(offsets); fclose(fin); fclose(fout);
    unlink(out_ffpfsc_path);
    return convert_res;
  }

  offsets[block_count] = current_out_offset;

  if (pfsc_write_header(fout, offsets, block_count, initial_data_offset, logical_size, err_msg, err_len) != 0) {
    free(offsets); fclose(fin); fclose(fout);
    unlink(out_ffpfsc_path);
    return -1;
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

typedef struct {
  FILE *f;
  uint8_t *in_buf;
  uint8_t *out_buf;
  uint64_t *offsets;
  size_t fill;
  uint32_t block_count;
  uint32_t next_block;
  uint64_t total_bytes;
  uint64_t initial_data_offset;
  uint64_t cur_off;
  uint64_t logical_size;
  z_stream strm;
  bool zinit;
  char err[256];
} pfsc_sink_t;

static void pfsc_sink_free(pfsc_sink_t *s) {
  if (s->zinit) deflateEnd(&s->strm);
  s->zinit = false;
  free(s->in_buf); free(s->out_buf); free(s->offsets);
  s->in_buf = s->out_buf = NULL;
  s->offsets = NULL;
}

/* Called once with the exact image size: reserves header area and allocates state. */
static int pfsc_sink_begin(uint64_t total_bytes, void *ctx) {
  pfsc_sink_t *s = (pfsc_sink_t *)ctx;
  if (total_bytes == 0) {
    snprintf(s->err, sizeof(s->err), "Generated image is empty (0 bytes)");
    return -1;
  }
  s->total_bytes = total_bytes;
  s->block_count = (uint32_t)((total_bytes + PFSC_LOGICAL_BLOCK_SIZE - 1) / PFSC_LOGICAL_BLOCK_SIZE);
  s->logical_size = (uint64_t)s->block_count * PFSC_LOGICAL_BLOCK_SIZE;
  s->initial_data_offset = pfsc_data_offset(s->block_count);
  s->cur_off = s->initial_data_offset;

  s->offsets = (uint64_t *)calloc((size_t)s->block_count + 1, sizeof(uint64_t));
  s->in_buf = (uint8_t *)malloc(PFSC_LOGICAL_BLOCK_SIZE);
  s->out_buf = (uint8_t *)malloc(PFSC_LOGICAL_BLOCK_SIZE * 2);
  if (!s->offsets || !s->in_buf || !s->out_buf) {
    snprintf(s->err, sizeof(s->err), "Out of memory for PFSC buffers (%u blocks)", s->block_count);
    return -1;
  }
  memset(&s->strm, 0, sizeof(s->strm));
  if (deflateInit(&s->strm, Z_DEFAULT_COMPRESSION) != Z_OK) {
    snprintf(s->err, sizeof(s->err), "deflateInit failed");
    return -1;
  }
  s->zinit = true;

  uint8_t zero_buf[4096] = {0};
  uint64_t pad = s->initial_data_offset;
  while (pad > 0) {
    size_t p = (pad > sizeof(zero_buf)) ? sizeof(zero_buf) : (size_t)pad;
    if (fwrite(zero_buf, 1, p, s->f) != p) {
      snprintf(s->err, sizeof(s->err), "Failed writing header padding: %s", strerror(errno));
      return -1;
    }
    pad -= p;
  }
  return 0;
}

static int pfsc_sink_flush_block(pfsc_sink_t *s) {
  if (s->next_block >= s->block_count) {
    snprintf(s->err, sizeof(s->err), "Image larger than declared size");
    return -1;
  }
  s->offsets[s->next_block] = s->cur_off;
  if (pfsc_emit_block(&s->strm, s->in_buf, s->out_buf, s->f, &s->cur_off, s->err, sizeof(s->err)) != 0) {
    return -1;
  }
  s->next_block++;
  s->fill = 0;
  return 0;
}

static int pfsc_sink_write(const void *buf, size_t len, void *ctx) {
  pfsc_sink_t *s = (pfsc_sink_t *)ctx;
  const uint8_t *p = (const uint8_t *)buf;
  while (len > 0) {
    size_t room = PFSC_LOGICAL_BLOCK_SIZE - s->fill;
    size_t n = (len < room) ? len : room;
    memcpy(s->in_buf + s->fill, p, n);
    s->fill += n; p += n; len -= n;
    if (s->fill == PFSC_LOGICAL_BLOCK_SIZE && pfsc_sink_flush_block(s) != 0) return -1;
  }
  return 0;
}

/* Zero-pad and flush the last partial block, then backpatch header + offset table. */
static int pfsc_sink_finish(pfsc_sink_t *s) {
  if (s->fill > 0) {
    memset(s->in_buf + s->fill, 0, PFSC_LOGICAL_BLOCK_SIZE - s->fill);
    if (pfsc_sink_flush_block(s) != 0) return -1;
  }
  if (s->next_block != s->block_count) {
    snprintf(s->err, sizeof(s->err), "Image shorter than declared size (%u of %u blocks)",
             s->next_block, s->block_count);
    return -1;
  }
  s->offsets[s->block_count] = s->cur_off;
  return pfsc_write_header(s->f, s->offsets, s->block_count, s->initial_data_offset,
                           s->logical_size, s->err, sizeof(s->err));
}

/* Folder -> .ffpfsc with no staging image: exFAT chunks stream straight into the PFSC encoder. */
static int convert_folder_to_ffpfsc(const char *source_dir, const char *out_ffpfsc_path,
                                    convert_progress_cb progress_cb, convert_cancel_cb cancel_cb,
                                    void *user_data, char *err_msg, size_t err_len) {
  pfsc_sink_t *s = (pfsc_sink_t *)calloc(1, sizeof(*s));
  if (!s) {
    snprintf(err_msg, err_len, "Out of memory");
    return -1;
  }
  s->f = fopen(out_ffpfsc_path, "wb+");
  if (!s->f) {
    snprintf(err_msg, err_len, "Cannot create target .ffpfsc: %s", strerror(errno));
    free(s);
    return -1;
  }

  int ret = convert_folder_to_exfat_stream(source_dir, pfsc_sink_begin, pfsc_sink_write, s,
                                           progress_cb, cancel_cb, user_data, err_msg, err_len);
  if (ret == 0 && pfsc_sink_finish(s) != 0) ret = -1;
  if (ret == -1 && s->err[0]) snprintf(err_msg, err_len, "%s", s->err);
  uint64_t total = s->total_bytes;
  pfsc_sink_free(s);
  int close_rc = fclose(s->f);
  if (ret == 0 && close_rc != 0) {
    snprintf(err_msg, err_len, "Failed flushing output file: %s", strerror(errno));
    ret = -1;
  }
  free(s);
  if (ret != 0) {
    unlink(out_ffpfsc_path);
    return ret;
  }
  if (progress_cb) progress_cb(total, total, user_data);
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
  bool is_ffpfsc_target = (!format_str || !strcasecmp(format_str, "ffpfsc") || !strcasecmp(format_str, "default"));

  if (!is_exfat_target && !is_ffpfsc_target) {
    snprintf(err_msg, err_len, "Unsupported target format '%s'", format_str ? format_str : "");
    return -1;
  }

  /* Sanitize source name: strip trailing slashes */
  char sanitized_source[4096];
  strncpy(sanitized_source, source_path, sizeof(sanitized_source) - 1);
  sanitized_source[sizeof(sanitized_source) - 1] = '\0';
  size_t slen = strlen(sanitized_source);
  while (slen > 1 && sanitized_source[slen - 1] == '/') {
    sanitized_source[slen - 1] = '\0';
    slen--;
  }

  char target_file[4096];
  const char *base = strrchr(sanitized_source, '/');
  base = base ? base + 1 : sanitized_source;

  char clean_name[256];
  strncpy(clean_name, base, sizeof(clean_name) - 1);
  clean_name[sizeof(clean_name) - 1] = '\0';

  /* Only strip recognized image/pkg file extension if regular file */
  if (!S_ISDIR(st.st_mode)) {
    char *ext = strrchr(clean_name, '.');
    if (ext && (!strcasecmp(ext, ".pkg") || !strcasecmp(ext, ".exfat") || !strcasecmp(ext, ".img") || !strcasecmp(ext, ".iso"))) {
      *ext = '\0';
    }
  }

  if (is_exfat_target) {
    snprintf(target_file, sizeof(target_file), "%s/%s.exfat", dest_path, clean_name);
  } else {
    snprintf(target_file, sizeof(target_file), "%s/%s.ffpfsc", dest_path, clean_name);
  }

  if (S_ISDIR(st.st_mode)) {
    if (is_exfat_target) {
      /* Direct folder -> .exfat */
      return convert_folder_to_exfat(sanitized_source, target_file, progress_cb, cancel_cb,
                                     user_data, err_msg, err_len);
    } else {
      /* Folder -> .ffpfsc: zero-staging, exFAT stream feeds the PFSC encoder directly */
      return convert_folder_to_ffpfsc(sanitized_source, target_file, progress_cb, cancel_cb,
                                      user_data, err_msg, err_len);
    }
  } else {
    /* If source is an exfat/raw image file and target is ffpfsc */
    if (!is_exfat_target) {
      /* A .pkg is not a filesystem image: compressing it would silently produce
       * a container that cannot be mounted. Reject until PKG extraction exists. */
      FILE *probe = fopen(sanitized_source, "rb");
      if (probe) {
        unsigned char magic[4] = {0};
        size_t got = fread(magic, 1, sizeof(magic), probe);
        fclose(probe);
        if (got == 4 && !memcmp(magic, "" "CNT", 4)) {
          snprintf(err_msg, err_len,
                   "PKG packages are not supported yet; extract to a folder, then convert the folder");
          return -1;
        }
      }
      return convert_image_to_ffpfsc(sanitized_source, target_file, progress_cb, cancel_cb,
                                     user_data, err_msg, err_len);
    } else {
      snprintf(err_msg, err_len, "Source is already an image file; cannot convert to exfat");
      return -1;
    }
  }
}
