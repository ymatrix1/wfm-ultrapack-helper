#include "convert_engine.h"
#include "pkg_reader.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pthread.h>
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

/* Compress one full 64 KiB logical block (reusing strm). Returns the number of bytes the block
 * occupies in the output and sets *stored when the raw block must be written instead (it did not
 * shrink below 64 KiB, or deflate failed). */
static size_t pfsc_compress_block(z_stream *strm, const uint8_t *in_buf, uint8_t *out_buf, int *stored) {
  deflateReset(strm);
  strm->avail_in = PFSC_LOGICAL_BLOCK_SIZE;
  strm->next_in = (Bytef *)in_buf;
  strm->avail_out = PFSC_LOGICAL_BLOCK_SIZE * 2;
  strm->next_out = out_buf;

  int ret = deflate(strm, Z_FINISH);
  size_t comp_sz = (PFSC_LOGICAL_BLOCK_SIZE * 2) - strm->avail_out;

  if (ret != Z_STREAM_END || comp_sz >= PFSC_LOGICAL_BLOCK_SIZE) {
    *stored = 1;
    return PFSC_LOGICAL_BLOCK_SIZE;
  }
  *stored = 0;
  return comp_sz;
}

/* Write an already compressed (or stored) block; advances *out_off. */
static int pfsc_write_block(const uint8_t *in_buf, const uint8_t *out_buf, size_t sz, int stored,
                            FILE *fout, uint64_t *out_off, char *err_msg, size_t err_len) {
  if (stored) {
    if (fwrite(in_buf, 1, PFSC_LOGICAL_BLOCK_SIZE, fout) != PFSC_LOGICAL_BLOCK_SIZE) {
      snprintf(err_msg, err_len, "Failed writing block to disk (disk full?): %s", strerror(errno));
      return -1;
    }
  } else if (fwrite(out_buf, 1, sz, fout) != sz) {
    snprintf(err_msg, err_len, "Failed writing compressed block (disk full?): %s", strerror(errno));
    return -1;
  }
  *out_off += sz;
  return 0;
}

/* Compress one full 64 KiB logical block (reusing strm) and write it; advances *out_off. */
static int pfsc_emit_block(z_stream *strm, const uint8_t *in_buf, uint8_t *out_buf,
                           FILE *fout, uint64_t *out_off, char *err_msg, size_t err_len) {
  int stored;
  size_t sz = pfsc_compress_block(strm, in_buf, out_buf, &stored);
  return pfsc_write_block(in_buf, out_buf, sz, stored, fout, out_off, err_msg, err_len);
}

enum { SLOT_FREE = 0, SLOT_QUEUED, SLOT_DONE };

typedef struct {
  uint8_t *in;
  uint8_t *out;
  size_t sz;
  int stored;
  int state;
} pfsc_slot_t;

struct pfsc_sink;

typedef struct {
  struct pfsc_sink *s;
} pfsc_worker_arg_t;

typedef struct pfsc_sink {
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

  /* Multithreaded mode (nthreads > 1): ring of slots, slot index = block sequence % nslots.
   * Only the sink thread fills slots (FREE -> QUEUED), writes output and frees them (DONE -> FREE);
   * workers claim blocks in sequence order and mark them DONE. */
  int nthreads;
  int nstarted;
  uint32_t nslots;
  pfsc_slot_t *slots;
  pthread_t *threads;
  pfsc_worker_arg_t warg;
  pthread_mutex_t mu;
  pthread_cond_t work_cv;
  pthread_cond_t done_cv;
  bool sync_init;
  bool stop;
  bool worker_failed;
  uint32_t submitted;   /* blocks handed to the queue */
  uint32_t next_claim;  /* next block a worker will take */
  uint32_t next_emit;   /* next block to be written to disk */
} pfsc_sink_t;

static int pfsc_thread_count(void) {
  const char *e = getenv("WUP_THREADS");
  long n = 0;
  if (e && *e) {
    char *end = NULL;
    n = strtol(e, &end, 10);
    if (end == e || n < 1) n = 0;
  }
  if (n == 0) {
    long cpu = sysconf(_SC_NPROCESSORS_ONLN);
    n = cpu - 1;
    if (n > 8) n = 8;
    if (n < 1) n = 1;
  }
  if (n > 64) n = 64;
  return (int)n;
}

static void *pfsc_worker_main(void *arg) {
  pfsc_sink_t *s = ((pfsc_worker_arg_t *)arg)->s;
  z_stream strm;
  memset(&strm, 0, sizeof(strm));
  if (deflateInit(&strm, Z_DEFAULT_COMPRESSION) != Z_OK) {
    pthread_mutex_lock(&s->mu);
    s->worker_failed = true;
    pthread_cond_broadcast(&s->done_cv);
    pthread_mutex_unlock(&s->mu);
    return NULL;
  }
  pthread_mutex_lock(&s->mu);
  for (;;) {
    while (!s->stop && s->next_claim >= s->submitted) pthread_cond_wait(&s->work_cv, &s->mu);
    if (s->stop) break;
    pfsc_slot_t *sl = &s->slots[s->next_claim % s->nslots];
    s->next_claim++;
    pthread_mutex_unlock(&s->mu);
    int stored;
    size_t sz = pfsc_compress_block(&strm, sl->in, sl->out, &stored);
    pthread_mutex_lock(&s->mu);
    sl->sz = sz;
    sl->stored = stored;
    sl->state = SLOT_DONE;
    pthread_cond_broadcast(&s->done_cv);
  }
  pthread_mutex_unlock(&s->mu);
  deflateEnd(&strm);
  return NULL;
}

/* Stops and joins all workers (safe to call repeatedly), then releases everything. */
static void pfsc_sink_free(pfsc_sink_t *s) {
  if (s->sync_init) {
    pthread_mutex_lock(&s->mu);
    s->stop = true;
    pthread_cond_broadcast(&s->work_cv);
    pthread_mutex_unlock(&s->mu);
    for (int i = 0; i < s->nstarted; i++) pthread_join(s->threads[i], NULL);
    s->nstarted = 0;
    pthread_cond_destroy(&s->work_cv);
    pthread_cond_destroy(&s->done_cv);
    pthread_mutex_destroy(&s->mu);
    s->sync_init = false;
  }
  if (s->slots) {
    for (uint32_t i = 0; i < s->nslots; i++) { free(s->slots[i].in); free(s->slots[i].out); }
  }
  free(s->slots); free(s->threads);
  s->slots = NULL; s->threads = NULL;
  if (s->zinit) deflateEnd(&s->strm);
  s->zinit = false;
  free(s->in_buf); free(s->out_buf); free(s->offsets);
  s->in_buf = s->out_buf = NULL;
  s->offsets = NULL;
}

/* Allocate the slot ring and start the workers. Returns 0 on success; on failure the caller
 * releases everything and falls back to the serial path. */
static int pfsc_mt_start(pfsc_sink_t *s, int nthreads) {
  s->nslots = (uint32_t)nthreads * 8;
  if (s->nslots > 256) s->nslots = 256;
  if (s->nslots < 8) s->nslots = 8;
  s->slots = (pfsc_slot_t *)calloc(s->nslots, sizeof(pfsc_slot_t));
  s->threads = (pthread_t *)calloc((size_t)nthreads, sizeof(pthread_t));
  if (!s->slots || !s->threads) return -1;
  for (uint32_t i = 0; i < s->nslots; i++) {
    s->slots[i].in = (uint8_t *)malloc(PFSC_LOGICAL_BLOCK_SIZE);
    s->slots[i].out = (uint8_t *)malloc(PFSC_LOGICAL_BLOCK_SIZE * 2);
    if (!s->slots[i].in || !s->slots[i].out) return -1;
  }
  if (pthread_mutex_init(&s->mu, NULL) != 0) return -1;
  if (pthread_cond_init(&s->work_cv, NULL) != 0) { pthread_mutex_destroy(&s->mu); return -1; }
  if (pthread_cond_init(&s->done_cv, NULL) != 0) {
    pthread_cond_destroy(&s->work_cv); pthread_mutex_destroy(&s->mu); return -1;
  }
  s->sync_init = true;
  s->warg.s = s;
  for (int i = 0; i < nthreads; i++) {
    if (pthread_create(&s->threads[s->nstarted], NULL, pfsc_worker_main, &s->warg) != 0) break;
    s->nstarted++;
  }
  if (s->nstarted == 0) return -1;
  s->nthreads = nthreads;
  return 0;
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

  int nthreads = pfsc_thread_count();
  if ((uint64_t)nthreads > s->block_count) nthreads = (int)s->block_count;
  if (nthreads > 1 && pfsc_mt_start(s, nthreads) != 0) {
    /* Could not set up threading: tear it down and use the legacy serial path. */
    pfsc_sink_free(s);
    s->stop = false;
    s->nthreads = 1;
  }

  s->offsets = (uint64_t *)calloc((size_t)s->block_count + 1, sizeof(uint64_t));
  if (!s->offsets) {
    snprintf(s->err, sizeof(s->err), "Out of memory for PFSC buffers (%u blocks)", s->block_count);
    return -1;
  }

  if (s->nthreads <= 1) {
    s->nthreads = 1;
    s->in_buf = (uint8_t *)malloc(PFSC_LOGICAL_BLOCK_SIZE);
    s->out_buf = (uint8_t *)malloc(PFSC_LOGICAL_BLOCK_SIZE * 2);
    if (!s->in_buf || !s->out_buf) {
      snprintf(s->err, sizeof(s->err), "Out of memory for PFSC buffers (%u blocks)", s->block_count);
      return -1;
    }
    memset(&s->strm, 0, sizeof(s->strm));
    if (deflateInit(&s->strm, Z_DEFAULT_COMPRESSION) != Z_OK) {
      snprintf(s->err, sizeof(s->err), "deflateInit failed");
      return -1;
    }
    s->zinit = true;
  }

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

/* MT: write the next in-order block if its slot is DONE. Caller holds s->mu (dropped around the
 * write; only this thread touches a DONE slot). Returns 1 emitted, 0 not ready, -1 error. */
static int pfsc_mt_try_emit(pfsc_sink_t *s) {
  pfsc_slot_t *sl = &s->slots[s->next_emit % s->nslots];
  if (sl->state != SLOT_DONE) return 0;
  pthread_mutex_unlock(&s->mu);
  s->offsets[s->next_emit] = s->cur_off;
  int rc = pfsc_write_block(sl->in, sl->out, sl->sz, sl->stored, s->f, &s->cur_off, s->err, sizeof(s->err));
  pthread_mutex_lock(&s->mu);
  if (rc != 0) return -1;
  sl->state = SLOT_FREE;
  s->next_emit++;
  return 1;
}

/* MT: wait until the slot for the next block is free, emitting finished blocks meanwhile. */
static int pfsc_mt_acquire(pfsc_sink_t *s) {
  int rc = 0;
  pthread_mutex_lock(&s->mu);
  for (;;) {
    if (s->worker_failed) {
      snprintf(s->err, sizeof(s->err), "deflateInit failed in worker thread");
      rc = -1; break;
    }
    int e = pfsc_mt_try_emit(s);
    if (e < 0) { rc = -1; break; }
    if (e > 0) continue;
    if (s->slots[s->next_block % s->nslots].state == SLOT_FREE) break;
    pthread_cond_wait(&s->done_cv, &s->mu);
  }
  pthread_mutex_unlock(&s->mu);
  return rc;
}

/* MT: hand the filled block to the workers. */
static void pfsc_mt_submit(pfsc_sink_t *s) {
  pthread_mutex_lock(&s->mu);
  s->slots[s->next_block % s->nslots].state = SLOT_QUEUED;
  s->submitted++;
  pthread_cond_signal(&s->work_cv);
  pthread_mutex_unlock(&s->mu);
}

/* MT: write every outstanding block, in order. */
static int pfsc_mt_drain(pfsc_sink_t *s) {
  int rc = 0;
  pthread_mutex_lock(&s->mu);
  while (s->next_emit < s->submitted) {
    if (s->worker_failed) {
      snprintf(s->err, sizeof(s->err), "deflateInit failed in worker thread");
      rc = -1; break;
    }
    int e = pfsc_mt_try_emit(s);
    if (e < 0) { rc = -1; break; }
    if (e == 0) pthread_cond_wait(&s->done_cv, &s->mu);
  }
  pthread_mutex_unlock(&s->mu);
  return rc;
}

static uint8_t *pfsc_cur_in(pfsc_sink_t *s) {
  return s->nthreads > 1 ? s->slots[s->next_block % s->nslots].in : s->in_buf;
}

static int pfsc_sink_flush_block(pfsc_sink_t *s) {
  if (s->nthreads > 1) {
    pfsc_mt_submit(s);
    s->next_block++;
    s->fill = 0;
    return 0;
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
    if (s->fill == 0) {
      if (s->next_block >= s->block_count) {
        snprintf(s->err, sizeof(s->err), "Image larger than declared size");
        return -1;
      }
      if (s->nthreads > 1 && pfsc_mt_acquire(s) != 0) return -1;
    }
    size_t room = PFSC_LOGICAL_BLOCK_SIZE - s->fill;
    size_t n = (len < room) ? len : room;
    memcpy(pfsc_cur_in(s) + s->fill, p, n);
    s->fill += n; p += n; len -= n;
    if (s->fill == PFSC_LOGICAL_BLOCK_SIZE && pfsc_sink_flush_block(s) != 0) return -1;
  }
  return 0;
}

/* Zero-pad and flush the last partial block, then backpatch header + offset table. */
static int pfsc_sink_finish(pfsc_sink_t *s) {
  if (s->fill > 0) {
    memset(pfsc_cur_in(s) + s->fill, 0, PFSC_LOGICAL_BLOCK_SIZE - s->fill);
    if (pfsc_sink_flush_block(s) != 0) return -1;
  }
  if (s->nthreads > 1 && pfsc_mt_drain(s) != 0) return -1;
  if (s->next_block != s->block_count) {
    snprintf(s->err, sizeof(s->err), "Image shorter than declared size (%u of %u blocks)",
             s->next_block, s->block_count);
    return -1;
  }
  s->offsets[s->block_count] = s->cur_off;
  return pfsc_write_header(s->f, s->offsets, s->block_count, s->initial_data_offset,
                           s->logical_size, s->err, sizeof(s->err));
}

/* Raw image file -> .ffpfsc through the same (optionally multithreaded) sink as the exFAT streams. */
#define PFSC_IMAGE_CHUNK (1024 * 1024)

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

  pfsc_sink_t *s = (pfsc_sink_t *)calloc(1, sizeof(*s));
  uint8_t *chunk = (uint8_t *)malloc(PFSC_IMAGE_CHUNK);
  if (!s || !chunk) {
    snprintf(err_msg, err_len, "Out of memory");
    free(s); free(chunk); fclose(fin);
    return -1;
  }
  s->f = fopen(out_ffpfsc_path, "wb+");
  if (!s->f) {
    snprintf(err_msg, err_len, "Cannot create target .ffpfsc: %s", strerror(errno));
    free(s); free(chunk); fclose(fin);
    return -1;
  }

  int ret = pfsc_sink_begin(total_input_size, s);
  uint64_t done = 0;
  while (ret == 0 && done < total_input_size) {
    if (cancel_cb && cancel_cb(user_data)) {
      snprintf(s->err, sizeof(s->err), "Conversion cancelled by user");
      ret = -2;
      break;
    }
    uint64_t want = total_input_size - done;
    size_t n = fread(chunk, 1, want < PFSC_IMAGE_CHUNK ? (size_t)want : PFSC_IMAGE_CHUNK, fin);
    if (n == 0) {
      if (ferror(fin)) snprintf(s->err, sizeof(s->err), "Error reading source image: %s", strerror(errno));
      else snprintf(s->err, sizeof(s->err), "Source image shrank while converting");
      ret = -1;
      break;
    }
    if (pfsc_sink_write(chunk, n, s) != 0) { ret = -1; break; }
    done += n;
    if (progress_cb) progress_cb(total_input_size, done, user_data);
  }
  if (ret == 0 && pfsc_sink_finish(s) != 0) ret = -1;
  if (ret != 0 && s->err[0]) snprintf(err_msg, err_len, "%s", s->err);
  pfsc_sink_free(s);
  free(chunk);
  fclose(fin);
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
  return 0;
}

/* Zero-staging .ffpfsc: an exFAT stream (folder or listing) feeds the PFSC encoder directly. */
typedef int (*ffpfsc_stream_fn)(void *run_ctx, exfat_begin_fn begin_fn, exfat_sink_fn sink_fn, void *sink_ctx,
                                convert_progress_cb progress_cb, convert_cancel_cb cancel_cb,
                                void *user_data, char *err_msg, size_t err_len);

static int stream_to_ffpfsc(const char *out_ffpfsc_path, ffpfsc_stream_fn run, void *run_ctx,
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

  int ret = run(run_ctx, pfsc_sink_begin, pfsc_sink_write, s, progress_cb, cancel_cb, user_data, err_msg, err_len);
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

static int run_folder_stream(void *run_ctx, exfat_begin_fn b, exfat_sink_fn s, void *sc,
                             convert_progress_cb p, convert_cancel_cb c, void *u, char *e, size_t el) {
  return convert_folder_to_exfat_stream((const char *)run_ctx, b, s, sc, p, c, u, e, el);
}

/* Folder -> .ffpfsc with no staging image: exFAT chunks stream straight into the PFSC encoder. */
static int convert_folder_to_ffpfsc(const char *source_dir, const char *out_ffpfsc_path,
                                    convert_progress_cb progress_cb, convert_cancel_cb cancel_cb,
                                    void *user_data, char *err_msg, size_t err_len) {
  return stream_to_ffpfsc(out_ffpfsc_path, run_folder_stream, (void *)source_dir, progress_cb, cancel_cb,
                          user_data, err_msg, err_len);
}

typedef struct {
  const exfat_listing_entry_t *entries;
  size_t count;
  const exfat_src_ops_t *ops;
  void *ops_ctx;
} listing_stream_t;

static int run_listing_stream(void *run_ctx, exfat_begin_fn b, exfat_sink_fn s, void *sc,
                              convert_progress_cb p, convert_cancel_cb c, void *u, char *e, size_t el) {
  const listing_stream_t *ls = (const listing_stream_t *)run_ctx;
  return convert_listing_to_exfat_stream(ls->entries, ls->count, ls->ops, ls->ops_ctx, b, s, sc, p, c, u, e, el);
}

int convert_listing_to_ffpfsc(const exfat_listing_entry_t *entries, size_t count,
                              const exfat_src_ops_t *ops, void *ops_ctx, const char *out_ffpfsc_path,
                              convert_progress_cb progress_cb, convert_cancel_cb cancel_cb,
                              void *user_data, char *err_msg, size_t err_len) {
  listing_stream_t ls = { entries, count, ops, ops_ctx };
  return stream_to_ffpfsc(out_ffpfsc_path, run_listing_stream, &ls, progress_cb, cancel_cb,
                          user_data, err_msg, err_len);
}

/* ---- PKG source: package -> pkg_reader -> listing -> exFAT [-> PFSC], zero staging ---- */

static int pkg_read_cb(void *ctx, uint64_t file_id, uint64_t offset, void *buf, size_t len) {
  int64_t n = pkgr_read((pkgr_t *)ctx, (size_t)file_id, offset, buf, len);
  return n < 0 ? -1 : (int)n;
}

static int convert_pkg(const char *pkg_path, const char *target_file, bool is_exfat,
                       const char *passcode,
                       convert_progress_cb progress_cb, convert_cancel_cb cancel_cb,
                       void *user_data, char *err_msg, size_t err_len) {
  pkgr_t *pkg = NULL;
  if (pkgr_open(pkg_path, passcode, &pkg, err_msg, err_len) != 0) {
    if (!err_msg[0]) snprintf(err_msg, err_len, "Cannot open package");
    return -1;
  }
  size_t n = pkgr_entry_count(pkg);
  exfat_listing_entry_t *list = (exfat_listing_entry_t *)calloc(n ? n : 1, sizeof(*list));
  if (!list) {
    pkgr_close(pkg);
    snprintf(err_msg, err_len, "Out of memory for package listing");
    return -1;
  }
  for (size_t i = 0; i < n; i++) {
    const pkgr_entry_t *e = pkgr_entry(pkg, i);
    list[i].path = e->path;
    list[i].size = e->size;
    list[i].is_dir = e->is_dir;
    list[i].file_id = i;
  }
  exfat_src_ops_t ops = { pkg_read_cb };
  int ret = is_exfat
    ? convert_listing_to_exfat(list, n, &ops, pkg, target_file, progress_cb, cancel_cb,
                               user_data, err_msg, err_len)
    : convert_listing_to_ffpfsc(list, n, &ops, pkg, target_file, progress_cb, cancel_cb,
                                user_data, err_msg, err_len);
  free(list);
  pkgr_close(pkg);
  return ret;
}

int run_conversion(const char *source_path, const char *dest_path, const char *format_str,
                   convert_progress_cb progress_cb, convert_cancel_cb cancel_cb,
                   void *user_data, char *err_msg, size_t err_len) {
  return run_conversion_ex(source_path, dest_path, format_str, NULL, progress_cb, cancel_cb,
                           user_data, err_msg, err_len);
}

int run_conversion_ex(const char *source_path, const char *dest_path, const char *format_str,
                      const char *passcode,
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
  snprintf(sanitized_source, sizeof(sanitized_source), "%s", source_path);
  size_t slen = strlen(sanitized_source);
  while (slen > 1 && sanitized_source[slen - 1] == '/') {
    sanitized_source[slen - 1] = '\0';
    slen--;
  }

  char target_file[4096];
  const char *base = strrchr(sanitized_source, '/');
  base = base ? base + 1 : sanitized_source;

  char clean_name[256];
  snprintf(clean_name, sizeof(clean_name), "%s", base); /* bounded, always terminated */

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
    /* A .pkg (CNT or native FIH magic) is read in place and streamed: no extraction, no temp image */
    {
      FILE *probe = fopen(sanitized_source, "rb");
      if (probe) {
        unsigned char magic[4] = {0};
        size_t got = fread(magic, 1, sizeof(magic), probe);
        fclose(probe);
        if (got == 4 && magic[0] == 0x7f && (!memcmp(magic + 1, "CNT", 3) || !memcmp(magic + 1, "FIH", 3))) {
          return convert_pkg(sanitized_source, target_file, is_exfat_target, passcode,
                             progress_cb, cancel_cb, user_data, err_msg, err_len);
        }
      }
    }
    /* If source is an exfat/raw image file and target is ffpfsc */
    if (!is_exfat_target) {
      return convert_image_to_ffpfsc(sanitized_source, target_file, progress_cb, cancel_cb,
                                     user_data, err_msg, err_len);
    } else {
      snprintf(err_msg, err_len, "Source is already an image file; cannot convert to exfat");
      return -1;
    }
  }
}
