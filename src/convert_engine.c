#include "convert_engine.h"
#include "pkg_reader.h"
#include <time.h>
#if defined(__FreeBSD__) || defined(__PROSPERO__) || defined(__SCE__)
#include <sys/param.h>
#include <sys/cpuset.h>
#define WUP_HAVE_CPUSET 1
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

static double mono_s(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

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

/* ---- PFS wrapper: the .ffpfsc is a PFS image (unsigned, unencrypted, 64 KiB blocks, 32-bit inodes)
 * holding ONE inner file whose data is a PFSC container. Layout mirrors ultrapack's
 * build_pfs_stream_from_exfat; the front metadata is fixed-size so the payload base is a constant:
 *   block 0 header | 1 inode table | 2 super_root dirents | 3 flat_path_table | 4 reserved empty |
 *   5 uroot dirents | 6.. PFSC container (header 0x30, offset table at +0x400, zlib blocks).
 * All PFSC offsets are relative to the start of the PFSC container (block 6). */
#define PFS_BLOCK_SIZE 0x10000U
#define PFS_MAGIC_VALUE 20130315
#define PFS_VERSION_PS5 2
#define PFS_MODE_CASE_INSENSITIVE 0x8U
#define PFS_INODE_COUNT 4
#define PFS_INODE_SIZE 0xA8U
#define PFS_PAYLOAD_BLOCK 6U
#define PFS_PAYLOAD_BASE ((uint64_t)PFS_PAYLOAD_BLOCK * PFS_BLOCK_SIZE)
#define PFS_FRONT_BYTES ((size_t)PFS_PAYLOAD_BLOCK * PFS_BLOCK_SIZE)
#define INODE_RX_ONLY 0x16DU /* o+r o+x g+r g+x u+r u+x */
#define INODE_MODE_DIR 0x4000U
#define INODE_MODE_FILE 0x8000U
#define INODE_FLAG_COMPRESSED 0x1U
#define INODE_FLAG_READONLY 0x10U
#define INODE_FLAG_INTERNAL 0x20000U
#define DIRENT_TYPE_FILE 2
#define DIRENT_TYPE_DIRECTORY 3
#define DIRENT_TYPE_DOT 4
#define DIRENT_TYPE_DOTDOT 5
#define PFS_INNER_NAME_MAX 200

static void put16_le(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v & 0xFF);
  p[1] = (uint8_t)((v >> 8) & 0xFF);
}

/* One directory entry; returns its aligned size. */
static size_t pfs_put_dirent(uint8_t *p, uint32_t ino, int32_t type, const char *name) {
  size_t nl = strlen(name);
  size_t ent = nl + 17;
  if (ent % 8) ent += 8 - ent % 8;
  put32_le(p, ino);
  put32_le(p + 4, (uint32_t)type);
  put32_le(p + 8, (uint32_t)nl);
  put32_le(p + 12, (uint32_t)ent);
  memcpy(p + 16, name, nl);
  return ent;
}

/* Unsigned D32 inode (0xA8 bytes): db[0]=db0, db[1..11]=dbrest, ib[] zero. */
static void pfs_put_inode(uint8_t *p, uint32_t mode, uint32_t nlink, uint32_t flags, uint64_t size,
                          uint64_t size_c, uint64_t now, uint32_t blocks, int32_t db0, int32_t dbrest) {
  put16_le(p, mode);
  put16_le(p + 2, nlink);
  put32_le(p + 4, flags);
  put64_le(p + 8, size);
  put64_le(p + 0x10, size_c);
  for (int i = 0; i < 4; i++) put64_le(p + 0x18 + 8 * i, now);
  /* nsec x4, uid, gid, unk1, unk2 = 0 (0x38..0x5F) */
  put32_le(p + 0x60, blocks);
  put32_le(p + 0x64, (uint32_t)db0);
  for (int i = 1; i < 12; i++) put32_le(p + 0x64 + 4 * i, (uint32_t)dbrest);
}

/* ultrapack fpt_hash over "/<name>", upper-cased (case-insensitive image). */
static uint32_t pfs_fpt_hash(const char *name) {
  uint32_t h = (uint32_t)'/';
  for (const char *c = name; *c; c++) h = (uint32_t)toupper((unsigned char)*c) + 31U * h;
  return h;
}

/* Build the PFS_PAYLOAD_BLOCK front blocks. stored_size == 0 means the file inode is provisional. */
static void pfs_build_front(uint8_t *buf, const char *inner, uint64_t now, uint64_t raw_size,
                            uint64_t stored_size, uint64_t final_ndblock) {
  const uint32_t bs = PFS_BLOCK_SIZE;
  memset(buf, 0, PFS_FRONT_BYTES);

  /* block 0: header */
  put64_le(buf + 0x00, PFS_VERSION_PS5);
  put64_le(buf + 0x08, PFS_MAGIC_VALUE);
  buf[0x1A] = 1; /* readonly */
  put16_le(buf + 0x1C, PFS_MODE_CASE_INSENSITIVE);
  put32_le(buf + 0x20, bs);
  put64_le(buf + 0x28, 1); /* nblock */
  put64_le(buf + 0x30, PFS_INODE_COUNT);
  put64_le(buf + 0x38, final_ndblock);
  put64_le(buf + 0x40, 1); /* inode block count */
  {
    uint8_t *sig = buf + 0x50; /* InodeBlockSig (0x310 bytes) */
    put16_le(sig + 0x02, 1);
    put32_le(sig + 0x04, INODE_FLAG_READONLY);
    put64_le(sig + 0x08, bs);
    put64_le(sig + 0x10, bs);
    for (int i = 0; i < 4; i++) put64_le(sig + 0x18 + 8 * i, now);
    put32_le(sig + 0x60, 1);
    put64_le(sig + 0x68 + 32, 1); /* db[0] = block 1 */
  }
  put32_le(buf + 0x368, 1);

  /* block 3: flat path table (one entry for the inner file -> inode 3) */
  uint8_t *fpt = buf + (size_t)3 * bs;
  put32_le(fpt, pfs_fpt_hash(inner));
  put32_le(fpt + 4, 3);

  /* block 1: inode table */
  uint8_t *ino = buf + bs;
  pfs_put_inode(ino + 0 * PFS_INODE_SIZE, INODE_MODE_DIR | INODE_RX_ONLY, 1,
                INODE_FLAG_INTERNAL | INODE_FLAG_READONLY, bs, bs, now, 1, 2, 0);
  pfs_put_inode(ino + 1 * PFS_INODE_SIZE, INODE_MODE_FILE | INODE_RX_ONLY, 1,
                INODE_FLAG_INTERNAL | INODE_FLAG_READONLY, 8, 8, now, 1, 3, -1);
  pfs_put_inode(ino + 2 * PFS_INODE_SIZE, INODE_MODE_DIR | INODE_RX_ONLY, 3,
                INODE_FLAG_READONLY, bs, bs, now, 1, 5, -1);
  if (stored_size) {
    uint32_t fblocks = (uint32_t)((stored_size + bs - 1) / bs);
    pfs_put_inode(ino + 3 * PFS_INODE_SIZE, INODE_MODE_FILE | INODE_RX_ONLY, 1,
                  INODE_FLAG_READONLY | INODE_FLAG_COMPRESSED, stored_size, raw_size, now, fblocks,
                  (int32_t)PFS_PAYLOAD_BLOCK, -1);
  } else {
    pfs_put_inode(ino + 3 * PFS_INODE_SIZE, INODE_MODE_FILE | INODE_RX_ONLY, 1,
                  INODE_FLAG_READONLY, 0, 0, now, 1, (int32_t)PFS_PAYLOAD_BLOCK, -1);
  }

  /* block 2: super_root dirents */
  uint8_t *sr = buf + (size_t)2 * bs;
  sr += pfs_put_dirent(sr, 1, DIRENT_TYPE_FILE, "flat_path_table");
  pfs_put_dirent(sr, 2, DIRENT_TYPE_DIRECTORY, "uroot");

  /* block 5: uroot dirents */
  uint8_t *ur = buf + (size_t)5 * bs;
  ur += pfs_put_dirent(ur, 2, DIRENT_TYPE_DOT, ".");
  ur += pfs_put_dirent(ur, 2, DIRENT_TYPE_DOTDOT, "..");
  pfs_put_dirent(ur, 3, DIRENT_TYPE_FILE, inner);
}

/* Backpatch PFSC header and block offset table at the PFSC container start (base). */
static int pfsc_write_header(FILE *fout, uint64_t base, const uint64_t *offsets, uint32_t block_count,
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

  if (fseeko(fout, (off_t)base, SEEK_SET) != 0 || fwrite(hdr, 1, sizeof(hdr), fout) != sizeof(hdr)) {
    snprintf(err_msg, err_len, "Failed writing PFSC header: %s", strerror(errno));
    return -1;
  }
  if (fseeko(fout, (off_t)(base + PFSC_BLOCK_OFFSETS_OFFSET), SEEK_SET) != 0) {
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
                            FILE *fout, uint64_t *out_off, double *t_write, char *err_msg, size_t err_len) {
  double tw = mono_s();
  if (stored) {
    if (fwrite(in_buf, 1, PFSC_LOGICAL_BLOCK_SIZE, fout) != PFSC_LOGICAL_BLOCK_SIZE) {
      snprintf(err_msg, err_len, "Failed writing block to disk (disk full?): %s", strerror(errno));
      return -1;
    }
  } else if (fwrite(out_buf, 1, sz, fout) != sz) {
    snprintf(err_msg, err_len, "Failed writing compressed block (disk full?): %s", strerror(errno));
    return -1;
  }
  *t_write += mono_s() - tw;
  *out_off += sz;
  return 0;
}

/* Compress one full 64 KiB logical block (reusing strm) and write it; advances *out_off. */
static int pfsc_emit_block(z_stream *strm, const uint8_t *in_buf, uint8_t *out_buf,
                           FILE *fout, uint64_t *out_off, double *t_write, char *err_msg, size_t err_len) {
  int stored;
  size_t sz = pfsc_compress_block(strm, in_buf, out_buf, &stored);
  return pfsc_write_block(in_buf, out_buf, sz, stored, fout, out_off, t_write, err_msg, err_len);
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
  uint64_t now;                            /* PFS timestamps (time(NULL) or WUP_FIXED_TIME) */
  char inner_name[PFS_INNER_NAME_MAX + 1]; /* name of the single inner file */
  z_stream strm;
  bool zinit;
  char err[256];
  double t_write;  /* diagnostics: fwrite wall time (sink thread) */
  double t_wait;   /* diagnostics: time waiting on compressors */

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

/* CPUs this process may actually run on. On the console a payload can be confined to few cores while
 * sysconf still reports all of them, so extra compressor threads would only share one core.
 * Best effort: try to widen the affinity to every online CPU, then report what we got. */
static int pfsc_usable_cpus(long online) {
  if (online < 1) online = 1;
#ifdef WUP_HAVE_CPUSET
  /* The kernel's cpuset is larger than the SDK's cpuset_t (getaffinity fails with ERANGE), so probe
   * increasing buffer sizes and treat the set as a raw little-endian bitmap. */
  enum { MAXBUF = 1024 };
  unsigned char cur[MAXBUF], want[MAXBUF];
  static const size_t sizes[] = {8, 16, 32, 64, 128, 256, 512, 1024};
  size_t len = 0;
  int last_errno = 0;
  if (online > MAXBUF * 8) online = MAXBUF * 8;
  for (size_t k = 0; k < sizeof(sizes) / sizeof(sizes[0]) && !len; k++) {
    memset(cur, 0, sizeof(cur));
    if (cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1, sizes[k], (cpuset_t *)(void *)cur) == 0) len = sizes[k];
    else last_errno = errno;
  }
  int before = -1, after = -1, setrc = 0, seterr = 0;
  if (len) {
    before = 0;
    for (long i = 0; i < online; i++) if (cur[i / 8] & (1u << (i % 8))) before++;
    if (before < online) {
      memset(want, 0, sizeof(want));
      for (long i = 0; i < online; i++) want[i / 8] |= (unsigned char)(1u << (i % 8));
      setrc = cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1, len, (const cpuset_t *)(const void *)want);
      seterr = setrc ? errno : 0;
      memset(cur, 0, sizeof(cur));
      if (cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1, len, (cpuset_t *)(void *)cur) == 0) {
        after = 0;
        for (long i = 0; i < online; i++) if (cur[i / 8] & (1u << (i % 8))) after++;
      }
    } else {
      after = before;
    }
  }
  fprintf(stderr, "[pfsc] cpus online=%ld setlen=%zu get_errno=%d allowed_before=%d widen_rc=%d widen_errno=%d allowed_after=%d\n",
          online, len, last_errno, before, setrc, seterr, after);
  if (after > 0) return after;
  if (before > 0) return before;
#endif
  return (int)online;
}

static int pfsc_thread_count(void) {
  const char *e = getenv("WUP_THREADS");
  long n = 0;
  if (e && *e) {
    char *end = NULL;
    n = strtol(e, &end, 10);
    if (end == e || n < 1) n = 0;
  }
  if (n == 0) {
    long cpu = pfsc_usable_cpus(sysconf(_SC_NPROCESSORS_ONLN));
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
  s->t_write = 0.0;
  s->t_wait = 0.0;
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

  if (!s->inner_name[0]) {
    snprintf(s->err, sizeof(s->err), "Inner file name not set");
    return -1;
  }
  uint8_t *front = (uint8_t *)malloc(PFS_FRONT_BYTES);
  if (!front) {
    snprintf(s->err, sizeof(s->err), "Out of memory for PFS metadata");
    return -1;
  }
  pfs_build_front(front, s->inner_name, s->now, total_bytes, 0, 0);
  size_t fw = fwrite(front, 1, PFS_FRONT_BYTES, s->f);
  free(front);
  if (fw != PFS_FRONT_BYTES) {
    snprintf(s->err, sizeof(s->err), "Failed writing PFS metadata: %s", strerror(errno));
    return -1;
  }

  /* Reserve the PFSC header + offset table area (backpatched at the end). */
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
  int rc = pfsc_write_block(sl->in, sl->out, sl->sz, sl->stored, s->f, &s->cur_off, &s->t_write, s->err, sizeof(s->err));
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
    { double tc = mono_s(); pthread_cond_wait(&s->done_cv, &s->mu); s->t_wait += mono_s() - tc; }
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
    if (e == 0) { double tc = mono_s(); pthread_cond_wait(&s->done_cv, &s->mu); s->t_wait += mono_s() - tc; }
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
  if (pfsc_emit_block(&s->strm, s->in_buf, s->out_buf, s->f, &s->cur_off, &s->t_write, s->err, sizeof(s->err)) != 0) {
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
  if (pfsc_write_header(s->f, PFS_PAYLOAD_BASE, s->offsets, s->block_count, s->initial_data_offset,
                        s->logical_size, s->err, sizeof(s->err)) != 0) return -1;

  /* Final PFS metadata: stored size, file inode and header block total are only known now. */
  uint64_t stored = s->cur_off;
  uint64_t final_ndblock = PFS_PAYLOAD_BLOCK + (stored + PFS_BLOCK_SIZE - 1) / PFS_BLOCK_SIZE;
  uint8_t *front = (uint8_t *)malloc(PFS_FRONT_BYTES);
  if (!front) {
    snprintf(s->err, sizeof(s->err), "Out of memory for PFS metadata");
    return -1;
  }
  pfs_build_front(front, s->inner_name, s->now, s->total_bytes, stored, final_ndblock);
  int rc = (fseeko(s->f, 0, SEEK_SET) == 0 && fwrite(front, 1, PFS_FRONT_BYTES, s->f) == PFS_FRONT_BYTES) ? 0 : -1;
  free(front);
  if (rc != 0) {
    snprintf(s->err, sizeof(s->err), "Failed backpatching PFS metadata: %s", strerror(errno));
    return -1;
  }
  if (fflush(s->f) != 0 || ftruncate(fileno(s->f), (off_t)(final_ndblock * PFS_BLOCK_SIZE)) != 0) {
    snprintf(s->err, sizeof(s->err), "Failed finalizing image size: %s", strerror(errno));
    return -1;
  }
  return 0;
}

/* ---- inner file naming (ultrapack: default_image_basename / resolve_single_file_inner_name) ---- */

/* ASCII [A-Za-z0-9._-] only, one '_' per other code point (like _sanitize_name_component). */
static void pfs_sanitize_component(const char *in, char *out, size_t cap) {
  size_t o = 0;
  for (const unsigned char *c = (const unsigned char *)in; *c && o + 1 < cap; c++) {
    if ((*c & 0xC0) == 0x80) continue; /* UTF-8 continuation byte */
    out[o++] = ((*c < 0x80 && isalnum(*c)) || *c == '.' || *c == '_' || *c == '-') ? (char)*c : '_';
  }
  out[o] = '\0';
}

/* Value of "titleId" (or "title_id") in param.json text; returns 1 when found. */
static int pfs_param_title_id(const char *json, size_t len, char *out, size_t cap) {
  static const char *const keys[] = { "\"titleId\"", "\"title_id\"" };
  for (int k = 0; k < 2; k++) {
    size_t kl = strlen(keys[k]);
    for (size_t i = 0; i + kl <= len; i++) {
      if (memcmp(json + i, keys[k], kl) != 0) continue;
      size_t j = i + kl;
      while (j < len && isspace((unsigned char)json[j])) j++;
      if (j >= len || json[j] != ':') continue;
      j++;
      while (j < len && isspace((unsigned char)json[j])) j++;
      if (j >= len || json[j] != '"') continue;
      j++;
      size_t o = 0;
      while (j < len && json[j] != '"' && json[j] != '\\' && o + 1 < cap) out[o++] = json[j++];
      if (j >= len || json[j] != '"') continue;
      while (o > 0 && isspace((unsigned char)out[o - 1])) o--;
      size_t st = 0;
      while (st < o && isspace((unsigned char)out[st])) st++;
      memmove(out, out + st, o - st);
      o -= st;
      out[o] = '\0';
      if (o > 0) return 1;
    }
  }
  return 0;
}

/* "<titleId or fallback>.exfat" for exFAT-stream sources (folder / listing / pkg). */
static void pfs_stream_inner_name(const char *title_id, const char *fallback, char *out, size_t cap) {
  char base[PFS_INNER_NAME_MAX - 8];
  pfs_sanitize_component(title_id && title_id[0] ? title_id : (fallback && fallback[0] ? fallback : "image"),
                         base, sizeof(base));
  if (!base[0]) snprintf(base, sizeof(base), "image");
  snprintf(out, cap, "%s.exfat", base);
}

static int pfs_is_upper(int c) { return c >= 'A' && c <= 'Z'; }
static int pfs_is_digit(int c) { return c >= '0' && c <= '9'; }
static int pfs_is_alnum_up(int c) { return pfs_is_upper(c) || pfs_is_digit(c); }

/* Preferred title ID inside a file stem (ABCD12345, ABCD12345_NN, legacy ABCD-12345). */
static int pfs_stem_title_id(const char *st, char *out) {
  size_t n = strlen(st);
  for (size_t i = 0; i + 9 <= n; i++) { /* modern */
    int ok = 1;
    for (int k = 0; k < 4 && ok; k++) ok = pfs_is_upper((unsigned char)st[i + k]);
    for (int k = 4; k < 9 && ok; k++) ok = pfs_is_digit((unsigned char)st[i + k]);
    if (!ok) continue;
    if (i > 0 && pfs_is_alnum_up((unsigned char)st[i - 1])) continue;
    if (i + 9 < n && pfs_is_alnum_up((unsigned char)st[i + 9])) continue;
    memcpy(out, st + i, 9); out[9] = '\0';
    return 1;
  }
  for (size_t i = 0; i + 12 <= n; i++) { /* long form ABCD12345_NN */
    int ok = 1;
    for (int k = 0; k < 4 && ok; k++) ok = pfs_is_upper((unsigned char)st[i + k]);
    for (int k = 4; k < 9 && ok; k++) ok = pfs_is_digit((unsigned char)st[i + k]);
    ok = ok && st[i + 9] == '_' && pfs_is_digit((unsigned char)st[i + 10]) && pfs_is_digit((unsigned char)st[i + 11]);
    if (!ok) continue;
    memcpy(out, st + i, 9); out[9] = '\0';
    return 1;
  }
  for (size_t i = 0; i + 10 <= n; i++) { /* legacy ABCD-12345 */
    int ok = 1;
    for (int k = 0; k < 4 && ok; k++) ok = pfs_is_upper((unsigned char)st[i + k]);
    ok = ok && st[i + 4] == '-';
    for (int k = 5; k < 10 && ok; k++) ok = pfs_is_digit((unsigned char)st[i + k]);
    if (!ok) continue;
    if (i > 0 && (pfs_is_alnum_up((unsigned char)st[i - 1]) || st[i - 1] == '-')) continue;
    if (i + 10 < n && (pfs_is_alnum_up((unsigned char)st[i + 10]) || st[i + 10] == '-')) continue;
    memcpy(out, st + i, 10); out[10] = '\0';
    return 1;
  }
  return 0;
}

/* Inner name for a raw image source: ultrapack's resolve_single_file_inner_name (rename on):
 * a title ID found in the stem, else the stem collapsed to <=15 ASCII chars, plus the lower-cased
 * extension(s). */
static void pfs_image_inner_name(const char *path, char *out, size_t cap) {
  const char *b = strrchr(path, '/');
  b = b ? b + 1 : path;
  size_t bl = strlen(b), stem_len = bl;
  for (size_t i = 1; i < bl; i++) {
    if (b[i] == '.') { stem_len = i; break; }
  }
  char stem[256], ext[64];
  snprintf(stem, sizeof(stem), "%.*s", (int)(stem_len < sizeof(stem) ? stem_len : sizeof(stem) - 1), b);
  snprintf(ext, sizeof(ext), "%s", b + stem_len);
  for (char *e = ext; *e; e++) *e = (char)tolower((unsigned char)*e);
  for (char *e = ext; *e; e++) if (!((*e >= 'a' && *e <= 'z') || (*e >= '0' && *e <= '9') || *e == '.' || *e == '_' || *e == '-')) *e = '_';
  char safe[32], tid[16];
  if (pfs_stem_title_id(stem, tid)) {
    snprintf(safe, sizeof(safe), "%s", tid);
  } else {
    size_t o = 0;
    char pending = 0;
    for (const unsigned char *c = (const unsigned char *)stem; *c && o < 15; c++) {
      if (*c < 0x80 && isalnum(*c)) {
        if (pending && o > 0) { safe[o++] = pending; if (o >= 15) break; }
        safe[o++] = (char)*c;
        pending = 0;
      } else if (*c == ' ') {
        pending = '_';
      } else if (*c == '_' || *c == '-') {
        pending = (char)*c;
      }
    }
    safe[o] = '\0';
    if (!safe[0]) snprintf(safe, sizeof(safe), "image");
  }
  snprintf(out, cap, "%s%s", safe, ext);
}

/* Set the inner name and timestamp; must precede pfsc_sink_begin. */
static void pfsc_sink_setup(pfsc_sink_t *s, const char *inner_name) {
  snprintf(s->inner_name, sizeof(s->inner_name), "%s", inner_name);
  const char *fx = getenv("WUP_FIXED_TIME");
  char *endp = NULL;
  unsigned long long v = (fx && *fx) ? strtoull(fx, &endp, 10) : 0;
  s->now = (fx && *fx && endp && *endp == '\0') ? (uint64_t)v : (uint64_t)time(NULL);
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
  if (s->f) setvbuf(s->f, NULL, _IOFBF, (size_t)8 << 20); /* big sequential writes: the console drive is slow with small ones */
  if (!s->f) {
    snprintf(err_msg, err_len, "Cannot create target .ffpfsc: %s", strerror(errno));
    free(s); free(chunk); fclose(fin);
    return -1;
  }

  char inner[PFS_INNER_NAME_MAX + 1];
  pfs_image_inner_name(in_image_path, inner, sizeof(inner));
  pfsc_sink_setup(s, inner);
  int ret = pfsc_sink_begin(total_input_size, s);
  uint64_t done = 0;
  double t_start = mono_s(), t_read = 0, t_sink = 0, t_mark = t_start;
  uint64_t next_report = (uint64_t)4 << 30;
  fprintf(stderr, "[pfsc] image start: %llu bytes, threads=%d\n", (unsigned long long)total_input_size, s->nthreads);
  while (ret == 0 && done < total_input_size) {
    if (cancel_cb && cancel_cb(user_data)) {
      snprintf(s->err, sizeof(s->err), "Conversion cancelled by user");
      ret = -2;
      break;
    }
    uint64_t want = total_input_size - done;
    double t0 = mono_s();
    size_t n = fread(chunk, 1, want < PFSC_IMAGE_CHUNK ? (size_t)want : PFSC_IMAGE_CHUNK, fin);
    t_read += mono_s() - t0;
    if (n == 0) {
      if (ferror(fin)) snprintf(s->err, sizeof(s->err), "Error reading source image: %s", strerror(errno));
      else snprintf(s->err, sizeof(s->err), "Source image shrank while converting");
      ret = -1;
      break;
    }
    double t1 = mono_s();
    if (pfsc_sink_write(chunk, n, s) != 0) { ret = -1; break; }
    t_sink += mono_s() - t1;
    done += n;
    if (done >= next_report) {
      double now = mono_s();
      fprintf(stderr, "[pfsc] %.1f GB done, %.0f MB/s overall | read %.0fs sink %.0fs (fwrite %.0fs, waiting on compressors %.0fs) of %.0fs\n",
              (double)done / 1e9, (double)done / 1e6 / (now - t_start), t_read, t_sink, s->t_write, s->t_wait, now - t_start);
      (void)t_mark;
      next_report += (uint64_t)4 << 30;
    }
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

static int stream_to_ffpfsc(const char *out_ffpfsc_path, const char *title_id, ffpfsc_stream_fn run, void *run_ctx,
                            convert_progress_cb progress_cb, convert_cancel_cb cancel_cb,
                            void *user_data, char *err_msg, size_t err_len) {
  pfsc_sink_t *s = (pfsc_sink_t *)calloc(1, sizeof(*s));
  if (!s) {
    snprintf(err_msg, err_len, "Out of memory");
    return -1;
  }
  s->f = fopen(out_ffpfsc_path, "wb+");
  if (s->f) setvbuf(s->f, NULL, _IOFBF, (size_t)8 << 20); /* big sequential writes: the console drive is slow with small ones */
  if (!s->f) {
    snprintf(err_msg, err_len, "Cannot create target .ffpfsc: %s", strerror(errno));
    free(s);
    return -1;
  }

  /* Inner file: <titleId>.exfat (param.json), else the output name. */
  char fallback[256], inner[PFS_INNER_NAME_MAX + 1];
  {
    const char *b = strrchr(out_ffpfsc_path, '/');
    snprintf(fallback, sizeof(fallback), "%s", b ? b + 1 : out_ffpfsc_path);
    char *dot = strrchr(fallback, '.');
    if (dot) *dot = '\0';
  }
  pfs_stream_inner_name(title_id, fallback, inner, sizeof(inner));
  pfsc_sink_setup(s, inner);

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
  char tid[128] = "";
  char pj[4096 + 32];
  snprintf(pj, sizeof(pj), "%s/sce_sys/param.json", source_dir);
  FILE *pf = fopen(pj, "rb");
  if (pf) {
    char *js = (char *)malloc(65536);
    if (js) {
      size_t n = fread(js, 1, 65536, pf);
      if (!pfs_param_title_id(js, n, tid, sizeof(tid))) tid[0] = 0;
      free(js);
    }
    fclose(pf);
  }
  return stream_to_ffpfsc(out_ffpfsc_path, tid, run_folder_stream, (void *)source_dir, progress_cb, cancel_cb,
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

int convert_listing_to_ffpfsc_ex(const exfat_listing_entry_t *entries, size_t count,
                                 const exfat_src_ops_t *ops, void *ops_ctx, const char *out_ffpfsc_path,
                                 const char *title_id,
                                 convert_progress_cb progress_cb, convert_cancel_cb cancel_cb,
                                 void *user_data, char *err_msg, size_t err_len) {
  listing_stream_t ls = { entries, count, ops, ops_ctx };
  return stream_to_ffpfsc(out_ffpfsc_path, title_id, run_listing_stream, &ls, progress_cb, cancel_cb,
                          user_data, err_msg, err_len);
}

int convert_listing_to_ffpfsc(const exfat_listing_entry_t *entries, size_t count,
                              const exfat_src_ops_t *ops, void *ops_ctx, const char *out_ffpfsc_path,
                              convert_progress_cb progress_cb, convert_cancel_cb cancel_cb,
                              void *user_data, char *err_msg, size_t err_len) {
  return convert_listing_to_ffpfsc_ex(entries, count, ops, ops_ctx, out_ffpfsc_path, NULL, progress_cb,
                                      cancel_cb, user_data, err_msg, err_len);
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
  char tid[128] = "";
  if (!is_exfat) {
    for (size_t i = 0; i < n; i++) {
      if (list[i].is_dir || list[i].size == 0 || strcmp(list[i].path, "sce_sys/param.json") != 0) continue;
      size_t want = list[i].size < 65536 ? (size_t)list[i].size : 65536;
      char *js = (char *)malloc(want);
      if (js) {
        if (pkg_read_cb(pkg, list[i].file_id, 0, js, want) == (int)want &&
            !pfs_param_title_id(js, want, tid, sizeof(tid))) tid[0] = 0;
        free(js);
      }
      break;
    }
    if (!tid[0]) { /* no title id in the package's param.json: take it from the file name */
      const char *b = strrchr(pkg_path, '/');
      if (!pfs_stem_title_id(b ? b + 1 : pkg_path, tid)) tid[0] = 0;
    }
  }
  int ret = is_exfat
    ? convert_listing_to_exfat(list, n, &ops, pkg, target_file, progress_cb, cancel_cb,
                               user_data, err_msg, err_len)
    : convert_listing_to_ffpfsc_ex(list, n, &ops, pkg, target_file, tid, progress_cb, cancel_cb,
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
