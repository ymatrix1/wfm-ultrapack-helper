/* Test driver for the listing -> exFAT / ffpfsc API (src/exfat_engine.c, src/convert_engine.c).
 *
 * The spec file describes a flat listing, one entry per line, tab separated:
 *   F <TAB> size <TAB> file_id <TAB> path
 *   D <TAB>      <TAB>         <TAB> path
 * File contents come from an in-memory fake source: byte(file_id, offset) is a pure function, so the same
 * data can also be materialized on disk and converted through the folder path for a byte-for-byte compare.
 *
 *   listing_driver exfat   <spec> <out.exfat>   [faults]
 *   listing_driver ffpfsc  <spec> <out.ffpfsc>  [faults]
 *   listing_driver materialize <spec> <dir>
 *   listing_driver folder-exfat  <dir> <out.exfat>
 *   listing_driver folder-ffpfsc <dir> <outdir>      (run_conversion; writes <outdir>/<basename>.ffpfsc)
 * Faults (listing modes): --short=<id> --neg=<id> (fail reads of that file), --at=<offset> (only from that
 * offset on), --cancel-after=<n> (cancel callback fires after n polls).
 * The fake source enforces the read contract: per file strictly contiguous offsets from 0, chunks of
 * 1..1 MiB, and a file is either never read or read completely.
 * Exit status: 0 ok, 1 error, 2 cancelled, 3 contract violation.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#include "convert_engine.h"

#define MAX_CHUNK (1024U * 1024U)

typedef struct {
  uint64_t *next_off; /* per file_id */
  uint64_t *size;
  size_t nids;
  uint64_t reads;
  uint64_t bytes;
  bool violation;
  long fault_short, fault_neg;
  uint64_t fault_at;
  long cancel_after;
  long polls;
} fake_t;

static uint64_t mix(uint64_t x) {
  x += 0x9E3779B97F4A7C15ULL;
  x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
  x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
  return x ^ (x >> 31);
}

static void gen(uint64_t id, uint64_t off, uint8_t *buf, size_t len) {
  for (size_t i = 0; i < len; i++) {
    uint64_t pos = off + i;
    switch (id % 3) {
      case 0: buf[i] = (uint8_t)(mix(id * 0x100000001B3ULL ^ (pos >> 3)) >> ((pos & 7) * 8)); break;
      case 1: buf[i] = (uint8_t)((pos / 997) & 0xFF); break; /* compressible */
      default: buf[i] = (pos & 0x100) ? (uint8_t)(mix(id ^ (pos >> 3)) >> ((pos & 7) * 8)) : 0; break;
    }
  }
}

static int fake_read(void *ctx, uint64_t id, uint64_t off, void *buf, size_t len) {
  fake_t *f = (fake_t *)ctx;
  if (id >= f->nids || len == 0 || len > MAX_CHUNK || off != f->next_off[id] || off + len > f->size[id]) {
    fprintf(stderr, "CONTRACT VIOLATION id=%llu off=%llu len=%zu expected_off=%llu\n", (unsigned long long)id,
            (unsigned long long)off, len, id < f->nids ? (unsigned long long)f->next_off[id] : 0ULL);
    f->violation = true;
    return -1;
  }
  if (off >= f->fault_at) {
    if ((long)id == f->fault_neg) return -5;
    if ((long)id == f->fault_short) return (int)len - 1;
  }
  gen(id, off, (uint8_t *)buf, len);
  f->next_off[id] += len;
  f->reads++;
  f->bytes += len;
  return (int)len;
}

static bool fake_cancel(void *ud) {
  fake_t *f = (fake_t *)ud;
  return f->cancel_after >= 0 && ++f->polls > f->cancel_after;
}

typedef struct {
  exfat_listing_entry_t *e;
  size_t n;
  char **paths;
} spec_t;

static int load_spec(const char *file, spec_t *s) {
  FILE *fp = fopen(file, "rb");
  if (!fp) return -1;
  char *line = NULL;
  size_t cap = 0;
  ssize_t got;
  size_t alloc = 0;
  memset(s, 0, sizeof(*s));
  while ((got = getline(&line, &cap, fp)) > 0) {
    while (got > 0 && (line[got - 1] == '\n' || line[got - 1] == '\r')) line[--got] = 0;
    if (got == 0) continue;
    char *t1 = strchr(line, '\t'), *t2 = t1 ? strchr(t1 + 1, '\t') : NULL, *t3 = t2 ? strchr(t2 + 1, '\t') : NULL;
    if (!t3) { fclose(fp); free(line); return -1; }
    *t1 = *t2 = *t3 = 0;
    if (s->n == alloc) {
      alloc = alloc ? alloc * 2 : 256;
      s->e = (exfat_listing_entry_t *)realloc(s->e, alloc * sizeof(*s->e));
      s->paths = (char **)realloc(s->paths, alloc * sizeof(*s->paths));
      if (!s->e || !s->paths) { fclose(fp); free(line); return -1; }
    }
    s->paths[s->n] = strdup(t3 + 1);
    s->e[s->n].path = s->paths[s->n];
    s->e[s->n].is_dir = (line[0] == 'D');
    s->e[s->n].size = strtoull(t1 + 1, NULL, 10);
    s->e[s->n].file_id = strtoull(t2 + 1, NULL, 10);
    s->n++;
  }
  free(line);
  fclose(fp);
  return 0;
}

static void mkdirs(const char *path) {
  char tmp[4096];
  snprintf(tmp, sizeof(tmp), "%s", path);
  for (char *p = tmp + 1; *p; p++) {
    if (*p == '/') { *p = 0; mkdir(tmp, 0755); *p = '/'; }
  }
  mkdir(tmp, 0755);
}

static int materialize(const spec_t *s, const char *dir) {
  mkdirs(dir);
  uint8_t *buf = (uint8_t *)malloc(MAX_CHUNK);
  if (!buf) return -1;
  for (size_t i = 0; i < s->n; i++) {
    char full[4096];
    snprintf(full, sizeof(full), "%s/%s", dir, s->e[i].path);
    if (s->e[i].is_dir) { mkdirs(full); continue; }
    char parent[4096];
    snprintf(parent, sizeof(parent), "%s", full);
    char *sl = strrchr(parent, '/');
    if (sl) { *sl = 0; mkdirs(parent); }
    FILE *f = fopen(full, "wb");
    if (!f) { free(buf); return -1; }
    for (uint64_t off = 0; off < s->e[i].size;) {
      size_t n = (s->e[i].size - off > MAX_CHUNK) ? MAX_CHUNK : (size_t)(s->e[i].size - off);
      gen(s->e[i].file_id, off, buf, n);
      if (fwrite(buf, 1, n, f) != n) { fclose(f); free(buf); return -1; }
      off += n;
    }
    if (fclose(f) != 0) { free(buf); return -1; }
  }
  free(buf);
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 4) { fprintf(stderr, "usage\n"); return 1; }
  const char *mode = argv[1];
  char err[512] = {0};
  int rc = 0;

  if (!strcmp(mode, "folder-exfat")) {
    rc = convert_folder_to_exfat(argv[2], argv[3], NULL, NULL, NULL, err, sizeof(err));
  } else if (!strcmp(mode, "folder-ffpfsc")) {
    rc = run_conversion(argv[2], argv[3], "ffpfsc", NULL, NULL, NULL, err, sizeof(err));
  } else {
    spec_t spec;
    if (load_spec(argv[2], &spec) != 0) { fprintf(stderr, "bad spec\n"); return 1; }
    if (!strcmp(mode, "materialize")) {
      if (materialize(&spec, argv[3]) != 0) { fprintf(stderr, "materialize failed\n"); return 1; }
      return 0;
    }
    fake_t f;
    memset(&f, 0, sizeof(f));
    f.fault_short = f.fault_neg = -1;
    f.cancel_after = -1;
    for (int i = 4; i < argc; i++) {
      if (!strncmp(argv[i], "--short=", 8)) f.fault_short = atol(argv[i] + 8);
      else if (!strncmp(argv[i], "--neg=", 6)) f.fault_neg = atol(argv[i] + 6);
      else if (!strncmp(argv[i], "--at=", 5)) f.fault_at = strtoull(argv[i] + 5, NULL, 10);
      else if (!strncmp(argv[i], "--cancel-after=", 15)) f.cancel_after = atol(argv[i] + 15);
    }
    for (size_t i = 0; i < spec.n; i++) {
      if (!spec.e[i].is_dir && spec.e[i].file_id + 1 > f.nids) f.nids = (size_t)spec.e[i].file_id + 1;
    }
    f.next_off = (uint64_t *)calloc(f.nids + 1, sizeof(uint64_t));
    f.size = (uint64_t *)calloc(f.nids + 1, sizeof(uint64_t));
    for (size_t i = 0; i < spec.n; i++) {
      if (!spec.e[i].is_dir) f.size[spec.e[i].file_id] = spec.e[i].size;
    }
    exfat_src_ops_t ops = { fake_read };
    if (!strcmp(mode, "exfat")) {
      rc = convert_listing_to_exfat(spec.e, spec.n, &ops, &f, argv[3], NULL, f.cancel_after >= 0 ? fake_cancel : NULL, &f,
                                    err, sizeof(err));
    } else if (!strcmp(mode, "ffpfsc")) {
      rc = convert_listing_to_ffpfsc(spec.e, spec.n, &ops, &f, argv[3], NULL, f.cancel_after >= 0 ? fake_cancel : NULL, &f,
                                     err, sizeof(err));
    } else {
      fprintf(stderr, "unknown mode\n");
      return 1;
    }
    if (f.violation) return 3;
    if (rc == 0) {
      for (size_t id = 0; id < f.nids; id++) {
        if (f.next_off[id] != 0 && f.next_off[id] != f.size[id]) {
          fprintf(stderr, "CONTRACT VIOLATION file %zu read partially (%llu of %llu)\n", id,
                  (unsigned long long)f.next_off[id], (unsigned long long)f.size[id]);
          return 3;
        }
      }
      printf("OK reads=%llu bytes=%llu\n", (unsigned long long)f.reads, (unsigned long long)f.bytes);
    }
  }

  if (rc != 0) fprintf(stderr, "ERR rc=%d %s\n", rc, err);
  return rc == 0 ? 0 : (rc == -2 ? 2 : 1);
}
