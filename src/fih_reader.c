/* Native PS5 "FIH" package reader (see fih_reader.h for the layer stack).
 *
 * Format knowledge: LibProsperoPkg (SvenGDK, GPL-3.0, ProsperoNapsImage / ProsperoNapsLayout /
 * ProsperoCompressedPfsImage), validated against a real 134 GB package. All multi-byte values are
 * little-endian except the embedded CNT (big-endian). */
#define _POSIX_C_SOURCE 200809L
#define _FILE_OFFSET_BITS 64

#include "fih_reader.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kraken.h"

#define BS 65536u
#define SPAN_MAX 262144u
#define CACHE_SLOTS 64
#define MAX_DEPTH 48
#define MAX_DIR_BYTES (64u << 20)

static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static uint64_t le64(const uint8_t *p) { return le32(p) | (uint64_t)le32(p + 4) << 32; }
static uint32_t be32(const uint8_t *p) {
    return (uint32_t)p[3] | (uint32_t)p[2] << 8 | (uint32_t)p[1] << 16 | (uint32_t)p[0] << 24;
}

static int fail(char *err, size_t errlen, const char *fmt, ...) {
    if (err && errlen) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err, errlen, fmt, ap);
        va_end(ap);
    }
    return -1;
}

/* One NAPS span: 256 KiB (at most) of the logical image. */
typedef struct {
    uint64_t uoff; /* offset in the logical image */
    uint64_t coff; /* offset of the compressed bytes, relative to pfs_image.dat */
    uint32_t clen;
    uint32_t ulen;
    uint32_t first; /* compressed size of the first 128 KiB chunk (Kraken, ulen > 128 KiB) */
    uint16_t fl;    /* even:3 odd:3 kde:6 shuf:4 */
} span_t;

typedef struct {
    int64_t idx; /* -1 = empty */
    uint64_t tick;
    uint8_t *buf;
} slot_t;

typedef struct {
    uint64_t size;
    int64_t off;
} inode_t; /* inner PFS inode (only what is needed) */

struct fih {
    pkgr_io_t io;
    char content_id[64];
    uint64_t cnt_off;
    uint32_t n_cnt;
    uint8_t *cnt_tab;

    uint64_t img_off; /* pfs_image.dat in the package file */
    span_t *spans;
    size_t nspans;
    uint64_t usize; /* logical image size */
    size_t hint;

    slot_t slots[CACHE_SLOTS];
    uint64_t tick;
    uint8_t *raw; /* SPAN_MAX */
    uint64_t n_stored, n_zero, n_kraken;

    uint32_t ibs; /* inner PFS block size */
    uint64_t ninodes;
    inode_t *ino;
    uint8_t *dir_seen;
};

static int io_read(const pkgr_io_t *io, uint64_t off, void *buf, size_t n) {
    if (n == 0) return 0;
    if (off > io->size || n > io->size - off) return -1;
    return io->pread(io->ctx, off, buf, n);
}

void fih_close(fih_t *f) {
    if (!f) return;
    for (int i = 0; i < CACHE_SLOTS; i++) free(f->slots[i].buf);
    free(f->raw);
    free(f->spans);
    free(f->cnt_tab);
    free(f->ino);
    free(f->dir_seen);
    if (f->io.close) f->io.close(f->io.ctx);
    free(f);
}

const char *fih_content_id(const fih_t *f) { return f->content_id; }
uint64_t fih_image_size(const fih_t *f) { return f->usize; }
uint64_t fih_span_count(const fih_t *f) { return f->nspans; }
void fih_decode_stats(const fih_t *f, uint64_t *stored, uint64_t *zero, uint64_t *kraken) {
    *stored = f->n_stored;
    *zero = f->n_zero;
    *kraken = f->n_kraken;
}
int fih_raw_read(fih_t *f, uint64_t off, void *buf, size_t n) { return io_read(&f->io, off, buf, n); }

int fih_cnt_find(const fih_t *f, uint32_t id, uint64_t *off, uint64_t *size) {
    for (uint32_t i = 0; i < f->n_cnt; i++) {
        const uint8_t *r = f->cnt_tab + (size_t)i * 32;
        if (be32(r) != id) continue;
        uint64_t o = f->cnt_off + be32(r + 16), s = be32(r + 20);
        if (o > f->io.size || s > f->io.size - o) return -1;
        *off = o;
        *size = s;
        return 0;
    }
    return -1;
}

/* ------------------------------------------------------------ NAPS layout */
typedef struct {
    const uint8_t *blob;
    size_t len;
    uint64_t nfiles, nub, ncbi, ublocks;
    size_t fidx_off, u2c_off, cbi_off;
} naps_t;

typedef struct {
    int run, term;
    uint32_t low, uoff, clen_m1, even, odd, kde, shuf;
    uint64_t costart256;
} cbi_t;

static int naps_parse(naps_t *n, const uint8_t *blob, size_t len) {
    if (len < 16) return -1;
    uint64_t n0 = le64(blob), n1 = le64(blob + 8);
    n->blob = blob;
    n->len = len;
    n->nfiles = (n0 & 0xFFFFFF) + 1;
    uint64_t nshuf = (n0 >> 28) & 0xF;
    n->nub = (n0 >> 32) & 0x7FFFFF;
    uint64_t nouter = n1 & 0xFFFFFF;
    n->ncbi = ((n1 >> 24) & 0xFFFFFF) + 2;
    n->ublocks = n->nub + 1;
    uint64_t off = 16;
    off += nouter * 8;
    off += nshuf * 8;
    n->fidx_off = (size_t)off;
    off += n->nfiles * 6;
    n->u2c_off = (size_t)off;
    off += ((n->nub + 8) >> 3) * 10;
    off = (off + 7) & ~(uint64_t)7;
    n->cbi_off = (size_t)off;
    off += n->ncbi * 9;
    off = (off + 7) & ~(uint64_t)7;
    return off <= len ? 0 : -1;
}

static void naps_file(const naps_t *n, uint64_t i, unsigned *type, uint64_t *uoff) {
    const uint8_t *b = n->blob + n->fidx_off + i * 6;
    *type = b[5];
    *uoff = (uint64_t)b[0] | (uint64_t)b[1] << 8 | (uint64_t)b[2] << 16 | (uint64_t)b[3] << 24 | (uint64_t)b[4] << 32;
}

static void naps_cbi(const naps_t *n, uint64_t i, cbi_t *o) {
    const uint8_t *b = n->blob + n->cbi_off + i * 9;
    uint64_t lo = le64(b);
    unsigned hi = b[8];
    o->low = (uint32_t)(lo & 0x3FFFF);
    o->run = (int)((lo >> 18) & 1);
    o->term = (int)((lo >> 19) & 1);
    o->uoff = (uint32_t)((lo >> 20) & 0x3FFFF);
    o->clen_m1 = (uint32_t)((lo >> 38) & 0x1FFFF);
    o->even = (uint32_t)((lo >> 55) & 7);
    o->odd = (uint32_t)((lo >> 58) & 7);
    o->kde = (uint32_t)(((lo >> 61) & 7) | (hi & 7) << 3);
    o->shuf = (hi >> 4) & 0xF;
    o->costart256 = ((lo >> 50) | (uint64_t)hi << 14) & 0x3FFFFF;
}

static uint64_t naps_u2c(const naps_t *n, uint64_t ub) {
    const uint8_t *b = n->blob + n->u2c_off + (ub >> 3) * 10;
    uint64_t base = (uint64_t)b[0] | (uint64_t)b[1] << 8 | (uint64_t)b[2] << 16;
    return (ub & 7) == 0 ? base : base + b[3 + (ub & 7) - 1];
}

static int naps_resolve(const naps_t *n, uint64_t uoff, uint64_t *out) {
    uint64_t ub = uoff >> 18;
    if (ub >= n->ublocks) return -1;
    uint64_t a = naps_u2c(n, ub);
    uint64_t b = ub + 1 < n->ublocks ? naps_u2c(n, ub + 1) : n->ncbi;
    if (b > n->ncbi) b = n->ncbi;
    for (uint64_t i = a; i < b; i++) {
        cbi_t e;
        naps_cbi(n, i, &e);
        if (!e.run && !e.term && uoff == (ub << 18) + e.uoff) {
            *out = i;
            return 0;
        }
    }
    return -1;
}

static uint32_t d18(uint32_t nx, uint32_t pv) {
    return nx > pv ? nx - pv : nx - pv + SPAN_MAX; /* (modular) 18-bit distance, 0 -> 256 KiB */
}

/* Port of ProsperoNapsImage.BuildPlan. */
static int naps_plan(const naps_t *n, span_t **out, size_t *count, uint64_t *usize, uint64_t *meta_off, char *err,
                     size_t errlen) {
    span_t *sp = NULL;
    size_t ns = 0, cap = 0;
    int have_prev = 0;
    uint64_t prev_coff = 0;
    uint32_t prev_clen = 0;
    if (n->nfiles < 2) return fail(err, errlen, "NAPS layout has no files");
    for (uint64_t i = 0; i + 1 < n->nfiles; i++) {
        unsigned typ;
        uint64_t uoff, next;
        unsigned t2;
        naps_file(n, i, &typ, &uoff);
        naps_file(n, i + 1, &t2, &next);
        if (next < uoff) {
            free(sp);
            return fail(err, errlen, "NAPS file offsets not monotonic");
        }
        if (i + 2 == n->nfiles) *meta_off = uoff; /* last logical file = inner PFS metadata */
        if (typ & 0x40) continue;
        uint64_t pos = uoff, rem = next - uoff, k = 0;
        if (rem && naps_resolve(n, pos, &k)) {
            free(sp);
            return fail(err, errlen, "NAPS: no cblock at 0x%llx", (unsigned long long)pos);
        }
        while (rem) {
            cbi_t e, n1, n2;
            if (k + 1 >= n->ncbi) goto bad;
            naps_cbi(n, k, &e);
            if (e.run) {
                k++;
                continue;
            }
            if (e.term) goto bad;
            naps_cbi(n, k + 1, &n1);
            uint64_t k2 = n1.run ? k + 2 : k + 1;
            if (k2 >= n->ncbi) goto bad;
            naps_cbi(n, k2, &n2);
            if (n2.run) goto bad;
            uint32_t clen = d18(n1.low, e.low); /* coend (run) / costart share the low 18 bits */
            uint32_t ulen = d18(n2.uoff, e.uoff);
            if (clen == 0 || ulen == 0 || ulen > SPAN_MAX || ulen > rem) goto bad;
            uint64_t coff;
            if (k > 0) {
                cbi_t r;
                naps_cbi(n, k - 1, &r);
                if (r.run) {
                    coff = (r.costart256 << 18) | e.low;
                    goto have_coff;
                }
            }
            if (!have_prev) goto bad;
            coff = prev_coff + prev_clen;
        have_coff:
            if (ns == cap) {
                size_t nc = cap ? cap * 2 : 1u << 16;
                span_t *t = realloc(sp, nc * sizeof *sp);
                if (!t) {
                    free(sp);
                    return fail(err, errlen, "out of memory");
                }
                sp = t;
                cap = nc;
            }
            span_t *s = &sp[ns++];
            s->uoff = pos;
            s->coff = coff;
            s->clen = clen;
            s->ulen = ulen;
            s->first = e.clen_m1 + 1;
            s->fl = (uint16_t)(e.even | e.odd << 3 | e.kde << 6 | e.shuf << 12);
            prev_coff = coff;
            prev_clen = clen;
            have_prev = 1;
            pos += ulen;
            rem -= ulen;
            k++;
        }
    }
    if (ns && ns < cap) {
        span_t *t = realloc(sp, ns * sizeof *sp);
        if (t) sp = t;
    }
    naps_file(n, n->nfiles - 1, &(unsigned){0}, usize);
    *out = sp;
    *count = ns;
    return 0;
bad:
    free(sp);
    return fail(err, errlen, "NAPS: bad cblock chain");
}

/* ------------------------------------------------------------ span decode / logical reads */
static int decode_span(fih_t *f, const span_t *s, uint8_t *dst) {
    unsigned even = s->fl & 7, odd = (s->fl >> 3) & 7, kde = (s->fl >> 6) & 0x3F, shuf = (s->fl >> 12) & 0xF;
    if (s->clen == s->ulen) {
        if (io_read(&f->io, f->img_off + s->coff, dst, s->ulen)) return -1;
        f->n_stored++;
        return 0;
    }
    if (s->clen <= 16 && even == 1 && s->ulen > s->clen) { /* deduplicated all-zero span */
        memset(dst, 0, s->ulen);
        f->n_zero++;
        return 0;
    }
    if (kde || shuf) return -1; /* predictor / shuffle codecs not supported */
    if (io_read(&f->io, f->img_off + s->coff, f->raw, s->clen)) return -1;
    int flags = (even & 4 ? 2 : 0) | (even & 2 ? 1 : 0) | (odd & 4 ? 32 : 0) | (odd & 2 ? 16 : 0);
    if (kraken_decode_block(f->raw, s->clen, flags, s->ulen > 131072 ? (int)s->first : 0, dst, s->ulen)) return -1;
    f->n_kraken++;
    return 0;
}

/* returns the decoded span (cache owned) or NULL */
static const uint8_t *span_data(fih_t *f, size_t idx) {
    int victim = 0;
    uint64_t oldest = UINT64_MAX;
    for (int k = 0; k < CACHE_SLOTS; k++) {
        if (f->slots[k].idx == (int64_t)idx) {
            f->slots[k].tick = ++f->tick;
            return f->slots[k].buf;
        }
        if (f->slots[k].idx < 0) {
            if (oldest) victim = k;
            oldest = 0;
        } else if (oldest && f->slots[k].tick < oldest) {
            oldest = f->slots[k].tick;
            victim = k;
        }
    }
    slot_t *sl = &f->slots[victim];
    if (!sl->buf) {
        sl->buf = malloc(SPAN_MAX);
        if (!sl->buf) return NULL;
    }
    sl->idx = -1;
    if (decode_span(f, &f->spans[idx], sl->buf)) return NULL;
    sl->idx = (int64_t)idx;
    sl->tick = ++f->tick;
    return sl->buf;
}

/* index of the last span with uoff <= off, or (size_t)-1 */
static size_t span_find(fih_t *f, uint64_t off) {
    size_t h = f->hint;
    if (h < f->nspans) {
        const span_t *s = &f->spans[h];
        if (off >= s->uoff && off < s->uoff + s->ulen) return h;
        if (h + 1 < f->nspans && off >= f->spans[h + 1].uoff && off < f->spans[h + 1].uoff + f->spans[h + 1].ulen)
            return h + 1;
    }
    size_t lo = 0, hi = f->nspans; /* first span with uoff > off */
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (f->spans[mid].uoff <= off) lo = mid + 1;
        else hi = mid;
    }
    return lo ? lo - 1 : (size_t)-1;
}

int fih_read(fih_t *f, uint64_t off, void *buf, size_t n) {
    uint8_t *out = buf;
    if (n == 0) return 0;
    if (off > f->usize || n > f->usize - off) return -1;
    while (n) {
        size_t i = span_find(f, off);
        uint64_t cover_end = 0; /* end of the span containing off, if any */
        if (i != (size_t)-1) cover_end = f->spans[i].uoff + f->spans[i].ulen;
        if (i != (size_t)-1 && off < cover_end) {
            const uint8_t *d = span_data(f, i);
            if (!d) return -1;
            f->hint = i;
            size_t o = (size_t)(off - f->spans[i].uoff);
            size_t k = f->spans[i].ulen - o < n ? f->spans[i].ulen - o : n;
            memcpy(out, d + o, k);
            out += k;
            off += k;
            n -= k;
        } else { /* hole between spans (sparse logical file): zeros */
            uint64_t next = i + 1 < f->nspans ? f->spans[i + 1].uoff : f->usize;
            if (i == (size_t)-1) next = f->nspans ? f->spans[0].uoff : f->usize;
            size_t k = next - off < n ? (size_t)(next - off) : n;
            if (k == 0) return -1;
            memset(out, 0, k);
            out += k;
            off += k;
            n -= k;
        }
    }
    return 0;
}

/* ------------------------------------------------------------ outer PFS */
typedef struct {
    int64_t start;
    uint64_t size;
    int found;
} outer_file_t;

/* seen[]: one flag per outer inode. A directory inode may be visited once; a crafted image that
 * lists the same directory under many parents would otherwise multiply the work per level. */
static int outer_walk(fih_t *f, uint64_t base, const uint8_t *itab, uint64_t nino, uint32_t ino, int depth,
                      uint8_t *seen, outer_file_t *img, outer_file_t *lay) {
    if (depth > 6 || ino >= nino) return -1;
    if (seen[ino]) return -1;
    seen[ino] = 1;
    const uint8_t *in = itab + (size_t)ino * 0x2C8;
    int32_t start = (int32_t)le32(in + 0x64 + 32);
    if (start < 0) return -1;
    uint8_t *blk = malloc(BS);
    if (!blk) return -1;
    int rc = 0;
    if (io_read(&f->io, base + (uint64_t)start * BS, blk, BS)) rc = -1;
    size_t pos = 0;
    while (!rc && pos + 16 <= BS) {
        uint32_t i2 = le32(blk + pos), nl = le32(blk + pos + 8), es = le32(blk + pos + 12);
        int typ = (int32_t)le32(blk + pos + 4);
        if (es == 0) break;
        if (es < 16 || pos + es > BS || nl > es - 16) {
            rc = -1;
            break;
        }
        size_t l = 0;
        while (l < nl && blk[pos + 16 + l]) l++;
        const char *nm = (const char *)blk + pos + 16;
        if (typ == 2 && i2 < nino) {
            const uint8_t *fi = itab + (size_t)i2 * 0x2C8;
            outer_file_t t = {(int32_t)le32(fi + 0x64 + 32), le64(fi + 8), 1};
            if (l == 13 && !memcmp(nm, "pfs_image.dat", 13)) *img = t;
            else if (l == 19 && !memcmp(nm, "naps_pkg_layout.dat", 19)) *lay = t;
        } else if (typ == 3) {
            if (outer_walk(f, base, itab, nino, i2, depth + 1, seen, img, lay)) rc = -1;
        }
        pos += es;
    }
    free(blk);
    return rc;
}

/* ------------------------------------------------------------ inner PFS */
typedef struct {
    fih_t *f;
    fih_walk_cb cb;
    void *ctx;
    char *err;
    size_t errlen;
} walk_t;

typedef struct {
    uint32_t ino;
    uint8_t *name;
    size_t nl;
} dent_t;

static int read_dir(fih_t *f, uint64_t dir, uint8_t **data, size_t *len) {
    if (dir >= f->ninodes) return -1;
    const inode_t *n = &f->ino[dir];
    if (n->size > MAX_DIR_BYTES || n->off < 0 || (uint64_t)n->off > f->usize || n->size > f->usize - (uint64_t)n->off)
        return -1;
    *data = malloc(n->size ? (size_t)n->size : 1);
    if (!*data) return -1;
    if (fih_read(f, (uint64_t)n->off, *data, (size_t)n->size)) {
        free(*data);
        *data = NULL;
        return -1;
    }
    *len = (size_t)n->size;
    return 0;
}

/* iterates dirents; cb(ino,type,name,nl) nonzero stops. Returns 0 / -1 (corrupt) / 1 (stopped) */
static int dir_iter(const uint8_t *d, size_t len, int (*cb)(void *, uint32_t, int, const uint8_t *, size_t),
                    void *ctx) {
    size_t pos = 0;
    while (pos + 16 <= len) {
        uint32_t ino = le32(d + pos), nl = le32(d + pos + 8), es = le32(d + pos + 12);
        int typ = (int32_t)le32(d + pos + 4);
        if (es == 0) break;
        if (es < 16 || pos + es > len || nl > es - 16) return -1;
        size_t l = 0;
        while (l < nl && d[pos + 16 + l]) l++;
        int r = cb(ctx, ino, typ, d + pos + 16, l);
        if (r) return r < 0 ? -1 : 1;
        pos += es;
    }
    return 0;
}

typedef struct {
    int64_t found;
} uroot_t;

static int uroot_cb(void *c, uint32_t ino, int type, const uint8_t *name, size_t nl) {
    (void)type;
    if (nl == 5 && !memcmp(name, "uroot", 5)) {
        ((uroot_t *)c)->found = ino;
        return 1;
    }
    return 0;
}

typedef struct {
    dent_t *dirs, *files;
    size_t nd, cd, nf, cf;
    int oom;
} collect_t;

static int collect_cb(void *c, uint32_t ino, int type, const uint8_t *name, size_t nl) {
    collect_t *w = c;
    if (type != 2 && type != 3) return 0;
    dent_t **arr = type == 3 ? &w->dirs : &w->files;
    size_t *cnt = type == 3 ? &w->nd : &w->nf, *cap = type == 3 ? &w->cd : &w->cf;
    if (*cnt == *cap) {
        size_t nc = *cap ? *cap * 2 : 16;
        dent_t *t = realloc(*arr, nc * sizeof **arr);
        if (!t) {
            w->oom = 1;
            return -1;
        }
        *arr = t;
        *cap = nc;
    }
    uint8_t *copy = malloc(nl ? nl : 1);
    if (!copy) {
        w->oom = 1;
        return -1;
    }
    memcpy(copy, name, nl);
    (*arr)[*cnt].ino = ino;
    (*arr)[*cnt].name = copy;
    (*arr)[*cnt].nl = nl;
    (*cnt)++;
    return 0;
}

static int walk_dir(walk_t *w, uint64_t dir, const char *prefix, int depth) {
    fih_t *f = w->f;
    if (depth > MAX_DEPTH || dir >= f->ninodes || f->dir_seen[dir]) return fail(w->err, w->errlen, "inner PFS directory walk failed (corrupt or cyclic)");
    f->dir_seen[dir] = 1;
    uint8_t *data = NULL;
    size_t len = 0;
    collect_t c;
    memset(&c, 0, sizeof c);
    int rc = 0;
    if (read_dir(f, dir, &data, &len)) {
        rc = fail(w->err, w->errlen, "cannot read inner PFS directory");
        goto done;
    }
    if (dir_iter(data, len, collect_cb, &c) < 0) {
        rc = fail(w->err, w->errlen, c.oom ? "out of memory" : "corrupt inner PFS directory");
        goto done;
    }
    for (size_t i = 0; i < c.nf && !rc; i++) {
        if (c.files[i].ino >= f->ninodes) {
            rc = fail(w->err, w->errlen, "bad inode in inner PFS");
            break;
        }
        const inode_t *n = &f->ino[c.files[i].ino];
        if (n->off < 0 || (uint64_t)n->off > f->usize || n->size > f->usize - (uint64_t)n->off) {
            rc = fail(w->err, w->errlen, "inner PFS file outside the image");
            break;
        }
        if (w->cb(w->ctx, prefix, c.files[i].name, c.files[i].nl, 0, n->size, (uint64_t)n->off) < 0)
            rc = fail(w->err, w->errlen, "out of memory");
    }
    for (size_t i = 0; i < c.nd && !rc; i++) {
        int r = w->cb(w->ctx, prefix, c.dirs[i].name, c.dirs[i].nl, 1, 0, 0);
        if (r < 0) {
            rc = fail(w->err, w->errlen, "out of memory");
            break;
        }
        if (r > 0) continue;
        size_t pl = strlen(prefix);
        char *sub = malloc(pl + 1 + c.dirs[i].nl + 1);
        if (!sub) {
            rc = fail(w->err, w->errlen, "out of memory");
            break;
        }
        memcpy(sub, prefix, pl);
        if (pl) sub[pl++] = '/';
        memcpy(sub + pl, c.dirs[i].name, c.dirs[i].nl);
        sub[pl + c.dirs[i].nl] = 0;
        rc = walk_dir(w, c.dirs[i].ino, sub, depth + 1);
        free(sub);
    }
done:
    for (size_t i = 0; i < c.nd; i++) free(c.dirs[i].name);
    for (size_t i = 0; i < c.nf; i++) free(c.files[i].name);
    free(c.dirs);
    free(c.files);
    free(data);
    return rc;
}

int fih_walk(fih_t *f, fih_walk_cb cb, void *ctx, char *err, size_t errlen) {
    uint8_t *rd = NULL;
    size_t rl = 0;
    uroot_t u = {-1};
    if (read_dir(f, 0, &rd, &rl)) return fail(err, errlen, "cannot read inner PFS root");
    int r = dir_iter(rd, rl, uroot_cb, &u);
    free(rd);
    if (r < 0 || u.found < 0) return fail(err, errlen, "inner PFS has no uroot");
    free(f->dir_seen);
    f->dir_seen = calloc((size_t)f->ninodes, 1);
    if (!f->dir_seen) return fail(err, errlen, "out of memory");
    walk_t w = {f, cb, ctx, err, errlen};
    return walk_dir(&w, (uint64_t)u.found, "", 0);
}

static int inner_open(fih_t *f, uint64_t meta_off, char *err, size_t errlen) {
    uint8_t *sb = malloc(0x400);
    uint8_t *blk = NULL;
    int rc = -1;
    if (!sb) return fail(err, errlen, "out of memory");
    if (fih_read(f, meta_off, sb, 0x400)) {
        fail(err, errlen, "cannot read inner PFS superblock");
        goto out;
    }
    uint16_t mode = le16(sb + 28);
    uint32_t bs = le32(sb + 32);
    uint64_t ni = le64(sb + 0x30);
    if (le64(sb) != 2 || le64(sb + 8) != 20130315ull || !(mode & 0x10)) {
        fail(err, errlen, "unsupported inner PFS (version/magic/mode 0x%x)", mode);
        goto out;
    }
    if (bs < 4096 || bs > (1u << 24) || (bs & (bs - 1)) || bs / 168 == 0 || ni == 0 || ni > (1u << 24)) {
        fail(err, errlen, "bad inner PFS geometry");
        goto out;
    }
    f->ibs = bs;
    f->ninodes = ni;
    f->ino = calloc((size_t)ni, sizeof *f->ino);
    blk = malloc(bs);
    if (!f->ino || !blk) {
        fail(err, errlen, "out of memory");
        goto out;
    }
    size_t per = bs / 168;
    for (uint64_t b = 0, n = 0; n < ni; b++) {
        if (fih_read(f, meta_off + bs + b * bs, blk, bs)) {
            fail(err, errlen, "cannot read inner PFS inode table");
            goto out;
        }
        for (size_t j = 0; j < per && n < ni; j++, n++) {
            const uint8_t *r = blk + j * 168;
            f->ino[n].size = le64(r + 8);
            f->ino[n].off = (int64_t)le64(r + 0x60);
        }
    }
    rc = 0;
out:
    free(sb);
    free(blk);
    return rc;
}

/* ------------------------------------------------------------ open */
int fih_open(const pkgr_io_t *io_in, fih_t **out, char *err, size_t errlen) {
    fih_t *f = calloc(1, sizeof *f);
    uint8_t *h = NULL, *lay = NULL, *sbblk = NULL, *itab = NULL;
    *out = NULL;
    if (!f) {
        if (io_in->close) io_in->close(io_in->ctx);
        return fail(err, errlen, "out of memory");
    }
    f->io = *io_in;
    for (int i = 0; i < CACHE_SLOTS; i++) f->slots[i].idx = -1;
    f->raw = malloc(SPAN_MAX);
    h = malloc(0x1000);
    if (!f->raw || !h) {
        fail(err, errlen, "out of memory");
        goto fail;
    }
    if (f->io.size < 0x20000 || io_read(&f->io, 0, h, 0x1000) || memcmp(h, "\x7f" "FIH", 4)) {
        fail(err, errlen, "not a FIH package");
        goto fail;
    }
    uint64_t pfs_off = le64(h + 0x10), pfs_size = le64(h + 0x18), cnt_off = le64(h + 0x58);
    uint32_t inner_blocks = le32(h + 0x90);
    uint64_t naps_size = le64(h + 0xA8);
    uint64_t fsz = f->io.size;
    if (pfs_off % BS || pfs_off > fsz || pfs_size > fsz - pfs_off || cnt_off > fsz || fsz - cnt_off < 0x600) {
        fail(err, errlen, "bad FIH header");
        goto fail;
    }
    uint64_t sb_index = (uint64_t)inner_blocks + (naps_size + BS - 1) / BS;
    uint64_t sb_off = pfs_off + sb_index * BS;
    if (sb_off + 2 * (uint64_t)BS > pfs_off + pfs_size) {
        fail(err, errlen, "FIH superblock outside the outer PFS");
        goto fail;
    }

    /* embedded CNT */
    f->cnt_off = cnt_off;
    {
        uint8_t c[0x600];
        if (io_read(&f->io, cnt_off, c, sizeof c) || memcmp(c, "\x7f" "CNT", 4)) {
            fail(err, errlen, "bad embedded CNT");
            goto fail;
        }
        f->n_cnt = be32(c + 0x10);
        uint32_t tab = be32(c + 0x18);
        size_t l = 0;
        while (l < 0x30 && c[0x40 + l]) l++;
        memcpy(f->content_id, c + 0x40, l < sizeof f->content_id ? l : sizeof f->content_id - 1);
        if (f->n_cnt == 0 || f->n_cnt > 4096 || (uint64_t)tab + (uint64_t)f->n_cnt * 32 > fsz - cnt_off) {
            fail(err, errlen, "bad embedded CNT entry table");
            goto fail;
        }
        f->cnt_tab = malloc((size_t)f->n_cnt * 32);
        if (!f->cnt_tab || io_read(&f->io, cnt_off + tab, f->cnt_tab, (size_t)f->n_cnt * 32)) {
            fail(err, errlen, "cannot read CNT entry table");
            goto fail;
        }
    }

    /* outer PFS superblock + inodes */
    sbblk = malloc(BS);
    itab = malloc(BS);
    if (!sbblk || !itab) {
        fail(err, errlen, "out of memory");
        goto fail;
    }
    if (io_read(&f->io, sb_off, sbblk, BS) || le64(sbblk) != 2 || le64(sbblk + 8) != 20130315ull) {
        fail(err, errlen, "bad outer PFS superblock");
        goto fail;
    }
    if (memcmp(sbblk + 0x370, "PPRPLAIN-NOAUTH!", 16)) {
        fail(err, errlen, "encrypted FIH package not supported yet");
        goto fail;
    }
    uint64_t nino = le64(sbblk + 0x30);
    if (nino == 0 || nino > BS / 0x2C8 || io_read(&f->io, sb_off + BS, itab, BS)) {
        fail(err, errlen, "bad outer PFS inode table");
        goto fail;
    }
    outer_file_t img = {0, 0, 0}, lf = {0, 0, 0};
    uint8_t *outer_seen = (uint8_t *)calloc((size_t)nino ? (size_t)nino : 1, 1);
    int walk_rc = outer_seen ? outer_walk(f, pfs_off, itab, nino, 0, 0, outer_seen, &img, &lf) : -1;
    free(outer_seen);
    if (walk_rc || !img.found || !lf.found) {
        fail(err, errlen, "outer PFS lacks pfs_image.dat / naps_pkg_layout.dat");
        goto fail;
    }
    if (img.start < 0 || lf.start < 0 || lf.size < 16 || lf.size > (1u << 30) ||
        pfs_off + (uint64_t)img.start * BS > fsz || pfs_off + (uint64_t)lf.start * BS > fsz ||
        lf.size > fsz - (pfs_off + (uint64_t)lf.start * BS)) {
        fail(err, errlen, "bad outer PFS file extents");
        goto fail;
    }
    f->img_off = pfs_off + (uint64_t)img.start * BS;

    /* NAPS layout -> span plan (the layout blob is dropped afterwards) */
    lay = malloc((size_t)lf.size);
    if (!lay || io_read(&f->io, pfs_off + (uint64_t)lf.start * BS, lay, (size_t)lf.size)) {
        fail(err, errlen, lay ? "cannot read naps_pkg_layout.dat" : "out of memory");
        goto fail;
    }
    naps_t nl;
    if (naps_parse(&nl, lay, (size_t)lf.size)) {
        fail(err, errlen, "bad naps_pkg_layout.dat");
        goto fail;
    }
    uint64_t meta_off = 0;
    if (naps_plan(&nl, &f->spans, &f->nspans, &f->usize, &meta_off, err, errlen)) goto fail;
    free(lay);
    lay = NULL;
    if (inner_open(f, meta_off, err, errlen)) goto fail;

    free(h);
    free(sbblk);
    free(itab);
    *out = f;
    return 0;
fail:
    free(h);
    free(lay);
    free(sbblk);
    free(itab);
    fih_close(f);
    return -1;
}
