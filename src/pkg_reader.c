/* PKG reader: see pkg_reader.h. Layer stack (each layer is a random-access
 * byte source):
 *
 *   raw file window (outer PFS image inside the CNT)
 *     -> AES-XTS decrypt (sectors >= first block; per-sector LRU cache)
 *     -> outer PFS (signed, block maps)  -> file pfs_image.dat
 *     -> PFSC (zlib sectors; LRU cache of decoded blocks)
 *     -> inner PFS (unsigned)            -> /app0 tree
 */
#define _POSIX_C_SOURCE 200809L
#define _FILE_OFFSET_BITS 64

#include "pkg_reader.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "crypto.h"
#include "miniz.h"

#ifndef PKGR_NO_RSA /* define to build without the RSA IMAGE_KEY route */
#define HAVE_RSA 1
#endif
#ifdef HAVE_RSA
#include "pkg_keys.h"
#include "rsa.h"
#endif

#define XTS_SS 0x1000u
#define XTS_SLOTS 64
#define PFSC_SLOTS 16
#define XTS_BULK_SECTORS 64u /* 256 KiB per bulk pread */
#define MAX_DEPTH 48

/* ------------------------------------------------------------ byte helpers */
static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static uint64_t le64(const uint8_t *p) { return le32(p) | (uint64_t)le32(p + 4) << 32; }
static uint32_t be32(const uint8_t *p) {
    return (uint32_t)p[3] | (uint32_t)p[2] << 8 | (uint32_t)p[1] << 16 | (uint32_t)p[0] << 24;
}
static uint64_t be64(const uint8_t *p) { return (uint64_t)be32(p) << 32 | be32(p + 4); }

/* ------------------------------------------------------------------ layers */
typedef struct layer layer_t;
struct layer {
    int (*rd)(layer_t *l, uint64_t pos, void *buf, size_t n); /* 0 ok, -1 error; must be in range */
    void (*destroy)(layer_t *l);
    uint64_t size;
};

static int layer_read(layer_t *l, uint64_t pos, void *buf, size_t n) {
    if (n == 0) return 0;
    if (pos > l->size || n > l->size - pos) return -1;
    return l->rd(l, pos, buf, n);
}

/* raw window over the file */
typedef struct {
    layer_t l;
    int fd;
    uint64_t base;
} raw_layer_t;

static int pread_full(int fd, void *buf, size_t n, uint64_t off) {
    uint8_t *b = buf;
    while (n) {
        ssize_t r = pread(fd, b, n, (off_t)off);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return -1;
        b += r;
        n -= (size_t)r;
        off += (uint64_t)r;
    }
    return 0;
}

static int raw_rd(layer_t *l, uint64_t pos, void *buf, size_t n) {
    raw_layer_t *r = (raw_layer_t *)l;
    return pread_full(r->fd, buf, n, r->base + pos);
}

/* AES-XTS layer */
typedef struct {
    uint64_t sector;
    uint64_t tick;
    int valid;
} xts_slot_t;

typedef struct {
    layer_t l;
    layer_t *src;
    uint8_t tk[16], dk[16];
    uint64_t start_sector; /* sectors below this are plaintext */
    xts_slot_t slots[XTS_SLOTS];
    uint8_t *data; /* XTS_SLOTS * XTS_SS */
    uint64_t tick;
} xts_layer_t;

static void xts_destroy(layer_t *l) { free(((xts_layer_t *)l)->data); }

static int xts_decrypt_run(xts_layer_t *x, uint64_t first, uint8_t *buf, size_t nsec) {
    /* buf holds raw sectors first..first+nsec-1 */
    uint64_t skip = 0;
    if (first < x->start_sector) {
        skip = x->start_sector - first;
        if (skip >= nsec) return 0;
    }
    return aes_xts_decrypt(x->dk, x->tk, first + skip, XTS_SS, buf + skip * XTS_SS, buf + skip * XTS_SS,
                           (size_t)(nsec - skip) * XTS_SS);
}

static const uint8_t *xts_sector(xts_layer_t *x, uint64_t i, size_t *avail) {
    int victim = 0;
    uint64_t oldest = UINT64_MAX;
    for (int k = 0; k < XTS_SLOTS; k++) {
        if (x->slots[k].valid && x->slots[k].sector == i) {
            x->slots[k].tick = ++x->tick;
            *avail = XTS_SS;
            return x->data + (size_t)k * XTS_SS;
        }
        if (!x->slots[k].valid) {
            victim = k;
            oldest = 0;
        } else if (oldest && x->slots[k].tick < oldest) {
            oldest = x->slots[k].tick;
            victim = k;
        }
    }
    uint8_t *d = x->data + (size_t)victim * XTS_SS;
    uint64_t off = i * XTS_SS;
    size_t n = x->l.size - off < XTS_SS ? (size_t)(x->l.size - off) : XTS_SS;
    x->slots[victim].valid = 0;
    if (layer_read(x->src, off, d, n)) return NULL;
    if (n != XTS_SS) memset(d + n, 0, XTS_SS - n); /* never for well-formed images */
    if (xts_decrypt_run(x, i, d, 1)) return NULL;
    x->slots[victim].valid = 1;
    x->slots[victim].sector = i;
    x->slots[victim].tick = ++x->tick;
    *avail = XTS_SS;
    return d;
}

static int xts_rd(layer_t *l, uint64_t pos, void *buf, size_t n) {
    xts_layer_t *x = (xts_layer_t *)l;
    uint8_t *out = buf;
    while (n) {
        uint64_t i = pos / XTS_SS;
        size_t o = (size_t)(pos % XTS_SS);
        if (o == 0 && n >= XTS_SS && (i + 1) * XTS_SS <= x->l.size) {
            size_t cnt = n / XTS_SS;
            if (cnt > XTS_BULK_SECTORS) cnt = XTS_BULK_SECTORS;
            if (layer_read(x->src, pos, out, cnt * XTS_SS)) return -1;
            if (xts_decrypt_run(x, i, out, cnt)) return -1;
            out += cnt * XTS_SS;
            pos += cnt * XTS_SS;
            n -= cnt * XTS_SS;
            continue;
        }
        size_t avail;
        const uint8_t *s = xts_sector(x, i, &avail);
        if (!s) return -1;
        size_t k = XTS_SS - o < n ? XTS_SS - o : n;
        memcpy(out, s + o, k);
        out += k;
        pos += k;
        n -= k;
    }
    return 0;
}

/* ------------------------------------------------------------- PFS (generic) */
typedef struct {
    int32_t db[12], ib[5];
    uint64_t size;
    uint32_t blocks;
    uint32_t flags;
    uint16_t mode;
} inode_t;

typedef struct {
    layer_t *src; /* not owned */
    uint32_t bs;
    int is_signed;
    uint32_t mode;
    uint8_t seed[16];
    uint64_t ninodes;
    inode_t *ino;
} pfs_t;

typedef struct {
    uint64_t size;
    int64_t start; /* first block when contiguous */
    uint32_t nblocks;
    int32_t *map; /* NULL = contiguous */
} fmap_t;

static void pfs_free(pfs_t *p) {
    free(p->ino);
    memset(p, 0, sizeof *p);
}

static int pfs_header(layer_t *src, uint32_t *bs, uint32_t *mode, uint8_t seed[16], uint64_t *ndi,
                      uint64_t *dblocks) {
    uint8_t h[0x400];
    if (layer_read(src, 0, h, sizeof h)) return -1;
    if (le64(h) != 1 || le64(h + 8) != 20130315ull) return -1;
    *mode = le16(h + 0x1c);
    *bs = le32(h + 0x20);
    *ndi = le64(h + 0x30);
    *dblocks = le64(h + 0x40);
    memcpy(seed, h + 0x370, 16);
    return 0;
}

static int pfs_open(pfs_t *p, layer_t *src) {
    uint64_t dblocks;
    memset(p, 0, sizeof *p);
    p->src = src;
    if (pfs_header(src, &p->bs, &p->mode, p->seed, &p->ninodes, &dblocks)) return -1;
    if (p->bs < 0x1000 || p->bs > (1u << 24) || (p->bs & (p->bs - 1))) return -1;
    p->is_signed = p->mode & 1;
    size_t isz = p->is_signed ? 0x2C8 : 0xA8;
    size_t per = p->bs / isz;
    if (p->ninodes == 0 || p->ninodes > (1u << 24) || dblocks > (1u << 20) || p->ninodes > dblocks * per) return -1;
    p->ino = calloc((size_t)p->ninodes, sizeof(inode_t));
    uint8_t *blk = malloc(p->bs);
    if (!p->ino || !blk) goto fail;
    uint64_t n = 0;
    for (uint64_t b = 0; b < dblocks && n < p->ninodes; b++) {
        if (layer_read(src, p->bs + b * p->bs, blk, p->bs)) goto fail;
        for (size_t j = 0; j < per && n < p->ninodes; j++, n++) {
            const uint8_t *r = blk + j * isz;
            inode_t *d = &p->ino[n];
            d->mode = le16(r);
            d->flags = le32(r + 4);
            d->size = le64(r + 8);
            d->blocks = le32(r + 0x60);
            for (int k = 0; k < 12; k++)
                d->db[k] = (int32_t)le32(r + 0x64 + (p->is_signed ? (size_t)k * 36 + 32 : (size_t)k * 4));
            for (int k = 0; k < 5; k++)
                d->ib[k] = (int32_t)le32(r + 0x64 + (p->is_signed ? (size_t)(12 + k) * 36 + 32 : 48 + (size_t)k * 4));
        }
    }
    free(blk);
    return 0;
fail:
    free(blk);
    pfs_free(p);
    return -1;
}

/* Builds the block map of file inode `ino` (mirrors the prototype). */
static int fmap_build(pfs_t *p, uint64_t ino, fmap_t *fm) {
    memset(fm, 0, sizeof *fm);
    if (ino >= p->ninodes) return -1;
    const inode_t *n = &p->ino[ino];
    fm->size = n->size;
    fm->nblocks = n->blocks;
    fm->start = n->db[0];
    if (!p->is_signed || n->blocks <= 1 || n->db[1] == -1) return 0;
    if (n->blocks > (1u << 24)) return -1;
    int32_t *bl = malloc((size_t)n->blocks * sizeof(int32_t));
    uint8_t *a = NULL, *b = NULL;
    if (!bl) return -1;
    uint32_t cnt = 0;
    for (; cnt < 12 && cnt < n->blocks; cnt++) bl[cnt] = n->db[cnt];
    int64_t rem = (int64_t)n->blocks - 12;
    uint32_t per = p->bs / 36;
    if (rem > 0) {
        a = malloc(p->bs);
        b = malloc(p->bs);
        if (!a || !b) goto fail;
        if (n->ib[0] < 0 || layer_read(p->src, (uint64_t)n->ib[0] * p->bs, a, p->bs)) goto fail;
        for (uint32_t i = 0; rem > 0 && i < per && i < (uint64_t)rem; i++) bl[cnt++] = (int32_t)le32(a + i * 36 + 32);
        rem -= per;
        for (uint32_t j = 0; rem > 0; j++) {
            if (n->ib[1] < 0 || j >= per) goto fail;
            if (layer_read(p->src, (uint64_t)n->ib[1] * p->bs + j * 36 + 32, a, 4)) goto fail;
            int32_t ind = (int32_t)le32(a);
            if (ind < 0 || layer_read(p->src, (uint64_t)ind * p->bs, b, p->bs)) goto fail;
            for (uint32_t i = 0; i < per && i < (uint64_t)rem; i++) bl[cnt++] = (int32_t)le32(b + i * 36 + 32);
            rem -= per;
        }
    }
    free(a);
    free(b);
    a = b = NULL;
    if (cnt != n->blocks) goto fail;
    int contiguous = 1;
    for (uint32_t i = 0; i + 1 < cnt; i++)
        if (bl[i] + 1 != bl[i + 1]) contiguous = 0;
    if (contiguous) {
        fm->start = bl[0];
        free(bl);
    } else {
        for (uint32_t i = 0; i < cnt; i++)
            if (bl[i] < 0) goto fail;
        fm->map = bl;
    }
    return 0;
fail:
    free(a);
    free(b);
    free(bl);
    return -1;
}

static int fmap_read(pfs_t *p, const fmap_t *fm, uint64_t pos, void *buf, size_t n) {
    uint8_t *out = buf;
    if (pos > fm->size || n > fm->size - pos) return -1;
    if (n == 0) return 0;
    if (!fm->map) {
        if (fm->start < 0) return -1;
        return layer_read(p->src, (uint64_t)fm->start * p->bs + pos, out, n);
    }
    while (n) {
        uint64_t bi = pos / p->bs;
        size_t o = (size_t)(pos % p->bs);
        if (bi >= fm->nblocks) return -1;
        /* coalesce consecutive blocks into one run */
        uint64_t last = bi;
        size_t run = p->bs - o;
        while (run < n && last + 1 < fm->nblocks && fm->map[last + 1] == fm->map[last] + 1) {
            last++;
            run += p->bs;
        }
        if (run > n) run = n;
        if (layer_read(p->src, (uint64_t)fm->map[bi] * p->bs + o, out, run)) return -1;
        out += run;
        pos += run;
        n -= run;
    }
    return 0;
}

/* iterate dirents of dir inode; cb returns nonzero to stop */
typedef int (*dirent_cb)(void *ctx, uint32_t ino, int type, const uint8_t *name, size_t namelen);

static int pfs_dir_iter(pfs_t *p, uint64_t dir, dirent_cb cb, void *ctx) {
    if (dir >= p->ninodes) return -1;
    const inode_t *n = &p->ino[dir];
    if (n->db[0] < 0 || n->blocks > (1u << 16)) return -1;
    uint8_t *blk = malloc(p->bs);
    if (!blk) return -1;
    int rc = 0;
    for (uint32_t x = 0; x < n->blocks && !rc; x++) {
        if (layer_read(p->src, ((uint64_t)n->db[0] + x) * p->bs, blk, p->bs)) {
            rc = -1;
            break;
        }
        size_t pos = 0;
        while (pos + 16 <= p->bs) {
            uint32_t ino = le32(blk + pos), nl = le32(blk + pos + 8), es = le32(blk + pos + 12);
            int type = (int32_t)le32(blk + pos + 4);
            if (es == 0) break;
            if (es < 16 || pos + es > p->bs || nl > es - 16) {
                rc = -1;
                break;
            }
            size_t l = 0;
            while (l < nl && blk[pos + 16 + l]) l++;
            int r = cb(ctx, ino, type, blk + pos + 16, l);
            if (r) {
                rc = r < 0 ? -1 : 1;
                break;
            }
            pos += es;
        }
    }
    free(blk);
    return rc;
}

typedef struct {
    const char *name;
    int want_type;
    int64_t found;
} find_ctx_t;

static int find_cb(void *c, uint32_t ino, int type, const uint8_t *name, size_t nl) {
    find_ctx_t *f = c;
    if (type == f->want_type && strlen(f->name) == nl && !memcmp(f->name, name, nl)) {
        f->found = ino;
        return 1;
    }
    return 0;
}

/* returns inode or -1 */
static int64_t pfs_find(pfs_t *p, uint64_t dir, const char *name, int type) {
    find_ctx_t f = {name, type, -1};
    int r = pfs_dir_iter(p, dir, find_cb, &f);
    return r == 1 ? f.found : -1;
}

/* A PFS file exposed as a layer */
typedef struct {
    layer_t l;
    pfs_t *pfs;
    fmap_t fm;
} pfsfile_layer_t;

static int pfsfile_rd(layer_t *l, uint64_t pos, void *buf, size_t n) {
    pfsfile_layer_t *f = (pfsfile_layer_t *)l;
    return fmap_read(f->pfs, &f->fm, pos, buf, n);
}
static void pfsfile_destroy(layer_t *l) { free(((pfsfile_layer_t *)l)->fm.map); }

/* ------------------------------------------------------------------- PFSC */
typedef struct {
    layer_t l;
    layer_t *src;
    uint32_t bsz;
    uint64_t nblocks;
    uint64_t *map; /* nblocks + 1 */
    uint8_t *data; /* PFSC_SLOTS * bsz */
    uint8_t *tmp;  /* bsz */
    struct {
        uint64_t blk, tick;
        int valid;
    } slot[PFSC_SLOTS];
    uint64_t tick;
} pfsc_layer_t;

static void pfsc_destroy(layer_t *l) {
    pfsc_layer_t *c = (pfsc_layer_t *)l;
    free(c->map);
    free(c->data);
    free(c->tmp);
}

/* decodes block i into out[bsz] */
static int pfsc_decode(pfsc_layer_t *c, uint64_t i, uint8_t *out) {
    uint64_t a = c->map[i], b = c->map[i + 1];
    if (b < a) return -1;
    uint64_t sz = b - a;
    if (sz == c->bsz) return layer_read(c->src, a, out, c->bsz);
    if (sz > c->bsz) {
        memset(out, 0, c->bsz);
        return 0;
    }
    if (sz < 3) return -1;
    if (layer_read(c->src, a, c->tmp, (size_t)sz)) return -1;
    /* skip the 2-byte zlib header, raw deflate follows (no adler check needed) */
    size_t r = tinfl_decompress_mem_to_mem(out, c->bsz, c->tmp + 2, (size_t)sz - 2, 0);
    if (r == (size_t)-1 || r > c->bsz) return -1;
    if (r < c->bsz) memset(out + r, 0, c->bsz - r);
    return 0;
}

static int pfsc_rd(layer_t *l, uint64_t pos, void *buf, size_t n) {
    pfsc_layer_t *c = (pfsc_layer_t *)l;
    uint8_t *out = buf;
    while (n) {
        uint64_t i = pos / c->bsz;
        size_t o = (size_t)(pos % c->bsz);
        if (i >= c->nblocks) return -1;
        if (o == 0 && n >= c->bsz) { /* whole block: decode straight into the caller's buffer */
            if (pfsc_decode(c, i, out)) return -1;
            out += c->bsz;
            pos += c->bsz;
            n -= c->bsz;
            continue;
        }
        int victim = 0, hit = -1;
        uint64_t oldest = UINT64_MAX;
        for (int k = 0; k < PFSC_SLOTS; k++) {
            if (c->slot[k].valid && c->slot[k].blk == i) {
                hit = k;
                break;
            }
            if (!c->slot[k].valid) {
                victim = k;
                oldest = 0;
            } else if (oldest && c->slot[k].tick < oldest) {
                oldest = c->slot[k].tick;
                victim = k;
            }
        }
        if (hit < 0) {
            c->slot[victim].valid = 0;
            if (pfsc_decode(c, i, c->data + (size_t)victim * c->bsz)) return -1;
            c->slot[victim].valid = 1;
            c->slot[victim].blk = i;
            hit = victim;
        }
        c->slot[hit].tick = ++c->tick;
        size_t k = c->bsz - o < n ? c->bsz - o : n;
        memcpy(out, c->data + (size_t)hit * c->bsz + o, k);
        out += k;
        pos += k;
        n -= k;
    }
    return 0;
}

/* ------------------------------------------------------------------- pkgr */
typedef struct {
    pkgr_entry_t pub;
    char *path;
    int kind; /* 0 dir, 1 inner PFS file, 2 CNT-resident */
    fmap_t fm;
    uint64_t cnt_off;
} entry_t;

struct pkgr {
    int fd;
    uint64_t file_size;
    char errbuf[160];
    char content_id[64];
    uint64_t pfs_flags, pfs_off, pfs_size;
    uint8_t ekpfs[32];

    uint32_t n_cnt;
    uint8_t *cnt_tab; /* n_cnt * 32 raw rows */

    raw_layer_t raw;
    xts_layer_t *xts;
    pfs_t outer;
    int outer_ok;
    pfsfile_layer_t *imgfile;
    pfsc_layer_t *pfsc;
    pfs_t inner;
    int inner_ok;

    entry_t *ents;
    size_t n_ents, cap_ents;
    uint64_t total;
};

static void set_err(pkgr_t *p, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(p->errbuf, sizeof p->errbuf, fmt, ap);
    va_end(ap);
}

static void free_entries(pkgr_t *p) {
    for (size_t i = 0; i < p->n_ents; i++) {
        free(p->ents[i].path);
        free(p->ents[i].fm.map);
    }
    free(p->ents);
    p->ents = NULL;
    p->n_ents = p->cap_ents = 0;
    p->total = 0;
}

static void free_stack(pkgr_t *p) {
    free_entries(p);
    if (p->inner_ok) pfs_free(&p->inner);
    p->inner_ok = 0;
    if (p->pfsc) {
        pfsc_destroy(&p->pfsc->l);
        free(p->pfsc);
        p->pfsc = NULL;
    }
    if (p->imgfile) {
        pfsfile_destroy(&p->imgfile->l);
        free(p->imgfile);
        p->imgfile = NULL;
    }
    if (p->outer_ok) pfs_free(&p->outer);
    p->outer_ok = 0;
    if (p->xts) {
        xts_destroy(&p->xts->l);
        free(p->xts);
        p->xts = NULL;
    }
}

void pkgr_close(pkgr_t *p) {
    if (!p) return;
    free_stack(p);
    free(p->cnt_tab);
    if (p->fd >= 0) close(p->fd);
    free(p);
}

static entry_t *add_entry(pkgr_t *p, const char *dirprefix, const uint8_t *name, size_t nl, int kind) {
    if (nl == 0 || (nl == 1 && name[0] == '.') || (nl == 2 && name[0] == '.' && name[1] == '.') || memchr(name, '/', nl))
        return NULL;
    if (p->n_ents == p->cap_ents) {
        size_t nc = p->cap_ents ? p->cap_ents * 2 : 64;
        entry_t *ne = realloc(p->ents, nc * sizeof *ne);
        if (!ne) return NULL;
        p->ents = ne;
        p->cap_ents = nc;
    }
    size_t pl = strlen(dirprefix);
    char *path = malloc(pl + 1 + nl + 1);
    if (!path) return NULL;
    memcpy(path, dirprefix, pl);
    if (pl) path[pl++] = '/';
    memcpy(path + pl, name, nl);
    path[pl + nl] = 0;
    entry_t *e = &p->ents[p->n_ents++];
    memset(e, 0, sizeof *e);
    e->path = path;
    e->pub.path = path;
    e->kind = kind;
    e->pub.is_dir = kind == 0;
    return e;
}

typedef struct {
    pkgr_t *p;
    const char *prefix;
    int depth;
    struct {
        uint32_t ino;
        uint8_t *name;
        size_t nl;
    } *dirs;
    size_t ndirs, cap;
    struct {
        uint32_t ino;
        uint8_t *name;
        size_t nl;
    } *files;
    size_t nfiles, capf;
    int err;
} walk_ctx_t;

static int walk_collect(void *c, uint32_t ino, int type, const uint8_t *name, size_t nl) {
    walk_ctx_t *w = c;
    if (type != 2 && type != 3) return 0;
    uint8_t *copy = malloc(nl ? nl : 1);
    if (!copy) {
        w->err = 1;
        return -1;
    }
    memcpy(copy, name, nl);
    if (type == 3) {
        if (w->ndirs == w->cap) {
            size_t nc = w->cap ? w->cap * 2 : 8;
            void *n = realloc(w->dirs, nc * sizeof *w->dirs);
            if (!n) {
                free(copy);
                w->err = 1;
                return -1;
            }
            w->dirs = n;
            w->cap = nc;
        }
        w->dirs[w->ndirs].ino = ino;
        w->dirs[w->ndirs].name = copy;
        w->dirs[w->ndirs++].nl = nl;
    } else {
        if (w->nfiles == w->capf) {
            size_t nc = w->capf ? w->capf * 2 : 16;
            void *n = realloc(w->files, nc * sizeof *w->files);
            if (!n) {
                free(copy);
                w->err = 1;
                return -1;
            }
            w->files = n;
            w->capf = nc;
        }
        w->files[w->nfiles].ino = ino;
        w->files[w->nfiles].name = copy;
        w->files[w->nfiles++].nl = nl;
    }
    return 0;
}

static int walk_dir(pkgr_t *p, uint64_t dir, const char *prefix, int depth) {
    if (depth > MAX_DEPTH) return -1;
    walk_ctx_t w;
    memset(&w, 0, sizeof w);
    w.p = p;
    int rc = pfs_dir_iter(&p->inner, dir, walk_collect, &w);
    if (rc < 0 || w.err) {
        rc = -1;
        goto done;
    }
    rc = 0;
    for (size_t i = 0; i < w.nfiles && !rc; i++) {
        if (w.files[i].ino >= p->inner.ninodes) {
            rc = -1;
            break;
        }
        entry_t *e = add_entry(p, prefix, w.files[i].name, w.files[i].nl, 1);
        if (!e) continue; /* unsafe name (skipped) */
        if (fmap_build(&p->inner, w.files[i].ino, &e->fm)) {
            rc = -1;
            break;
        }
        e->pub.size = e->fm.size;
        p->total += e->fm.size;
    }
    for (size_t i = 0; i < w.ndirs && !rc; i++) {
        entry_t *e = add_entry(p, prefix, w.dirs[i].name, w.dirs[i].nl, 0);
        if (!e) continue;
        char *sub = strdup(e->path); /* e may be invalidated by recursion */
        if (!sub) {
            rc = -1;
            break;
        }
        rc = walk_dir(p, w.dirs[i].ino, sub, depth + 1);
        free(sub);
    }
done:
    for (size_t i = 0; i < w.ndirs; i++) free(w.dirs[i].name);
    for (size_t i = 0; i < w.nfiles; i++) free(w.files[i].name);
    free(w.dirs);
    free(w.files);
    return rc;
}

static int find_path(pkgr_t *p, const char *path) {
    for (size_t i = 0; i < p->n_ents; i++)
        if (!strcmp(p->ents[i].path, path)) return (int)i;
    return -1;
}

/* CNT-resident named entries -> sce_sys/<name> (inner PFS wins on collisions) */
static int add_cnt_files(pkgr_t *p, const uint8_t *names, size_t names_len) {
    if (find_path(p, "sce_sys") < 0 && !add_entry(p, "", (const uint8_t *)"sce_sys", 7, 0)) return -1;
    for (uint32_t i = 0; i < p->n_cnt; i++) {
        const uint8_t *r = p->cnt_tab + (size_t)i * 32;
        uint32_t id = be32(r), noff = be32(r + 4), off = be32(r + 16), size = be32(r + 20);
        if (id < 0x1000 || noff == 0 || noff >= names_len) continue;
        size_t nl = 0;
        while (noff + nl < names_len && names[noff + nl]) nl++;
        if (nl == 0 || (uint64_t)off + size > p->file_size) continue;
        char full[512];
        if (nl > 400) continue;
        memcpy(full, "sce_sys/", 8);
        memcpy(full + 8, names + noff, nl);
        full[8 + nl] = 0;
        if (find_path(p, full) >= 0) continue;
        entry_t *e = add_entry(p, "sce_sys", names + noff, nl, 2);
        if (!e) continue;
        e->cnt_off = off;
        e->pub.size = size;
        p->total += size;
    }
    return 0;
}

/* ---- EKPFS ---- */
static int ekpfs_valid(const uint8_t k[32], const uint8_t dig1[32]) {
    uint8_t h[32];
    sha256(k, 32, h);
    for (int i = 0; i < 32; i++)
        if ((h[i] ^ k[i]) != dig1[i]) return 0;
    return 1;
}

static void ekpfs_from_passcode(const char *cid, const char *pass, uint8_t out[32]) {
    uint8_t buf[96], idx[4] = {0, 0, 0, 1}, cidp[48] = {0};
    size_t cl = strlen(cid);
    memcpy(cidp, cid, cl > 48 ? 48 : cl);
    sha256(idx, 4, buf);
    sha256(cidp, 48, buf + 32);
    size_t pl = strlen(pass);
    uint8_t *m = malloc(64 + pl);
    if (!m) {
        memset(out, 0, 32);
        return;
    }
    memcpy(m, buf, 64);
    memcpy(m + 64, pass, pl);
    sha256(m, 64 + pl, out);
    free(m);
}

#ifdef HAVE_RSA
static void to_rsa_key(rsa2048_key_t *k, const pkg_rsa_keyset_t *s) {
    memcpy(k->n, s->n, 256);
    memcpy(k->p, s->p, 128);
    memcpy(k->q, s->q, 128);
    memcpy(k->dp, s->dp, 128);
    memcpy(k->dq, s->dq, 128);
    memcpy(k->qinv, s->qinv, 128);
}

static int rsa_dec_unpad(const pkg_rsa_keyset_t *ks, const uint8_t in[256], uint8_t *out, size_t *outlen) {
    rsa2048_key_t *k = malloc(sizeof *k);
    uint8_t em[256];
    if (!k) return -1;
    to_rsa_key(k, ks);
    int r = rsa2048_private_op(k, in, em);
    free(k);
    if (r) return -1;
    *outlen = 256;
    return rsa_unpad_pkcs1_v15(em, out, outlen) ? -1 : 0;
}

/* IMAGE_KEY chain (prototype: route B) */
static int ekpfs_from_rsa(pkgr_t *p, const uint8_t *keys, size_t keys_len, const uint8_t *imgkey, size_t imgkey_len,
                          const uint8_t row20[32], uint8_t out[32]) {
    uint8_t dk3[256], ek[256];
    size_t dk3len = 0, eklen = 0;
    (void)p;
    if (keys_len < 32 + 7 * 32 + 4 * 256 || imgkey_len != 256) return -1;
    if (rsa_dec_unpad(&pkg_keyset_derived3, keys + 32 + 7 * 32 + 3 * 256, dk3, &dk3len) || dk3len > 200) return -1;
    uint8_t ivbuf[32 + 200], iv[32], plain[256];
    memcpy(ivbuf, row20, 32);
    memcpy(ivbuf + 32, dk3, dk3len);
    sha256(ivbuf, 32 + dk3len, iv);
    aes128_cbc_decrypt(iv + 16, iv, imgkey, plain, 256);
    if (rsa_dec_unpad(&pkg_keyset_fake, plain, ek, &eklen) || eklen != 32) return -1;
    memcpy(out, ek, 32);
    return 0;
}
#endif

/* ---- build the layer stack for one new_crypt choice ---- */
static int build_stack(pkgr_t *p, int new_crypt, const uint8_t *names, size_t names_len) {
    uint32_t bs, mode;
    uint8_t seed[16];
    uint64_t ndi, dbl;
    layer_t *outer_src = &p->raw.l;

    if (pfs_header(&p->raw.l, &bs, &mode, seed, &ndi, &dbl)) {
        set_err(p, "bad outer PFS superblock");
        return -1;
    }
    if (mode & 4) {
        p->xts = calloc(1, sizeof *p->xts);
        if (!p->xts) goto oom;
        p->xts->data = malloc((size_t)XTS_SLOTS * XTS_SS);
        if (!p->xts->data) goto oom;
        uint8_t base[32], k[32], tw[16 + 4];
        const uint8_t *hk = p->ekpfs;
        size_t hkl = 32;
        if (new_crypt) {
            hmac_sha256(p->ekpfs, 32, seed, 16, base);
            hk = base;
        }
        memcpy(tw, "\x01\x00\x00\x00", 4);
        memcpy(tw + 4, seed, 16);
        hmac_sha256(hk, hkl, tw, 20, k);
        memcpy(p->xts->tk, k, 16);
        memcpy(p->xts->dk, k + 16, 16);
        p->xts->src = &p->raw.l;
        p->xts->l.size = p->raw.l.size;
        p->xts->l.rd = xts_rd;
        p->xts->l.destroy = xts_destroy;
        p->xts->start_sector = bs / XTS_SS;
        outer_src = &p->xts->l;
    }
    if (pfs_open(&p->outer, outer_src)) {
        set_err(p, "cannot parse outer PFS (wrong key?)");
        return -1;
    }
    p->outer_ok = 1;
    int64_t uroot = pfs_find(&p->outer, 0, "uroot", 3);
    if (uroot < 0) {
        set_err(p, "outer PFS has no uroot");
        return -1;
    }
    int64_t img = pfs_find(&p->outer, (uint64_t)uroot, "pfs_image.dat", 2);
    if (img < 0) {
        set_err(p, "outer PFS has no pfs_image.dat");
        return -1;
    }
    p->imgfile = calloc(1, sizeof *p->imgfile);
    if (!p->imgfile) goto oom;
    if (fmap_build(&p->outer, (uint64_t)img, &p->imgfile->fm)) {
        set_err(p, "bad pfs_image.dat inode");
        return -1;
    }
    p->imgfile->pfs = &p->outer;
    p->imgfile->l.size = p->imgfile->fm.size;
    p->imgfile->l.rd = pfsfile_rd;
    p->imgfile->l.destroy = pfsfile_destroy;

    uint8_t head[16];
    if (layer_read(&p->imgfile->l, 0, head, 16)) {
        set_err(p, "cannot read pfs_image.dat");
        return -1;
    }
    layer_t *inner_src = &p->imgfile->l;
    if (!memcmp(head, "PFSC", 4)) {
        uint8_t h[0x30];
        if (layer_read(&p->imgfile->l, 0, h, sizeof h)) goto badpfsc;
        uint32_t bsz = le32(h + 12);
        uint64_t boff = le64(h + 24), size = le64(h + 40);
        if (bsz < 0x1000 || bsz > (1u << 24) || le32(h + 16) != bsz || size > ((uint64_t)1 << 44)) goto badpfsc;
        uint64_t nb = (size + bsz - 1) / bsz;
        if (nb > (1u << 26)) goto badpfsc;
        pfsc_layer_t *c = calloc(1, sizeof *c);
        if (!c) goto oom;
        p->pfsc = c;
        c->src = &p->imgfile->l;
        c->bsz = bsz;
        c->nblocks = nb;
        c->l.size = size;
        c->l.rd = pfsc_rd;
        c->l.destroy = pfsc_destroy;
        c->map = malloc((size_t)(nb + 1) * 8);
        c->data = malloc((size_t)PFSC_SLOTS * bsz);
        c->tmp = malloc(bsz);
        if (!c->map || !c->data || !c->tmp) goto oom;
        if (layer_read(c->src, boff, c->map, (size_t)(nb + 1) * 8)) goto badpfsc;
        for (uint64_t i = 0; i <= nb; i++) {
            uint8_t *q = (uint8_t *)&c->map[i];
            c->map[i] = le64(q);
        }
        inner_src = &c->l;
    } else if (le64(head) != 1) {
        set_err(p, "pfs_image.dat is neither PFSC nor plain PFS (unsupported codec)");
        return -1;
    }
    if (pfs_open(&p->inner, inner_src) || (p->inner.mode & 4)) {
        set_err(p, "cannot parse inner PFS");
        return -1;
    }
    p->inner_ok = 1;
    int64_t iroot = pfs_find(&p->inner, 0, "uroot", 3);
    if (iroot < 0) {
        set_err(p, "inner PFS has no uroot");
        return -1;
    }
    if (walk_dir(p, (uint64_t)iroot, "", 0)) {
        set_err(p, "inner PFS directory walk failed");
        return -1;
    }
    if (add_cnt_files(p, names, names_len)) goto oom;
    return 0;
badpfsc:
    set_err(p, "bad PFSC header/map");
    return -1;
oom:
    set_err(p, "out of memory");
    return -1;
}

int pkgr_open(const char *path, const char *passcode, pkgr_t **out, char *err, size_t errlen) {
    pkgr_t *p = calloc(1, sizeof *p);
    uint8_t *keys = NULL, *imgkey = NULL, *names = NULL;
    size_t keys_len = 0, imgkey_len = 0, names_len = 0;
    *out = NULL;
    crypto_init();
    if (!p) {
        if (err && errlen) snprintf(err, errlen, "out of memory");
        return -1;
    }
    p->fd = -1;
    p->fd = open(path, O_RDONLY);
    if (p->fd < 0) {
        set_err(p, "cannot open %s: %s", path, strerror(errno));
        goto fail;
    }
    struct stat st;
    if (fstat(p->fd, &st) || st.st_size < 0x1000) {
        set_err(p, "file too small");
        goto fail;
    }
    p->file_size = (uint64_t)st.st_size;
    uint8_t h[0x460];
    if (pread_full(p->fd, h, sizeof h, 0) || memcmp(h, "\x7f" "CNT", 4)) {
        set_err(p, "not a CNT/PKG file");
        goto fail;
    }
    p->n_cnt = be32(h + 0x10);
    uint32_t tab = be32(h + 0x18);
    memcpy(p->content_id, h + 0x40, 36);
    p->content_id[36] = 0;
    p->pfs_flags = be64(h + 0x408);
    p->pfs_off = be64(h + 0x410);
    p->pfs_size = be64(h + 0x418);
    if (p->n_cnt == 0 || p->n_cnt > 4096 || (uint64_t)tab + (uint64_t)p->n_cnt * 32 > p->file_size) {
        set_err(p, "bad CNT entry table");
        goto fail;
    }
    if (p->pfs_off > p->file_size || p->pfs_size > p->file_size - p->pfs_off || p->pfs_size < 0x10000) {
        set_err(p, "bad PFS image range");
        goto fail;
    }
    p->cnt_tab = malloc((size_t)p->n_cnt * 32);
    if (!p->cnt_tab || pread_full(p->fd, p->cnt_tab, (size_t)p->n_cnt * 32, tab)) {
        set_err(p, "cannot read CNT entry table");
        goto fail;
    }
    const uint8_t *row10 = NULL, *row20 = NULL, *row200 = NULL;
    for (uint32_t i = 0; i < p->n_cnt; i++) {
        const uint8_t *r = p->cnt_tab + (size_t)i * 32;
        uint32_t id = be32(r);
        if (id == 0x10 && !row10) row10 = r;
        if (id == 0x20 && !row20) row20 = r;
        if (id == 0x200 && !row200) row200 = r;
    }
#define LOAD(row, buf, len, cap)                                                                  \
    do {                                                                                          \
        if (row) {                                                                                \
            uint32_t o_ = be32((row) + 16), s_ = be32((row) + 20);                                \
            if (s_ <= (cap) && (uint64_t)o_ + s_ <= p->file_size) {                               \
                buf = malloc(s_ ? s_ : 1);                                                        \
                if (buf && !pread_full(p->fd, buf, s_, o_)) len = s_;                             \
            }                                                                                     \
        }                                                                                         \
    } while (0)
    LOAD(row10, keys, keys_len, 1u << 16);
    LOAD(row20, imgkey, imgkey_len, 1u << 12);
    LOAD(row200, names, names_len, 1u << 22);
#undef LOAD
    if (keys_len < 96) {
        set_err(p, "missing ENTRY_KEYS");
        goto fail;
    }
    {
        int have = 0;
        char defpass[33];
        memset(defpass, '0', 32);
        defpass[32] = 0;
        ekpfs_from_passcode(p->content_id, passcode ? passcode : defpass, p->ekpfs);
        have = ekpfs_valid(p->ekpfs, keys + 64);
#ifdef HAVE_RSA
        if (!have && row20 && imgkey_len) {
            uint8_t cand[32];
            if (!ekpfs_from_rsa(p, keys, keys_len, imgkey, imgkey_len, row20, cand) && ekpfs_valid(cand, keys + 64)) {
                memcpy(p->ekpfs, cand, 32);
                have = 1;
            }
        }
#endif
        if (!have) {
            set_err(p, "no EKPFS candidate matches ENTRY_KEYS (wrong passcode, retail pkg%s)",
#ifdef HAVE_RSA
                    "");
#else
                    ", or built without RSA support");
#endif
            goto fail;
        }
    }
    p->raw.fd = p->fd;
    p->raw.base = p->pfs_off;
    p->raw.l.size = p->pfs_size;
    p->raw.l.rd = raw_rd;
    int nc = (p->pfs_flags >> 61) & 1;
    if (build_stack(p, nc, names, names_len)) {
        char first[sizeof p->errbuf];
        memcpy(first, p->errbuf, sizeof first);
        free_stack(p);
        if (build_stack(p, !nc, names, names_len)) {
            memcpy(p->errbuf, first, sizeof first);
            goto fail;
        }
    }
    free(keys);
    free(imgkey);
    free(names);
    *out = p;
    return 0;
fail:
    if (err && errlen) snprintf(err, errlen, "%s", p->errbuf[0] ? p->errbuf : "error");
    free(keys);
    free(imgkey);
    free(names);
    pkgr_close(p);
    return -1;
}

size_t pkgr_entry_count(pkgr_t *p) { return p->n_ents; }

const pkgr_entry_t *pkgr_entry(pkgr_t *p, size_t i) { return i < p->n_ents ? &p->ents[i].pub : NULL; }

uint64_t pkgr_total_size(pkgr_t *p) { return p->total; }

int64_t pkgr_read(pkgr_t *p, size_t idx, uint64_t offset, void *buf, size_t len) {
    if (idx >= p->n_ents) return -1;
    entry_t *e = &p->ents[idx];
    if (e->kind == 0) return -1;
    if (offset >= e->pub.size) return 0;
    if (len > e->pub.size - offset) len = (size_t)(e->pub.size - offset);
    if (len == 0) return 0;
    if (e->kind == 2) return pread_full(p->fd, buf, len, e->cnt_off + offset) ? -1 : (int64_t)len;
    return fmap_read(&p->inner, &e->fm, offset, buf, len) ? -1 : (int64_t)len;
}
