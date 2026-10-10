/*
 * kraken.c - decoder for the header-stripped Kraken (newLZ) blocks found in PS5 FIH "NAPS" packages.
 *
 * PROVENANCE / LICENSE: this is a line-by-line C port of
 *   LibProsperoPkg  src/LibProsperoPkg/PFS/Compression/Oodle/KrakenDecoder.cs (+ KrakenBitReader.cs)
 *   Copyright (C) 2026 SvenGDK, https://github.com/SvenGDK/LibProsperoPKG, licensed GPL-3.0.
 * That C# source in turn states that parts of the bit-level decode logic are a translation of a
 * GPLv3 third-party decompressor (see NOTICE in that repo; the public Kraken bitstream layout as
 * documented by the ooz/Powzix reverse engineering). This port is therefore a GPL-3.0 derivative:
 * keep this notice, and any program that links it must be GPL-3.0 compatible.
 *
 * Supported entropy array types: 0 (stored), 2/4 (Huffman, both code-length encodings).
 * Types 1 (TANS), 3 (RLE), 5 (recursive) return KRK_UNSUPPORTED_ENTROPY, like the C# original.
 *
 * Public API:
 *   int kraken_decode_block(src, srclen, flags, first_chunk_comp, dst, dstlen)   exact (as C# DecodeBlock)
 *   int kraken_decompress(src, srclen, dst, dstlen)  convenience: tries the flag combinations, 0 on success
 * flags (from NAPS CblockInfo even/odd modes):
 *   ((even&4)?2:0)|((even&2)?1:0)|((odd&4)?32:0)|((odd&2)?16:0)
 * Build:  gcc -O2 -shared -o kraken.dll kraken.c      (or -DKRAKEN_MAIN for a test CLI)
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define KEXPORT __declspec(dllexport)
#else
#define KEXPORT
#endif

enum { KRK_OK = 0, KRK_MALFORMED = 1, KRK_UNSUPPORTED_ENTROPY = 2, KRK_UNSUPPORTED_EXCESS = 3 };

#define CHUNK_MAX 0x20000
#define SEED_SIZE 8
#define PAD 64

static int bsr_(uint32_t x) { return x == 0 ? 0 : 31 - __builtin_clz(x); }
static int bsf_(uint32_t x) { return x == 0 ? 0 : __builtin_ctz(x); }
static int clz_(uint32_t x) { return x == 0 ? 31 : __builtin_clz(x); }
static uint32_t rotl_(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

/* ---------------------------------------------------------------- bit reader */
typedef struct {
    const uint8_t *B;
    int P, Bound;
    uint32_t Bits;
    int BitPos;
    int bwd;
} RBR;

static void rbr_refill_f(RBR *r) {
    while (r->BitPos > 0) {
        r->Bits |= (uint32_t)(r->P < r->Bound ? r->B[r->P] : 0) << r->BitPos;
        r->BitPos -= 8;
        r->P++;
    }
}
static void rbr_refill_b(RBR *r) {
    while (r->BitPos > 0) {
        r->P--;
        r->Bits |= (uint32_t)(r->P >= r->Bound ? r->B[r->P] : 0) << r->BitPos;
        r->BitPos -= 8;
    }
}
static void rbr_refill(RBR *r) { if (r->bwd) rbr_refill_b(r); else rbr_refill_f(r); }
static RBR rbr_forward(const uint8_t *b, int start, int end) {
    RBR r = { b, start, end, 0, 24, 0 };
    rbr_refill_f(&r);
    return r;
}
static RBR rbr_backward(const uint8_t *b, int low, int high) {
    RBR r = { b, high, low, 0, 24, 1 };
    rbr_refill_b(&r);
    return r;
}
static int rbr_bit(RBR *r) {
    rbr_refill(r);
    int v = (int)(r->Bits >> 31);
    r->Bits <<= 1; r->BitPos += 1;
    return v;
}
static int rbr_bit_nr(RBR *r) {
    int v = (int)(r->Bits >> 31);
    r->Bits <<= 1; r->BitPos += 1;
    return v;
}
static uint32_t rbr_bits_nr(RBR *r, int n) {
    uint32_t v = r->Bits >> (32 - n);
    r->Bits <<= n; r->BitPos += n;
    return v;
}
static uint32_t rbr_bits_nrz(RBR *r, int n) {
    uint32_t v = r->Bits >> 1 >> (31 - n);
    r->Bits <<= n; r->BitPos += n;
    return v;
}
static int rbr_fluff(RBR *r, int numSymbols) {
    if (numSymbols == 256) return 0;
    int x = 257 - numSymbols;
    if (x > numSymbols) x = numSymbols;
    x *= 2;
    int y = bsr_((uint32_t)(x - 1)) + 1;
    uint32_t v = r->Bits >> (32 - y);
    uint32_t z = (uint32_t)((1 << y) - x);
    if ((v >> 1) >= z) {
        r->Bits <<= y; r->BitPos += y;
        return (int)(v - z);
    } else {
        r->Bits <<= (y - 1); r->BitPos += (y - 1);
        return (int)(v >> 1);
    }
}
static uint32_t rbr_more24(RBR *r, int n) {
    uint32_t rv;
    if (n <= 24) rv = rbr_bits_nrz(r, n);
    else { rv = rbr_bits_nr(r, 24) << (n - 24); rbr_refill(r); rv += rbr_bits_nr(r, n - 24); }
    rbr_refill(r);
    return rv;
}
static uint32_t rbr_distance(RBR *r, uint32_t v) {
    uint32_t w, m, rv; int n;
    if (v < 0xF0) {
        n = (int)(v >> 4) + 4;
        w = rotl_(r->Bits | 1, n);
        r->BitPos += n;
        m = (2u << n) - 1;
        r->Bits = w & ~m;
        rv = ((w & m) << 4) + (v & 0xF) - 248;
    } else {
        n = (int)(v - 0xF0) + 4;
        w = rotl_(r->Bits | 1, n);
        r->BitPos += n;
        m = (2u << n) - 1;
        r->Bits = w & ~m;
        rv = 8322816 + ((w & m) << 12);
        rbr_refill(r);
        rv += r->Bits >> 20;
        r->BitPos += 12;
        r->Bits <<= 12;
    }
    rbr_refill(r);
    return rv;
}
static int rbr_length(RBR *r, uint32_t *v) {
    *v = 0;
    int n = 31 - bsr_(r->Bits);
    if (n > 12) return 0;
    r->BitPos += n; r->Bits <<= n; rbr_refill(r);
    n += 7;
    r->BitPos += n;
    *v = (r->Bits >> (32 - n)) - 64;
    r->Bits <<= n; rbr_refill(r);
    return 1;
}

/* ---------------------------------------------------------------- tables */
static const uint32_t RiceVal[256] = {
0x80000000,0x00000007,0x10000006,0x00000006,0x20000005,0x00000105,0x10000005,0x00000005,
0x30000004,0x00000204,0x10000104,0x00000104,0x20000004,0x00010004,0x10000004,0x00000004,
0x40000003,0x00000303,0x10000203,0x00000203,0x20000103,0x00010103,0x10000103,0x00000103,
0x30000003,0x00020003,0x10010003,0x00010003,0x20000003,0x01000003,0x10000003,0x00000003,
0x50000002,0x00000402,0x10000302,0x00000302,0x20000202,0x00010202,0x10000202,0x00000202,
0x30000102,0x00020102,0x10010102,0x00010102,0x20000102,0x01000102,0x10000102,0x00000102,
0x40000002,0x00030002,0x10020002,0x00020002,0x20010002,0x01010002,0x10010002,0x00010002,
0x30000002,0x02000002,0x11000002,0x01000002,0x20000002,0x00000012,0x10000002,0x00000002,
0x60000001,0x00000501,0x10000401,0x00000401,0x20000301,0x00010301,0x10000301,0x00000301,
0x30000201,0x00020201,0x10010201,0x00010201,0x20000201,0x01000201,0x10000201,0x00000201,
0x40000101,0x00030101,0x10020101,0x00020101,0x20010101,0x01010101,0x10010101,0x00010101,
0x30000101,0x02000101,0x11000101,0x01000101,0x20000101,0x00000111,0x10000101,0x00000101,
0x50000001,0x00040001,0x10030001,0x00030001,0x20020001,0x01020001,0x10020001,0x00020001,
0x30010001,0x02010001,0x11010001,0x01010001,0x20010001,0x00010011,0x10010001,0x00010001,
0x40000001,0x03000001,0x12000001,0x02000001,0x21000001,0x01000011,0x11000001,0x01000001,
0x30000001,0x00000021,0x10000011,0x00000011,0x20000001,0x00001001,0x10000001,0x00000001,
0x70000000,0x00000600,0x10000500,0x00000500,0x20000400,0x00010400,0x10000400,0x00000400,
0x30000300,0x00020300,0x10010300,0x00010300,0x20000300,0x01000300,0x10000300,0x00000300,
0x40000200,0x00030200,0x10020200,0x00020200,0x20010200,0x01010200,0x10010200,0x00010200,
0x30000200,0x02000200,0x11000200,0x01000200,0x20000200,0x00000210,0x10000200,0x00000200,
0x50000100,0x00040100,0x10030100,0x00030100,0x20020100,0x01020100,0x10020100,0x00020100,
0x30010100,0x02010100,0x11010100,0x01010100,0x20010100,0x00010110,0x10010100,0x00010100,
0x40000100,0x03000100,0x12000100,0x02000100,0x21000100,0x01000110,0x11000100,0x01000100,
0x30000100,0x00000120,0x10000110,0x00000110,0x20000100,0x00001100,0x10000100,0x00000100,
0x60000000,0x00050000,0x10040000,0x00040000,0x20030000,0x01030000,0x10030000,0x00030000,
0x30020000,0x02020000,0x11020000,0x01020000,0x20020000,0x00020010,0x10020000,0x00020000,
0x40010000,0x03010000,0x12010000,0x02010000,0x21010000,0x01010010,0x11010000,0x01010000,
0x30010000,0x00010020,0x10010010,0x00010010,0x20010000,0x00011000,0x10010000,0x00010000,
0x50000000,0x04000000,0x13000000,0x03000000,0x22000000,0x02000010,0x12000000,0x02000000,
0x31000000,0x01000020,0x11000010,0x01000010,0x21000000,0x01001000,0x11000000,0x01000000,
0x40000000,0x00000030,0x10000020,0x00000020,0x20000010,0x00001010,0x10000010,0x00000010,
0x30000000,0x00002000,0x10001000,0x00001000,0x20000000,0x00100000,0x10000000,0x00000000 };
static const uint8_t RiceLen[256] = {
0,1,1,2,1,2,2,3,1,2,2,3,2,3,3,4,1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,
1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,
1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,
2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,
1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,
2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,
2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,
3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,4,5,5,6,5,6,6,7,5,6,6,7,6,7,7,8 };
static const uint32_t CodePrefixOrg[12] = { 0x0,0x0,0x2,0x6,0xE,0x1E,0x3E,0x7E,0xFE,0x1FE,0x2FE,0x3FE };

static uint32_t rd32(const uint8_t *b, int off) {
    return (uint32_t)b[off] | (uint32_t)b[off+1] << 8 | (uint32_t)b[off+2] << 16 | (uint32_t)b[off+3] << 24;
}
static uint64_t rd64(const uint8_t *b, int off) { return (uint64_t)rd32(b, off) | (uint64_t)rd32(b, off + 4) << 32; }
static void wr32(uint8_t *b, int off, uint32_t v) { for (int i = 0; i < 4; i++) b[off+i] = (uint8_t)(v >> (8*i)); }
static void wr64(uint8_t *b, int off, uint64_t v) { for (int i = 0; i < 8; i++) b[off+i] = (uint8_t)(v >> (8*i)); }
static uint32_t bswap32_(uint32_t v) { return __builtin_bswap32(v); }
static uint64_t bswap64_(uint64_t v) { return __builtin_bswap64(v); }

/* ---------------------------------------------------------------- Golomb-Rice */
typedef struct { const uint8_t *B; int P, PEnd, BitPos; } RBR2;

static int golomb_lengths(uint8_t *dst, int size, RBR2 *br) {
    int p = br->P, pEnd = br->PEnd, dstPos = 0, dstEnd = size;
    if (p >= pEnd) return 0;
    int count = -br->BitPos;
    uint32_t v = (uint32_t)(br->B[p++] & (255 >> br->BitPos));
    for (;;) {
        if (v == 0) count += 8;
        else {
            uint32_t x = RiceVal[v];
            uint32_t lo = (uint32_t)count + (x & 0x0F0F0F0Fu);
            wr32(dst, dstPos, lo);
            wr32(dst, dstPos + 4, (x >> 4) & 0x0F0F0F0Fu);
            dstPos += RiceLen[v];
            if (dstPos >= dstEnd) break;
            count = (int)(x >> 28);
        }
        if (p >= pEnd) return 0;
        v = br->B[p++];
    }
    if (dstPos > dstEnd) {
        int nn = dstPos - dstEnd;
        do { v &= v - 1; } while (--nn != 0);
    }
    int bitpos = 0;
    if ((v & 1) == 0) { p--; int q = bsf_(v); bitpos = 8 - q; }
    br->P = p; br->BitPos = bitpos;
    return 1;
}

static int golomb_bits(uint8_t *dst, int size, int bitcount, RBR2 *br) {
    if (bitcount == 0) return 1;
    int dstPos = 0, dstEnd = size, p = br->P, bitpos = br->BitPos;
    int bitsRequired = bitpos + bitcount * size;
    int bytesRequired = (bitsRequired + 7) >> 3;
    if (bytesRequired > br->PEnd - p) return 0;
    br->P = p + (bitsRequired >> 3);
    br->BitPos = bitsRequired & 7;
    uint64_t bak = rd64(dst, dstEnd);
    if (bitcount == 1) {
        do {
            uint64_t bits = (uint8_t)(bswap32_(rd32(br->B, p)) >> (24 - bitpos));
            p += 1;
            bits = (bits | (bits << 28)) & 0xF0000000Full;
            bits = (bits | (bits << 14)) & 0x3000300030003ull;
            bits = (bits | (bits << 7)) & 0x0101010101010101ull;
            uint64_t cur = rd64(dst, dstPos);
            wr64(dst, dstPos, cur * 2 + bswap64_(bits));
            dstPos += 8;
        } while (dstPos < dstEnd);
    } else if (bitcount == 2) {
        do {
            uint64_t bits = (uint16_t)(bswap32_(rd32(br->B, p)) >> (16 - bitpos));
            p += 2;
            bits = (bits | (bits << 24)) & 0xFF000000FFull;
            bits = (bits | (bits << 12)) & 0xF000F000F000Full;
            bits = (bits | (bits << 6)) & 0x0303030303030303ull;
            uint64_t cur = rd64(dst, dstPos);
            wr64(dst, dstPos, cur * 4 + bswap64_(bits));
            dstPos += 8;
        } while (dstPos < dstEnd);
    } else {
        do {
            uint64_t bits = (uint64_t)((bswap32_(rd32(br->B, p)) >> (8 - bitpos)) & 0xFFFFFF);
            p += 3;
            bits = (bits | (bits << 20)) & 0xFFF00000FFFull;
            bits = (bits | (bits << 10)) & 0x3F003F003F003Full;
            bits = (bits | (bits << 5)) & 0x0707070707070707ull;
            uint64_t cur = rd64(dst, dstPos);
            wr64(dst, dstPos, cur * 8 + bswap64_(bits));
            dstPos += 8;
        } while (dstPos < dstEnd);
    }
    wr64(dst, dstEnd, bak);
    return 1;
}

/* ---------------------------------------------------------------- Huffman */
typedef struct { int Symbol, Num; } HuffRange;

static int huff_ranges(HuffRange *range, int numSymbols, int p, const uint8_t *symlen, int symlenOff, RBR *bits) {
    int numRanges = p >> 1, v, symIdx = 0;
    if (p & 1) {
        rbr_refill(bits);
        v = symlen[symlenOff++];
        if (v >= 8) return -1;
        symIdx = (int)rbr_bits_nr(bits, v + 1) + (1 << (v + 1)) - 1;
    }
    int symsUsed = 0;
    for (int i = 0; i < numRanges; i++) {
        rbr_refill(bits);
        v = symlen[symlenOff];
        if (v >= 9) return -1;
        int num = (int)rbr_bits_nrz(bits, v) + (1 << v);
        v = symlen[symlenOff + 1];
        if (v >= 8) return -1;
        int space = (int)rbr_bits_nr(bits, v + 1) + (1 << (v + 1)) - 1;
        range[i].Symbol = symIdx; range[i].Num = num;
        symsUsed += num;
        symIdx += num + space;
        symlenOff += 2;
    }
    if (symIdx >= 256 || symsUsed >= numSymbols || symIdx + numSymbols - symsUsed > 256) return -1;
    range[numRanges].Symbol = symIdx;
    range[numRanges].Num = numSymbols - symsUsed;
    return numRanges + 1;
}

static int huff_lengths_old(RBR *bits, uint8_t *syms, uint32_t *codePrefix) {
    if (rbr_bit_nr(bits) != 0) {
        int sym = 0, codelen, numSymbols = 0, avgBitsX4 = 32;
        int forcedBits = (int)rbr_bits_nr(bits, 2);
        uint32_t thres = 1u << (31 - (int)(20u >> forcedBits));
        int n;
        int skip = rbr_bit(bits) != 0;
        for (;;) {
            if (!skip) {
                if ((bits->Bits & 0xFF000000u) == 0) return -1;
                sym += (int)rbr_bits_nr(bits, 2 * (clz_(bits->Bits) + 1)) - 2 + 1;
                if (sym >= 256) break;
            }
            skip = 0;
            rbr_refill(bits);
            if ((bits->Bits & 0xFF000000u) == 0) return -1;
            n = (int)rbr_bits_nr(bits, 2 * (clz_(bits->Bits) + 1)) - 2 + 1;
            if (sym + n > 256) return -1;
            rbr_refill(bits);
            numSymbols += n;
            do {
                if (bits->Bits < thres) return -1;
                int lz = clz_(bits->Bits);
                int v = (int)rbr_bits_nr(bits, lz + forcedBits + 1) + ((lz - 1) << forcedBits);
                codelen = (-(v & 1) ^ (v >> 1)) + ((avgBitsX4 + 2) >> 2);
                if (codelen < 1 || codelen > 11) return -1;
                avgBitsX4 = codelen + ((3 * avgBitsX4 + 2) >> 2);
                rbr_refill(bits);
                syms[codePrefix[codelen]++] = (uint8_t)sym++;
            } while (--n != 0);
            if (sym == 256) break;
        }
        return (sym == 256 && numSymbols >= 2) ? numSymbols : -1;
    } else {
        int numSymbols = (int)rbr_bits_nr(bits, 8);
        if (numSymbols == 0) return -1;
        if (numSymbols == 1) syms[0] = (uint8_t)rbr_bits_nr(bits, 8);
        else {
            int codelenBits = (int)rbr_bits_nr(bits, 3);
            if (codelenBits > 4) return -1;
            for (int i = 0; i < numSymbols; i++) {
                rbr_refill(bits);
                int sym = (int)rbr_bits_nr(bits, 8);
                int codelen = (int)rbr_bits_nrz(bits, codelenBits) + 1;
                if (codelen > 11) return -1;
                syms[codePrefix[codelen]++] = (uint8_t)sym;
            }
        }
        return numSymbols;
    }
}

static int huff_lengths_new(RBR *bits, uint8_t *syms, uint32_t *codePrefix) {
    int forcedBits = (int)rbr_bits_nr(bits, 2);
    int numSymbols = (int)rbr_bits_nr(bits, 8) + 1;
    int fluff = rbr_fluff(bits, numSymbols);
    uint8_t codeLen[512 + 64];
    memset(codeLen, 0, sizeof codeLen);
    RBR2 br2;
    br2.B = bits->B;
    br2.BitPos = (bits->BitPos - 24) & 7;
    br2.PEnd = bits->Bound;
    br2.P = bits->P - ((24 - bits->BitPos + 7) >> 3);
    if (numSymbols + fluff > 512) return -1;
    if (!golomb_lengths(codeLen, numSymbols + fluff, &br2)) return -1;
    for (int z = 0; z < 16; z++) codeLen[numSymbols + fluff + z] = 0;
    if (!golomb_bits(codeLen, numSymbols, forcedBits, &br2)) return -1;
    bits->BitPos = 24; bits->P = br2.P; bits->Bits = 0;
    rbr_refill(bits);
    bits->Bits <<= br2.BitPos;
    bits->BitPos += br2.BitPos;
    uint32_t runningSum = 0x1e;
    for (int i = 0; i < numSymbols; i++) {
        int v = codeLen[i];
        v = -(v & 1) ^ (v >> 1);
        int cl = v + (int)(runningSum >> 2) + 1;
        if (cl < 1 || cl > 11) return -1;
        codeLen[i] = (uint8_t)cl;
        runningSum = (uint32_t)((int)runningSum + v);
    }
    HuffRange range[130];
    int ranges = huff_ranges(range, numSymbols, fluff, codeLen, numSymbols, bits);
    if (ranges <= 0) return -1;
    int cp = 0;
    for (int i = 0; i < ranges; i++) {
        int sym = range[i].Symbol, nn = range[i].Num;
        do { syms[codePrefix[codeLen[cp++]]++] = (uint8_t)sym++; } while (--nn != 0);
    }
    return numSymbols;
}

typedef struct { uint8_t Bits2Len[2048 + 16]; uint8_t Bits2Sym[2048 + 16]; } HuffLut;

static int huff_make_lut(const uint32_t *prefixOrg, const uint32_t *prefixCur, HuffLut *lut, const uint8_t *syms) {
    uint32_t currslot = 0;
    for (uint32_t i = 1; i < 11; i++) {
        uint32_t start = prefixOrg[i], count = prefixCur[i] - start;
        if (count != 0) {
            uint32_t stepsize = 1u << (11 - i), numToSet = count << (11 - i);
            if (currslot + numToSet > 2048) return 0;
            memset(lut->Bits2Len + currslot, (int)i, numToSet);
            uint32_t p = currslot;
            for (uint32_t j = 0; j != count; j++, p += stepsize) memset(lut->Bits2Sym + p, syms[start + j], stepsize);
            currslot += numToSet;
        }
    }
    if (prefixCur[11] - prefixOrg[11] != 0) {
        uint32_t numToSet = prefixCur[11] - prefixOrg[11];
        if (currslot + numToSet > 2048) return 0;
        memset(lut->Bits2Len + currslot, 11, numToSet);
        memcpy(lut->Bits2Sym + currslot, syms + prefixOrg[11], numToSet);
        currslot += numToSet;
    }
    return currslot == 2048;
}

static void reverse_lut(const uint8_t *in, uint8_t *out) {
    for (int i = 0; i < 2048; i++) {
        int r = 0, v = i;
        for (int k = 0; k < 11; k++) { r = (r << 1) | (v & 1); v >>= 1; }
        out[i] = in[r];
    }
}

typedef struct {
    const uint8_t *B; uint8_t *Out;
    int Src, SrcEnd, SrcMid, SrcMidOrg;
    uint32_t SrcBits, SrcMidBits, SrcEndBits;
    int SrcBitpos, SrcMidBitpos, SrcEndBitpos;
    int OutOff, OutEnd;
} HuffReader;

static int huff_core(HuffReader *hr, const HuffLut *lut) {
    const uint8_t *B = hr->B; uint8_t *outp = hr->Out;
    const uint8_t *b2len = lut->Bits2Len, *b2sym = lut->Bits2Sym;
    int src = hr->Src; uint32_t srcBits = hr->SrcBits; int srcBitpos = hr->SrcBitpos;
    int srcMid = hr->SrcMid; uint32_t srcMidBits = hr->SrcMidBits; int srcMidBitpos = hr->SrcMidBitpos;
    int srcEnd = hr->SrcEnd; uint32_t srcEndBits = hr->SrcEndBits; int srcEndBitpos = hr->SrcEndBitpos;
    int dst = hr->OutOff, dstEnd = hr->OutEnd;
    if (src > srcMid) return 0;
    int k, n;
    for (;;) {
        if (dst >= dstEnd) break;
        if (srcMid - src <= 1) {
            if (srcMid - src == 1) srcBits |= (uint32_t)B[src] << srcBitpos;
        } else {
            srcBits |= (uint32_t)(B[src] | (B[src + 1] << 8)) << srcBitpos;
        }
        k = (int)(srcBits & 0x7FF);
        n = b2len[k];
        srcBitpos -= n;
        srcBits >>= n;
        outp[dst++] = b2sym[k];
        src += (7 - srcBitpos) >> 3;
        srcBitpos &= 7;
        if (dst < dstEnd) {
            if (srcEnd - srcMid <= 1) {
                if (srcEnd - srcMid == 1) {
                    srcEndBits |= (uint32_t)B[srcMid] << srcEndBitpos;
                    srcMidBits |= (uint32_t)B[srcMid] << srcMidBitpos;
                }
            } else {
                uint32_t vv = (uint32_t)(B[srcEnd - 2] | (B[srcEnd - 1] << 8));
                srcEndBits |= (((vv >> 8) | (vv << 8)) & 0xFFFF) << srcEndBitpos;
                srcMidBits |= (uint32_t)(B[srcMid] | (B[srcMid + 1] << 8)) << srcMidBitpos;
            }
            k = (int)(srcEndBits & 0x7FF);
            n = b2len[k];
            outp[dst++] = b2sym[k];
            srcEndBitpos -= n;
            srcEndBits >>= n;
            srcEnd -= (7 - srcEndBitpos) >> 3;
            srcEndBitpos &= 7;
            if (dst < dstEnd) {
                k = (int)(srcMidBits & 0x7FF);
                n = b2len[k];
                outp[dst++] = b2sym[k];
                srcMidBitpos -= n;
                srcMidBits >>= n;
                srcMid += (7 - srcMidBitpos) >> 3;
                srcMidBitpos &= 7;
            }
        }
        if (src > srcMid || srcMid > srcEnd) return 0;
    }
    if (src != hr->SrcMidOrg || srcEnd != srcMid) return 0;
    return 1;
}

static int decode_type12(const uint8_t *src, int srcStart, int srcSize, uint8_t *output, int outputSize, int type) {
    int srcEnd = srcStart + srcSize;
    RBR bits = rbr_forward(src, srcStart, srcEnd);
    uint32_t codePrefix[12];
    memcpy(codePrefix, CodePrefixOrg, sizeof codePrefix);
    uint8_t syms[1280 + 16];
    memset(syms, 0, sizeof syms);
    int numSyms;
    if (rbr_bit_nr(&bits) == 0) numSyms = huff_lengths_old(&bits, syms, codePrefix);
    else if (rbr_bit_nr(&bits) == 0) numSyms = huff_lengths_new(&bits, syms, codePrefix);
    else return -1;
    if (numSyms < 1) return -1;
    int sp = bits.P - ((24 - bits.BitPos) / 8);
    if (numSyms == 1) {
        memset(output, syms[0], outputSize);
        return srcSize;
    }
    HuffLut lut, rev;
    memset(&lut, 0, sizeof lut); memset(&rev, 0, sizeof rev);
    if (!huff_make_lut(CodePrefixOrg, codePrefix, &lut, syms)) return -1;
    reverse_lut(lut.Bits2Len, rev.Bits2Len);
    reverse_lut(lut.Bits2Sym, rev.Bits2Sym);
    if (type == 1) {
        if (sp + 3 > srcEnd) return -1;
        int splitMid = src[sp] | (src[sp + 1] << 8);
        sp += 2;
        HuffReader hr; memset(&hr, 0, sizeof hr);
        hr.B = src; hr.Out = output; hr.OutOff = 0; hr.OutEnd = outputSize;
        hr.Src = sp; hr.SrcEnd = srcEnd; hr.SrcMidOrg = sp + splitMid; hr.SrcMid = sp + splitMid;
        if (!huff_core(&hr, &rev)) return -1;
    } else {
        if (sp + 6 > srcEnd) return -1;
        int halfOut = (outputSize + 1) >> 1;
        int splitMid = src[sp] | (src[sp + 1] << 8) | (src[sp + 2] << 16);
        sp += 3;
        if (splitMid > srcEnd - sp) return -1;
        int srcMid = sp + splitMid;
        int splitLeft = src[sp] | (src[sp + 1] << 8);
        sp += 2;
        if (srcMid - sp < splitLeft + 2 || srcEnd - srcMid < 3) return -1;
        int splitRight = src[srcMid] | (src[srcMid + 1] << 8);
        if (srcEnd - (srcMid + 2) < splitRight + 2) return -1;
        HuffReader h1; memset(&h1, 0, sizeof h1);
        h1.B = src; h1.Out = output; h1.OutOff = 0; h1.OutEnd = halfOut;
        h1.Src = sp; h1.SrcEnd = srcMid; h1.SrcMidOrg = sp + splitLeft; h1.SrcMid = sp + splitLeft;
        if (!huff_core(&h1, &rev)) return -1;
        HuffReader h2; memset(&h2, 0, sizeof h2);
        h2.B = src; h2.Out = output; h2.OutOff = halfOut; h2.OutEnd = outputSize;
        h2.Src = srcMid + 2; h2.SrcEnd = srcEnd; h2.SrcMidOrg = srcMid + 2 + splitRight; h2.SrcMid = srcMid + 2 + splitRight;
        if (!huff_core(&h2, &rev)) return -1;
    }
    return srcSize;
}

/* output buffer must have outputCap + PAD bytes. returns bytes consumed, -1 malformed, -2 unsupported */
static int decode_bytes(const uint8_t *src, int sp, int srcEnd, int outputCap, uint8_t *output, int *decodedSize) {
    int srcOrg = sp, chunkType, srcSize, dstSize;
    *decodedSize = 0;
    if (srcEnd - sp < 2) return -1;
    chunkType = (src[sp] >> 4) & 0x7;
    if (chunkType == 0) {
        if (src[sp] >= 0x80) { srcSize = ((src[sp] << 8) | src[sp + 1]) & 0xFFF; sp += 2; }
        else {
            if (srcEnd - sp < 3) return -1;
            srcSize = (src[sp] << 16) | (src[sp + 1] << 8) | src[sp + 2];
            if ((srcSize & ~0x3FFFF) != 0) return -1;
            sp += 3;
        }
        if (srcSize > outputCap || srcEnd - sp < srcSize) return -1;
        memcpy(output, src + sp, srcSize);
        *decodedSize = srcSize;
        return sp + srcSize - srcOrg;
    }
    if (src[sp] >= 0x80) {
        if (srcEnd - sp < 3) return -1;
        uint32_t bits = ((uint32_t)src[sp] << 16) | ((uint32_t)src[sp + 1] << 8) | src[sp + 2];
        srcSize = (int)(bits & 0x3FF);
        dstSize = (int)(srcSize + ((bits >> 10) & 0x3FF) + 1);
        sp += 3;
    } else {
        if (srcEnd - sp < 5) return -1;
        uint32_t bits = ((uint32_t)src[sp + 1] << 24) | ((uint32_t)src[sp + 2] << 16) | ((uint32_t)src[sp + 3] << 8) | src[sp + 4];
        srcSize = (int)(bits & 0x3FFFF);
        dstSize = (int)((((bits >> 18) | ((uint32_t)src[sp] << 14)) & 0x3FFFF) + 1);
        if (srcSize >= dstSize) return -1;
        sp += 5;
    }
    if (srcEnd - sp < srcSize || dstSize > outputCap) return -1;
    int used;
    switch (chunkType) {
    case 2: case 4: used = decode_type12(src, sp, srcSize, output, dstSize, chunkType >> 1); break;
    default: return -2;
    }
    if (used != srcSize) return -1;
    *decodedSize = dstSize;
    return sp + srcSize - srcOrg;
}

/* ---------------------------------------------------------------- LZ table */
typedef struct {
    uint8_t *lit; int litN;
    uint8_t *cmd; int cmdN;
    int32_t *offs; int offsN;
    int32_t *len; int lenN;
    uint8_t *packedOffs, *packedExtra, *packedLitLen;
} Lz;

static int unpack_offsets(const uint8_t *src, int bsBegin, int bsEnd, int excessFlag, int excessCount,
                          const uint8_t *packedOffs, int offsCount, int offsScaling, const uint8_t *packedExtra,
                          const uint8_t *packedLitLen, int lenCount, int32_t *offsStream, int32_t *lenStream) {
    RBR a = rbr_forward(src, bsBegin, bsEnd);
    RBR b = rbr_backward(src, bsBegin, bsEnd);
    int u32LenStreamSize = 0;
    if (!excessFlag) {
        if (b.Bits < 0x2000) return 0;
        int nn = 31 - bsr_(b.Bits);
        b.BitPos += nn; b.Bits <<= nn; rbr_refill_b(&b);
        nn++;
        u32LenStreamSize = (int)((b.Bits >> (32 - nn)) - 1);
        b.BitPos += nn; b.Bits <<= nn; rbr_refill_b(&b);
    } else {
        for (int q = 0; q < lenCount; q++) if (packedLitLen[q] == 255) u32LenStreamSize++;
    }
    if (offsScaling == 0) {
        int i = 0;
        while (i < offsCount) {
            offsStream[i] = -(int)rbr_distance(&a, packedOffs[i]); i++;
            if (i >= offsCount) break;
            offsStream[i] = -(int)rbr_distance(&b, packedOffs[i]); i++;
        }
    } else {
        int i = 0;
        while (i < offsCount) {
            uint32_t cmd = packedOffs[i];
            if ((cmd >> 3) > 26) return 0;
            uint32_t off = ((8u + (cmd & 7)) << (int)(cmd >> 3)) | rbr_more24(&a, (int)(cmd >> 3));
            offsStream[i] = 8 - (int)off; i++;
            if (i >= offsCount) break;
            cmd = packedOffs[i];
            if ((cmd >> 3) > 26) return 0;
            off = ((8u + (cmd & 7)) << (int)(cmd >> 3)) | rbr_more24(&b, (int)(cmd >> 3));
            offsStream[i] = 8 - (int)off; i++;
        }
        if (offsScaling != 1)
            for (int j = 0; j < offsCount; j++) offsStream[j] = (int8_t)packedExtra[j] - offsStream[j] * offsScaling;
    }
    if (u32LenStreamSize > 512 || u32LenStreamSize < 0) return 0;
    uint32_t u32[520];
    if (excessFlag) {
        RBR ea = rbr_forward(src, bsEnd, bsEnd + excessCount);
        RBR eb = rbr_backward(src, bsEnd, bsEnd + excessCount);
        int i = 0;
        for (; i + 1 < u32LenStreamSize; i += 2) {
            if (!rbr_length(&ea, &u32[i])) return 0;
            if (!rbr_length(&eb, &u32[i + 1])) return 0;
        }
        if (i < u32LenStreamSize) { if (!rbr_length(&ea, &u32[i])) return 0; }
    } else {
        int i = 0;
        for (; i + 1 < u32LenStreamSize; i += 2) {
            if (!rbr_length(&a, &u32[i])) return 0;
            if (!rbr_length(&b, &u32[i + 1])) return 0;
        }
        if (i < u32LenStreamSize) { if (!rbr_length(&a, &u32[i])) return 0; }
    }
    int aSeam = a.P - ((24 - a.BitPos) >> 3);
    int bSeam = b.P + ((24 - b.BitPos) >> 3);
    if (aSeam != bSeam && !excessFlag) return 0;
    int u = 0;
    for (int i = 0; i < lenCount; i++) {
        uint32_t v = packedLitLen[i];
        if (v == 255) {
            if (u >= u32LenStreamSize) return 0;
            v = u32[u++] + 255;
        }
        lenStream[i] = (int)v + 3;
    }
    return u == u32LenStreamSize;
}

/* returns new sp (>=0) or <0 error: -1 malformed, -2 unsupported */
static int read_lz_table(const uint8_t *src, int *spp, int srcEnd, uint8_t *dst, int dstStart, int dstSize, int offset, Lz *lz) {
    int sp = *spp;
    if (offset == 0) {
        if (srcEnd - sp < SEED_SIZE) return -1;
        memcpy(dst + dstStart, src + sp, SEED_SIZE);
        sp += SEED_SIZE;
    }
    int excessFlag = 0, excessCount = 0;
    if (sp < srcEnd && (src[sp] & 0x80) != 0) {
        uint8_t flag = src[sp++];
        if ((flag & 0xC0) != 0x80) return -1;
        excessFlag = 1;
        excessCount = flag & 0x3F;
        if (excessCount > 0x1F) {
            if (sp >= srcEnd) return -1;
            excessCount += src[sp++] * 0x20;
        }
        srcEnd -= excessCount;
        if (srcEnd < sp) return -1;
    }
    int n = decode_bytes(src, sp, srcEnd, dstSize, lz->lit, &lz->litN);
    if (n < 0) return n;
    sp += n;
    n = decode_bytes(src, sp, srcEnd, dstSize, lz->cmd, &lz->cmdN);
    if (n < 0) return n;
    sp += n;
    if (srcEnd - sp < 3) return -1;
    int offsScaling = 0, offsCount, extraCount;
    if ((src[sp] & 0x80) != 0) {
        offsScaling = src[sp] - 127;
        sp++;
        n = decode_bytes(src, sp, srcEnd, lz->cmdN, lz->packedOffs, &offsCount);
        if (n < 0) return n;
        sp += n;
        if (offsScaling != 1) {
            n = decode_bytes(src, sp, srcEnd, offsCount, lz->packedExtra, &extraCount);
            if (n < 0) return n;
            if (extraCount != offsCount) return -1;
            sp += n;
        }
    } else {
        n = decode_bytes(src, sp, srcEnd, lz->cmdN, lz->packedOffs, &offsCount);
        if (n < 0) return n;
        sp += n;
    }
    lz->offsN = offsCount;
    int lenCount;
    n = decode_bytes(src, sp, srcEnd, dstSize >> 2, lz->packedLitLen, &lenCount);
    if (n < 0) return n;
    sp += n;
    lz->lenN = lenCount;
    if (!unpack_offsets(src, sp, srcEnd, excessFlag, excessCount, lz->packedOffs, offsCount, offsScaling,
                        lz->packedExtra, lz->packedLitLen, lenCount, lz->offs, lz->len)) return -1;
    *spp = sp;
    return sp;
}

static int process_runs(int mode, uint8_t *dst, int dstStart, int dstSize, int offset, Lz *lz) {
    int dstEnd = dstStart + dstSize;
    int dstPos = dstStart + (offset == 0 ? SEED_SIZE : 0);
    int dstBase = dstStart - offset;
    int cmdPos = 0, lenPos = 0, litPos = 0, offsPos = 0;
    int recent[7] = { 0, 0, 0, -8, -8, -8, 0 };
    int lastOffset = -8;
    if (mode != 0 && mode != 1) return 0;
    while (cmdPos < lz->cmdN) {
        uint32_t f = lz->cmd[cmdPos++];
        uint32_t litlen = f & 3;
        int offsIndex = (int)(f >> 6);
        uint32_t matchlen = (f >> 2) & 0xF;
        if (litlen == 3) {
            if (lenPos >= lz->lenN) return 0;
            litlen = (uint32_t)lz->len[lenPos++];
        }
        recent[6] = offsPos < lz->offsN ? lz->offs[offsPos] : 0;
        if (litlen != 0) {
            if ((int64_t)litPos + litlen > lz->litN || (int64_t)dstPos + litlen > dstEnd) return 0;
            if (mode == 1) for (uint32_t c = 0; c < litlen; c++) dst[dstPos + c] = lz->lit[litPos + c];
            else for (uint32_t c = 0; c < litlen; c++) dst[dstPos + c] = (uint8_t)(lz->lit[litPos + c] + dst[dstPos + (int)c + lastOffset]);
            dstPos += (int)litlen; litPos += (int)litlen;
        }
        int offv = recent[offsIndex + 3];
        recent[offsIndex + 3] = recent[offsIndex + 2];
        recent[offsIndex + 2] = recent[offsIndex + 1];
        recent[offsIndex + 1] = recent[offsIndex + 0];
        recent[3] = offv;
        lastOffset = offv;
        offsPos += ((offsIndex + 1) & 4) >> 2;
        if (offv >= 0 || dstPos + offv < dstBase) return 0;
        int copyFrom = dstPos + offv;
        uint32_t actual;
        if (matchlen != 15) actual = matchlen + 2;
        else {
            if (lenPos >= lz->lenN) return 0;
            actual = 14 + (uint32_t)lz->len[lenPos++];
        }
        if ((int64_t)dstPos + actual > dstEnd) return 0;
        for (uint32_t c = 0; c < actual; c++) dst[dstPos + c] = dst[copyFrom + c];
        dstPos += (int)actual;
    }
    if (offsPos != lz->offsN || lenPos != lz->lenN) return 0;
    int finalLen = dstEnd - dstPos;
    if (finalLen != lz->litN - litPos) return 0;
    if (mode == 1) for (int c = 0; c < finalLen; c++) dst[dstPos + c] = lz->lit[litPos + c];
    else for (int c = 0; c < finalLen; c++) dst[dstPos + c] = (uint8_t)(lz->lit[litPos + c] + dst[dstPos + c + lastOffset]);
    return 1;
}

static int decode_chunk(const uint8_t *src, int srcStart, int srcLen, uint8_t *dst, int dstStart, int dstSize, int withSeed, int literalMode) {
    int srcEnd = srcStart + srcLen, sp = srcStart;
    int offset = withSeed ? 0 : dstStart;
    Lz lz;
    int cap = CHUNK_MAX + PAD;
    uint8_t *mem = (uint8_t *)malloc((size_t)cap * (1 + 1 + 1 + 1 + 1) + (size_t)cap * 4 * 2 + 64);
    if (!mem) return KRK_MALFORMED;
    lz.lit = mem; lz.cmd = mem + cap; lz.packedOffs = mem + 2 * (size_t)cap; lz.packedExtra = mem + 3 * (size_t)cap;
    lz.packedLitLen = mem + 4 * (size_t)cap;
    lz.offs = (int32_t *)(mem + 5 * (size_t)cap); lz.len = (int32_t *)(mem + 5 * (size_t)cap + (size_t)cap * 4);
    lz.litN = lz.cmdN = lz.offsN = lz.lenN = 0;
    int rc = read_lz_table(src, &sp, srcEnd, dst, dstStart, dstSize, offset, &lz);
    int st;
    if (rc < 0) st = rc == -2 ? KRK_UNSUPPORTED_ENTROPY : KRK_MALFORMED;
    else st = process_runs(literalMode, dst, dstStart, dstSize, offset, &lz) ? KRK_OK : KRK_MALFORMED;
    free(mem);
    return st;
}

static int decode_bare(const uint8_t *src, int srcStart, int srcLen, uint8_t *outBuf, int dstStart, int dstLen) {
    uint8_t *tmp = (uint8_t *)malloc((size_t)dstLen + PAD);
    if (!tmp) return KRK_MALFORMED;
    int cnt, n = decode_bytes(src, srcStart, srcStart + srcLen, dstLen, tmp, &cnt);
    int st = KRK_OK;
    if (n < 0) st = n == -2 ? KRK_UNSUPPORTED_ENTROPY : KRK_MALFORMED;
    else if (n != srcLen || cnt != dstLen) st = KRK_MALFORMED;
    else memcpy(outBuf + dstStart, tmp, dstLen);
    free(tmp);
    return st;
}

static int decode_sub(const uint8_t *src, int srcStart, int srcLen, uint8_t *outBuf, int dstStart, int dstLen,
                      int lzEnable, int restart, int literalMode) {
    if (srcLen < 0 || dstLen < 0) return KRK_MALFORMED;
    if (srcLen == dstLen) { memcpy(outBuf + dstStart, src + srcStart, dstLen); return KRK_OK; }
    return lzEnable ? decode_chunk(src, srcStart, srcLen, outBuf, dstStart, dstLen, restart, literalMode)
                    : decode_bare(src, srcStart, srcLen, outBuf, dstStart, dstLen);
}

KEXPORT int kraken_decode_block(const uint8_t *payload, size_t srclen, int flags, int firstChunkComp, uint8_t *dst, size_t dstlen) {
    if (dstlen == 0) return srclen == 0 ? KRK_OK : KRK_MALFORMED;
    if (srclen > (1u << 20) || dstlen > 2 * CHUNK_MAX) return KRK_MALFORMED;
    uint8_t *src = (uint8_t *)calloc(srclen + PAD, 1);
    uint8_t *outBuf = (uint8_t *)calloc(dstlen + PAD, 1);
    if (!src || !outBuf) { free(src); free(outBuf); return KRK_MALFORMED; }
    memcpy(src, payload, srclen);
    int dl = (int)dstlen, sl = (int)srclen;
    int chunk0Dst = dl < CHUNK_MAX ? dl : CHUNK_MAX;
    int chunk1Dst = dl - chunk0Dst;
    int chunk0Comp = chunk1Dst == 0 ? sl : firstChunkComp;
    int st;
    if (chunk0Comp <= 0 || chunk0Comp > sl) { st = KRK_MALFORMED; goto done; }
    int chunk1Comp = sl - chunk0Comp;
    if (chunk1Dst == 0 && chunk1Comp != 0) { st = KRK_MALFORMED; goto done; }
    st = decode_sub(src, 0, chunk0Comp, outBuf, 0, chunk0Dst, (flags & 0x02) != 0, 1, (flags & 0x01) ? 0 : 1);
    if (st != KRK_OK) goto done;
    if (chunk1Dst > 0) {
        st = decode_sub(src, chunk0Comp, chunk1Comp, outBuf, chunk0Dst, chunk1Dst, (flags & 0x20) != 0, (flags & 0x40) != 0,
                        (flags & 0x10) ? 0 : 1);
        if (st != KRK_OK) goto done;
    }
    memcpy(dst, outBuf, dstlen);
done:
    free(src); free(outBuf);
    return st;
}

/* Convenience: the two sub-chunk boundary is unknown here, so this only handles single-chunk blocks
 * (dstlen <= 128 KiB) or tries first_chunk = every plausible split is NOT attempted; use kraken_decode_block
 * with NAPS metadata for 2-chunk blocks. Returns 0 on success. */
KEXPORT int kraken_decompress(const uint8_t *src, size_t srclen, uint8_t *dst, size_t dstlen) {
    static const int cand1[] = { 0x02, 0x00, 0x03, 0x01 };
    if (dstlen > CHUNK_MAX) return KRK_MALFORMED;
    for (int i = 0; i < 4; i++)
        if (kraken_decode_block(src, srclen, cand1[i], 0, dst, dstlen) == KRK_OK) return 0;
    return KRK_MALFORMED;
}

#ifdef KRAKEN_MAIN
#include <stdio.h>
int main(int argc, char **argv) {
    /* kraken_test src.bin flags first dstlen out.bin */
    if (argc < 6) return 2;
    FILE *f = fopen(argv[1], "rb"); fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *s = malloc(n); fread(s, 1, n, f); fclose(f);
    size_t dl = (size_t)atol(argv[4]); uint8_t *d = malloc(dl);
    int r = kraken_decode_block(s, n, (int)strtol(argv[2], 0, 0), atoi(argv[3]), d, dl);
    printf("status %d\n", r);
    if (r == 0) { f = fopen(argv[5], "wb"); fwrite(d, 1, dl, f); fclose(f); }
    return r;
}
#endif
