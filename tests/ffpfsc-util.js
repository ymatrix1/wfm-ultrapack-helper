'use strict';
// Reusable .ffpfsc parser for the tests. A .ffpfsc is a PFS image (ultrapack layout): header block,
// inode table, super_root dirents, flat path table, uroot dirents, then ONE inner file whose data is a
// PFSC container (header 0x30, offset table at +0x400, zlib 64 KiB blocks). All PFSC offsets are relative
// to the start of the PFSC container, which begins at inodes[file].db[0] * pfs block size.
const assert = require('assert');
const zlib = require('zlib');

const PFS_MAGIC = 20130315;
const PFSC_MAGIC = 0x43534650;
const INODE_SIZE = 0xA8;

function parseDirents(buf, off, size) {
  const out = [];
  let p = off;
  const end = off + size;
  while (p + 16 <= end) {
    const ino = buf.readUInt32LE(p), type = buf.readInt32LE(p + 4);
    const nl = buf.readInt32LE(p + 8), ent = buf.readInt32LE(p + 12);
    if (ent === 0) break;
    out.push({ ino, type, name: buf.toString('latin1', p + 16, p + 16 + nl) });
    p += ent;
  }
  return out;
}

/** Parse a whole .ffpfsc buffer. Throws (AssertionError) on any structural inconsistency. */
function parseFfpfsc(buf) {
  assert.ok(buf.length >= 0x10000 * 6, 'too small to be a PFS image');
  const pfsHeader = {
    version: Number(buf.readBigInt64LE(0x00)),
    magic: Number(buf.readBigInt64LE(0x08)),
    readonly: buf[0x1A],
    mode: buf.readUInt16LE(0x1C),
    blockSize: buf.readUInt32LE(0x20),
    nblock: Number(buf.readBigInt64LE(0x28)),
    inodeCount: Number(buf.readBigInt64LE(0x30)),
    ndblock: Number(buf.readBigInt64LE(0x38)),
    inodeBlockCount: Number(buf.readBigInt64LE(0x40)),
  };
  assert.strictEqual(pfsHeader.magic, PFS_MAGIC, 'PFS magic');
  const bs = pfsHeader.blockSize;
  assert.strictEqual(buf.toString('ascii', 0, 4) === 'PFSC', false, 'PFSC must not be at offset 0');
  assert.strictEqual(buf.length, pfsHeader.ndblock * bs, 'file size == ndblock * block size');

  const inodes = [];
  for (let i = 0; i < pfsHeader.inodeCount; i++) {
    const o = bs + i * INODE_SIZE;
    const ino = {
      number: i,
      mode: buf.readUInt16LE(o), nlink: buf.readUInt16LE(o + 2), flags: buf.readUInt32LE(o + 4),
      size: Number(buf.readBigInt64LE(o + 8)), sizeCompressed: Number(buf.readBigInt64LE(o + 0x10)),
      time: Number(buf.readBigInt64LE(o + 0x18)),
      blocks: buf.readUInt32LE(o + 0x60),
      db: [], ib: [],
    };
    for (let k = 0; k < 12; k++) ino.db.push(buf.readInt32LE(o + 0x64 + 4 * k));
    for (let k = 0; k < 5; k++) ino.ib.push(buf.readInt32LE(o + 0x94 + 4 * k));
    inodes.push(ino);
  }
  assert.ok(inodes.length >= 4, 'need super_root, fpt, uroot and one file inode');

  const superRoot = parseDirents(buf, inodes[0].db[0] * bs, inodes[0].size);
  assert.deepStrictEqual(superRoot.map((d) => d.name), ['flat_path_table', 'uroot']);
  const uroot = parseDirents(buf, inodes[2].db[0] * bs, inodes[2].size);
  assert.deepStrictEqual(uroot.slice(0, 2).map((d) => d.name), ['.', '..']);
  const files = uroot.filter((d) => d.type === 2);
  assert.strictEqual(files.length, 1, 'exactly one inner file');
  const innerName = files[0].name;
  const fileInode = inodes[files[0].ino];
  const innerOffset = fileInode.db[0] * bs;
  const innerSize = fileInode.size;
  assert.ok(fileInode.flags & 1, 'inner file inode is flagged compressed');

  // flat path table: sorted (hash, inode) pairs
  const fpt = [];
  for (let o = inodes[1].db[0] * bs; o < inodes[1].db[0] * bs + inodes[1].size; o += 8) {
    fpt.push({ hash: buf.readUInt32LE(o), value: buf.readUInt32LE(o + 4) });
  }

  // PFSC container at the inner file
  const p = innerOffset;
  const pfsc = {
    magic: buf.readInt32LE(p), unk4: buf.readInt32LE(p + 4), unk8: buf.readInt32LE(p + 8),
    lbs32: buf.readInt32LE(p + 12), lbs: Number(buf.readBigInt64LE(p + 0x10)),
    offsetsOffset: Number(buf.readBigInt64LE(p + 0x18)), dataOffset: Number(buf.readBigUInt64LE(p + 0x20)),
    dataLength: Number(buf.readBigInt64LE(p + 0x28)),
  };
  assert.strictEqual(pfsc.magic, PFSC_MAGIC, 'PFSC magic at the inner file');
  assert.strictEqual(pfsc.lbs, pfsc.lbs32);
  const nblocks = pfsc.dataLength / pfsc.lbs;
  assert.ok(Number.isInteger(nblocks));
  const blocks = [];
  for (let i = 0; i < nblocks; i++) {
    const a = Number(buf.readBigUInt64LE(p + pfsc.offsetsOffset + i * 8));
    const e = Number(buf.readBigUInt64LE(p + pfsc.offsetsOffset + (i + 1) * 8));
    assert.ok(e >= a && e <= innerSize, `block ${i} range ${a}..${e} within the inner file (${innerSize})`);
    blocks.push({ start: a, end: e, len: e - a, raw: e - a === pfsc.lbs });
  }

  function inflate() {
    const parts = [];
    for (const b of blocks) {
      const s = buf.subarray(innerOffset + b.start, innerOffset + b.end);
      parts.push(b.raw ? s : zlib.inflateSync(s));
    }
    const out = Buffer.concat(parts);
    assert.strictEqual(out.length, pfsc.dataLength, 'inflated length == PFSC logical size');
    return out;
  }

  return { pfsHeader, inodes, superRoot, uroot, fpt, innerName, innerOffset, innerSize, rawSize: fileInode.sizeCompressed,
           pfsc, blocks, inflate };
}

/** Inflate a .ffpfsc to the logical (block-padded) inner image. */
function unpfsc(buf) { return parseFfpfsc(buf).inflate(); }

module.exports = { parseFfpfsc, unpfsc };
