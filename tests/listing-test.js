'use strict';
// Tests the listing -> exFAT / ffpfsc API: a flat listing + random-access data source (in-memory fake,
// see tests/listing_driver.c) must produce exactly the bytes the folder path produces for the same tree.
const { spawnSync } = require('child_process');
const crypto = require('crypto');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');

const root = path.join(__dirname, '..');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'wup-listing-'));
process.on('exit', () => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) { /* best effort */ } });

const exe = path.join(tmp, 'listing_driver');
const cc = spawnSync('gcc', ['-std=gnu99', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-sign-compare', '-I', path.join(root, 'src'),
  path.join(__dirname, 'listing_driver.c'), path.join(root, 'src', 'exfat_engine.c'),
  path.join(root, 'src', 'convert_engine.c'), path.join(root, 'src', 'miniz.c'),
  path.join(root, 'src', 'pkg_reader.c'), path.join(root, 'src', 'crypto.c'), path.join(root, 'src', 'rsa.c'), '-o', exe],
  { encoding: 'utf8' });
if (cc.status !== 0) { console.error(cc.stdout + cc.stderr); process.exit(1); }

const sh = (cmd, args) => spawnSync(cmd, args, { encoding: 'utf8' });
const haveFsck = sh('which', ['fsck.exfat']).status === 0;
if (!haveFsck) console.log('       (fsck.exfat not installed; byte-equality checks only)');
const drv = (...args) => sh(exe, args);
const sha = (f) => crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');

let n = 0;
const work = (name) => { const d = path.join(tmp, `w${n++}-${name}`); fs.mkdirSync(d, { recursive: true }); return d; };

let passed = 0, failed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log(`  ok   ${name}`); } catch (e) { failed++; console.error(`  FAIL ${name}\n    ${e.stack || e}`); }
}

// ---- listing helpers -------------------------------------------------------------------------
const F = (p, size, id) => ({ p, size, id, dir: false });
const D = (p) => ({ p, dir: true });
const specText = (es) => es.map((e) => (e.dir ? `D\t\t\t${e.p}` : `F\t${e.size}\t${e.id}\t${e.p}`)).join('\n') + '\n';
function writeSpec(dir, es, name = 'spec.txt') {
  const f = path.join(dir, name);
  fs.writeFileSync(f, specText(es));
  return f;
}
function shuffled(es, seed) {
  const a = es.slice();
  let s = seed >>> 0;
  const rnd = () => { s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0; return s; };
  for (let i = a.length - 1; i > 0; i--) { const j = rnd() % (i + 1); [a[i], a[j]] = [a[j], a[i]]; }
  return a;
}
function unpfsc(d) {
  assert.strictEqual(d.toString('ascii', 0, 4), 'PFSC');
  const bs = Number(d.readBigUInt64LE(0x10)), tbl = Number(d.readBigUInt64LE(0x18));
  const logical = Number(d.readBigUInt64LE(0x28));
  const parts = [];
  for (let i = 0; i < logical / bs; i++) {
    const a = Number(d.readBigUInt64LE(tbl + i * 8)), e = Number(d.readBigUInt64LE(tbl + (i + 1) * 8));
    const chunk = d.subarray(a, e);
    parts.push(chunk.length === bs ? chunk : zlib.inflateSync(chunk));
  }
  return Buffer.concat(parts);
}
function fsckClean(img) {
  if (!haveFsck) return;
  const r = sh('fsck.exfat', [img]);
  assert.strictEqual(r.status, 0, r.stdout + r.stderr);
}
const ok = (r, what) => assert.strictEqual(r.status, 0, `${what}: exit ${r.status}\n${r.stdout}${r.stderr}`);

// Listing -> exfat image path, plus the folder-path image of the same data materialized on disk.
function both(es, tag) {
  const w = work(tag);
  const spec = writeSpec(w, es);
  const mat = path.join(w, 'tree');
  ok(drv('materialize', spec, mat), 'materialize');
  const folderImg = path.join(w, 'folder.exfat');
  ok(drv('folder-exfat', mat, folderImg), 'folder-exfat');
  return { w, spec, mat, folderImg };
}

// ---- fixtures ---------------------------------------------------------------------------------
const MiB = 1024 * 1024;
const base = [];
let nextId = 1000;
const addF = (p, size) => { base.push(F(p, size, nextId)); nextId += 7; };
addF('Ünïcödé.txt', 5);
addF('日本語/ファイル.bin', 1000);
addF('emoji/😀 smile.txt', 70000);
addF('empty.dat', 0);
base.push(D('emptydir/nested/deeper'));
addF('big/random3mb.bin', 3 * MiB);
addF('multi/cluster.bin', 150001);
addF('multi/exact64k.bin', 65536);
addF('multi/Zeta', 65537);
addF('multi/alpha', 5);
addF('.DS_Store', 10);
addF('._ghost', 10);
addF('sub/Thumbs.db', 10);
addF('sub/keep.txt', 100);
addF('__MACOSX/inner.txt', 7);
addF('multi/Desktop.INI', 3);
base.push(D('many'));
for (let i = 0; i < 40; i++) addF(`many/file_with_long_name_to_force_dir_growth_${String(i).padStart(4, '0')}.dat`, i * 3);
addF(`long/${'x'.repeat(200)}.txt`, 3);

console.log('listing -> exFAT');
const ref = both(base, 'base');
const refHash = sha(ref.folderImg);

for (const [label, es] of [['given order', base], ['reversed', base.slice().reverse()],
  ['shuffled #1', shuffled(base, 1)], ['shuffled #2', shuffled(base, 987654321)]]) {
  test(`exfat from listing (${label}) == folder image, fsck clean`, () => {
    const out = path.join(ref.w, `l-${label.replace(/\W/g, '')}.exfat`);
    const r = drv('exfat', writeSpec(ref.w, es, 's.txt'), out);
    ok(r, 'listing exfat');
    assert.match(r.stdout, /^OK reads=\d+ bytes=\d+/);
    assert.strictEqual(sha(out), refHash);
    fsckClean(out);
  });
}

test('reference image is fsck clean and holds the expected bytes of the 3 MiB file', () => {
  fsckClean(ref.folderImg);
  const img = fs.readFileSync(ref.folderImg);
  const disk = fs.readFileSync(path.join(ref.mat, 'big', 'random3mb.bin'));
  assert.ok(img.includes(disk.subarray(0, 4096)) && img.includes(disk.subarray(3 * MiB - 4096)));
});

test('reads are chunked (<=1 MiB), in order, and cover every non-ignored file', () => {
  const r = drv('exfat', ref.spec, path.join(ref.w, 'c.exfat'));
  ok(r, 'exfat');
  const m = /reads=(\d+) bytes=(\d+)/.exec(r.stdout);
  const expected = base.filter((e) => !e.dir && !/(\.DS_Store|\._ghost|Thumbs\.db|__MACOSX|Desktop\.INI)/.test(e.p))
    .reduce((a, e) => a + e.size, 0);
  assert.strictEqual(Number(m[2]), expected);
  assert.ok(Number(m[1]) >= Math.ceil(expected / MiB));
});

test('noisy paths (leading/double/trailing slashes) equal the clean listing', () => {
  const clean = [F('a/b/c.txt', 100, 1), D('a/d'), F('top.bin', 70000, 2)];
  const noisy = [F('//a///b/c.txt', 100, 1), D('a/d/'), F('/top.bin', 70000, 2), D(''), D('/')];
  const w = work('noisy');
  const o1 = path.join(w, '1.exfat'), o2 = path.join(w, '2.exfat');
  ok(drv('exfat', writeSpec(w, clean, 'a.txt'), o1), 'clean');
  ok(drv('exfat', writeSpec(w, noisy, 'b.txt'), o2), 'noisy');
  assert.strictEqual(sha(o1), sha(o2));
});

test('empty listing == empty folder, fsck clean', () => {
  const t = both([], 'empty');
  const out = path.join(t.w, 'l.exfat');
  ok(drv('exfat', t.spec, out), 'exfat');
  assert.strictEqual(sha(out), sha(t.folderImg));
  fsckClean(out);
});

test('wide directory (5000 entries, shuffled) == folder image, fsck clean', () => {
  const es = [];
  for (let i = 0; i < 5000; i++) es.push(F(`wide/f${String(i).padStart(5, '0')}.bin`, i % 5 === 0 ? 100 + i : 0, 50000 + i));
  const t = both(shuffled(es, 42), 'wide');
  const out = path.join(t.w, 'l.exfat');
  const t0 = Date.now();
  ok(drv('exfat', t.spec, out), 'exfat');
  assert.ok(Date.now() - t0 < 20000, 'too slow');
  assert.strictEqual(sha(out), sha(t.folderImg));
  fsckClean(out);
});

console.log('listing -> ffpfsc');
test('ffpfsc from listing == folder -> ffpfsc, inner image == exFAT, fsck clean', () => {
  const lo = path.join(ref.w, 'l.ffpfsc');
  const r = drv('ffpfsc', writeSpec(ref.w, shuffled(base, 7), 'f.txt'), lo);
  ok(r, 'listing ffpfsc');
  const fo = path.join(ref.w, 'fout');
  fs.mkdirSync(fo);
  ok(drv('folder-ffpfsc', ref.mat, fo), 'folder ffpfsc');
  const folderPfsc = path.join(fo, 'tree.ffpfsc');
  assert.strictEqual(sha(lo), sha(folderPfsc));
  const inner = unpfsc(fs.readFileSync(lo));
  const exfat = fs.readFileSync(ref.folderImg);
  assert.ok(inner.subarray(0, exfat.length).equals(exfat), 'decompressed prefix differs from exFAT image');
  assert.ok(inner.subarray(exfat.length).every((b) => b === 0), 'padding must be zero');
  const img = path.join(ref.w, 'inner.exfat');
  fs.writeFileSync(img, inner.subarray(0, exfat.length));
  fsckClean(img);
});

console.log('error handling');
function failsClean(label, es, args, re, code = 1) {
  for (const mode of ['exfat', 'ffpfsc']) {
    const w = work(`${label}-${mode}`);
    const out = path.join(w, `o.${mode}`);
    const r = drv(mode, writeSpec(w, es), out, ...args);
    assert.strictEqual(r.status, code, `${mode}: exit ${r.status}\n${r.stdout}${r.stderr}`);
    if (re) assert.match(r.stderr, re, mode);
    assert.ok(!fs.existsSync(out), `${mode}: output must be removed`);
    assert.deepStrictEqual(fs.readdirSync(w).filter((f) => f !== 'spec.txt'), [], `${mode}: stray files`);
  }
}
test('case-insensitive duplicate names are rejected', () => failsClean('dup', [F('A', 1, 1), F('a', 1, 2)], [], /duplicate/i));
test('case-insensitive duplicate directories via different case parents are rejected',
  () => failsClean('dup2', [F('Dir/x', 1, 1), F('dir/y', 1, 2)], [], /duplicate/i));
test('exact duplicate paths are rejected', () => failsClean('dup3', [F('a', 1, 1), F('a', 2, 2)], [], /duplicate/i));
test('a file used as a directory is rejected', () => failsClean('conflict', [F('x', 1, 1), F('x/y', 1, 2)], [], /conflict/i));
test('a file with an empty path is rejected', () => failsClean('emptypath', [F('', 1, 1)], [], /empty path/i));
test('short read (first chunk) is an error', () => failsClean('short0', [F('f', 3 * MiB, 5)], ['--short=5'], /Source read failed/));
test('short read (late chunk) is an error', () =>
  failsClean('short1', [F('f', 3 * MiB, 5)], ['--short=5', '--at=1048576'], /Source read failed.*offset 1048576/));
test('negative read result is an error', () => failsClean('neg', [F('g', 70000, 6)], ['--neg=6'], /Source read failed/));
test('cancel mid-stream returns -2 and leaves no output', () =>
  failsClean('cancel', [F('f', 3 * MiB, 5), F('d/g', 70000, 6)], ['--cancel-after=3'], /cancel/i, 2));

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
