'use strict';
// Tests src/crypto.c against Node's built-in crypto and official vectors.
const { spawnSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const root = path.join(__dirname, '..');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'wup-crypto-'));
const exe = path.join(tmp, 'crypto_driver' + (process.platform === 'win32' ? '.exe' : ''));
const cc = spawnSync('gcc', ['-std=gnu99', '-O2', ...(process.env.EXTRA_CFLAGS ? process.env.EXTRA_CFLAGS.split(' ') : []), '-Wall', '-Wextra', '-Werror', '-pthread', '-I', path.join(root, 'src'),
  path.join(__dirname, 'crypto_driver.c'), path.join(root, 'src', 'crypto.c'), '-o', exe],
  { encoding: 'utf8' });
if (cc.status !== 0) { console.error(cc.stdout + cc.stderr); process.exit(1); }

let passed = 0, failed = 0;
function check(name, got, want) {
  if (got === want) { passed++; return; }
  failed++;
  console.error(`FAIL ${name}\n  got:  ${String(got).slice(0, 200)}\n  want: ${String(want).slice(0, 200)}`);
}

const h = (b) => (b.length ? Buffer.from(b).toString('hex') : '-');
const hx = (s) => Buffer.from(s.replace(/\s+/g, ''), 'hex');
const rnd = (n) => crypto.randomBytes(n);

// Fresh processes ensure each race starts with uninitialized lookup tables.
for (let i = 0; i < 8; i++) {
  const r = spawnSync(exe, [], { input: 'threads\n', encoding: 'utf8', timeout: 10000 });
  check(`concurrent AES first use #${i}`, r.status === 0 && r.stdout.trim(), 'OK');
}

// Batch every command into a single driver run.
const jobs = [];
function run(cmd, name, want) { jobs.push({ cmd, name, want }); }
const xtsJs = (dec, k1, k2, sector, ssize, data) => {
  const out = [];
  for (let off = 0, s = BigInt(sector); off < data.length; off += ssize, s++) {
    const iv = Buffer.alloc(16); iv.writeBigUInt64LE(s);
    const f = dec ? crypto.createDecipheriv : crypto.createCipheriv;
    const c = f('aes-128-xts', Buffer.concat([k1, k2]), iv); c.setAutoPadding(false);
    out.push(Buffer.concat([c.update(data.subarray(off, off + ssize)), c.final()]));
  }
  return Buffer.concat(out).toString('hex');
};

// --- official vectors ---
run(`sha256 -`, 'FIPS180 sha256 empty', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
run(`sha256 ${h(Buffer.from('abc'))}`, 'FIPS180 sha256 abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
run(`sha256 ${h(Buffer.from('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'))}`, 'FIPS180 sha256 448-bit',
  '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
run(`sha256 ${h(Buffer.from('abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu'))}`,
  'FIPS180 sha256 896-bit', 'cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1');
run(`sha256 ${h(Buffer.alloc(1000000, 0x61))}`, 'FIPS180 sha256 million a', 'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0');
// RFC 4231
const rfc = [
  [Buffer.alloc(20, 0x0b), Buffer.from('Hi There'), 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'],
  [Buffer.from('Jefe'), Buffer.from('what do ya want for nothing?'), '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843'],
  [Buffer.alloc(20, 0xaa), Buffer.alloc(50, 0xdd), '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe'],
  [hx('0102030405060708090a0b0c0d0e0f10111213141516171819'), Buffer.alloc(50, 0xcd), '82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b'],
  [Buffer.alloc(131, 0xaa), Buffer.from('Test Using Larger Than Block-Size Key - Hash Key First'), '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54'],
  [Buffer.alloc(131, 0xaa), Buffer.from('This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.'),
    '9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2'],
];
rfc.forEach(([k, m, w], i) => run(`hmac ${h(k)} ${h(m)}`, `RFC4231 case ${i + 1}`, w));
// FIPS-197 appendix B and C.1
run(`aesenc ${'2b7e151628aed2a6abf7158809cf4f3c'} 3243f6a8885a308d313198a2e0370734`, 'FIPS197 App.B enc', '3925841d02dc09fbdc118597196a0b32');
run(`aesenc 000102030405060708090a0b0c0d0e0f 00112233445566778899aabbccddeeff`, 'FIPS197 C.1 enc', '69c4e0d86a7b0430d8cdb78070b4c55a');
run(`aesdec 000102030405060708090a0b0c0d0e0f 69c4e0d86a7b0430d8cdb78070b4c55a`, 'FIPS197 C.1 dec', '00112233445566778899aabbccddeeff');
// IEEE 1619-2007 vectors 1-3 (data unit sequence number given in hex there)
const xv = [
  ['00'.repeat(16), '00'.repeat(16), 0n, '00'.repeat(32), '917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e'],
  ['11'.repeat(16), '22'.repeat(16), 0x3333333333n, '44'.repeat(32), 'c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0'],
  ['fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0', '22'.repeat(16), 0x3333333333n, '44'.repeat(32), 'af85336b597afc1a900b2eb21ec949d292df4c047e0b21532186a5971a227a89'],
];
xv.forEach(([k1, k2, s, pt, ct], i) => {
  run(`xtsenc ${k1} ${k2} ${s} 32 ${pt}`, `IEEE1619 vector ${i + 1} enc`, ct);
  run(`xtsdec ${k1} ${k2} ${s} 32 ${ct}`, `IEEE1619 vector ${i + 1} dec`, pt);
});
// error handling: partial block and bad sector size
run(`xtsdec ${'00'.repeat(16)} ${'11'.repeat(16)} 0 4096 ${'00'.repeat(17)}`, 'XTS partial block rejected', 'ERR');
run(`xtsdec ${'00'.repeat(16)} ${'11'.repeat(16)} 0 24 ${'00'.repeat(48)}`, 'XTS sector size not multiple of 16 rejected', 'ERR');
run(`xtsdec ${'00'.repeat(16)} ${'11'.repeat(16)} 0 0 ${'00'.repeat(48)}`, 'XTS zero sector size rejected', 'ERR');

// --- random vs Node ---
const sizes = [0, 1, 3, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 1000, 4096, 10007];
for (const n of sizes) {
  for (let t = 0; t < 4; t++) {
    const m = rnd(n);
    run(`sha256 ${h(m)}`, `sha256 random len=${n}`, crypto.createHash('sha256').update(m).digest('hex'));
    const k = rnd([0, 1, 16, 32, 64, 65, 100, 200][(t * 3 + n) % 8]);
    run(`hmac ${h(k)} ${h(m)}`, `hmac random klen=${k.length} mlen=${n}`, crypto.createHmac('sha256', k).update(m).digest('hex'));
  }
}
{
  // streaming API is covered by the million-a vector; also verify chunk boundaries via one-shot on odd sizes above
}
for (let i = 0; i < 300; i++) {
  const k = rnd(16), b = rnd(16);
  const e = crypto.createCipheriv('aes-128-ecb', k, null); e.setAutoPadding(false);
  const ct = Buffer.concat([e.update(b), e.final()]);
  run(`aesenc ${h(k)} ${h(b)}`, `aes enc random #${i}`, ct.toString('hex'));
  run(`aesdec ${h(k)} ${h(ct)}`, `aes dec random #${i}`, b.toString('hex'));
}
const ssizes = [16, 32, 48, 512, 4096];
const sectors = [0n, 1n, 2n, 255n, 256n, 65535n, 0xffffffffn, 0x100000000n, 0x123456789abcdefn, (1n << 64n) - 4n];
for (let i = 0; i < 120; i++) {
  const k1 = rnd(16), k2 = rnd(16);
  const ss = ssizes[i % ssizes.length];
  const nsec = 1 + (i % 4);
  const len = i % 7 === 0 ? ss * nsec - 16 * (i % 3) : ss * nsec;
  const L = Math.max(16, len);
  const s = sectors[i % sectors.length];
  const pt = rnd(L);
  const ct = xtsJs(false, k1, k2, s, ss, pt);
  run(`xtsenc ${h(k1)} ${h(k2)} ${s} ${ss} ${h(pt)}`, `xts enc ss=${ss} len=${L} sector=${s}`, ct);
  run(`xtsdec ${h(k1)} ${h(k2)} ${s} ${ss} ${ct}`, `xts dec ss=${ss} len=${L} sector=${s}`, pt.toString('hex'));
}
// PFS-style: 1 MiB of 0x1000 sectors starting at a nonzero index
{
  const k1 = rnd(16), k2 = rnd(16), pt = rnd(1 << 20), s = 777n;
  const ct = xtsJs(false, k1, k2, s, 0x1000, pt);
  run(`xtsdec ${h(k1)} ${h(k2)} ${s} 4096 ${ct}`, 'xts dec 1MiB 0x1000 sectors', pt.toString('hex'));
}

const input = jobs.map((j) => j.cmd).join('\n') + '\nbench\n';
const r = spawnSync(exe, [], { input, encoding: 'utf8', maxBuffer: 1 << 30 });
if (r.status !== 0) { console.error('driver failed', r.status, r.stderr); process.exit(1); }
const lines = r.stdout.split('\n');
jobs.forEach((j, i) => check(j.name, lines[i], j.want));

const bm = /^MBPS ([0-9.]+)$/.exec(lines[jobs.length] || '');
check('bench output present', !!bm, true);
const mbps = bm ? parseFloat(bm[1]) : 0;
console.log(`XTS decrypt speed: ${mbps.toFixed(1)} MB/s (64 MiB, 0x1000 sectors)`);
// Sanitizer builds are 10-50x slower; the throughput floor only makes sense for plain builds.
const sanitized = /sanitize/.test(process.env.EXTRA_CFLAGS || '');
if (!sanitized) check('speed > 20 MB/s', mbps > 20, true);

fs.rmSync(tmp, { recursive: true, force: true });
console.log(`crypto tests: ${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
