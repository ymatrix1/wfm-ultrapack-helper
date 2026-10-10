'use strict';
// Tests src/rsa.c (RSA-2048 CRT private op, PKCS#1 v1.5 / OAEP-SHA1 unpadding)
// and the SHA-1 / AES-128-CBC additions to src/crypto.c against Node's crypto.
const { spawnSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const root = path.join(__dirname, '..');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'wup-rsa-'));
const exe = path.join(tmp, 'rsa_driver' + (process.platform === 'win32' ? '.exe' : ''));
const cc = spawnSync(process.env.HOST_CC || 'cc', ['-std=gnu99', '-O2', ...(process.env.EXTRA_CFLAGS ? process.env.EXTRA_CFLAGS.split(' ') : []), '-Wall', '-Wextra', '-Werror', '-pthread', '-I', path.join(root, 'src'),
  path.join(__dirname, 'rsa_driver.c'), path.join(root, 'src', 'rsa.c'), path.join(root, 'src', 'crypto.c'), '-o', exe],
  { encoding: 'utf8' });
if (cc.status !== 0) { console.error(cc.stdout + cc.stderr); process.exit(1); }

let passed = 0, failed = 0;
function check(name, got, want) {
  if (got === want) { passed++; return; }
  failed++;
  console.error(`FAIL ${name}\n  got:  ${String(got).slice(0, 200)}\n  want: ${String(want).slice(0, 200)}`);
}

const h = (b) => (b.length ? Buffer.from(b).toString('hex') : '-');
const rnd = (n) => crypto.randomBytes(n);
const jobs = [];
function run(cmd, name, want) { jobs.push({ cmd, name, want }); }

// --- SHA-1 official vectors (FIPS 180) ---
run('sha1 -', 'sha1 empty', 'da39a3ee5e6b4b0d3255bfef95601890afd80709');
run(`sha1 ${h(Buffer.from('abc'))}`, 'sha1 abc', 'a9993e364706816aba3e25717850c26c9cd0d89d');
run(`sha1 ${h(Buffer.from('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'))}`, 'sha1 448-bit',
  '84983e441c3bd26ebaae4aa1f95129e5e54670f1');
run(`sha1 ${h(Buffer.alloc(1000000, 0x61))}`, 'sha1 million a', '34aa973cd4c4daa4f61eeb2bdbad27316534016f');
for (const n of [0, 1, 55, 56, 63, 64, 65, 119, 120, 128, 1000, 4097]) {
  for (let t = 0; t < 3; t++) {
    const m = rnd(n);
    const want = crypto.createHash('sha1').update(m).digest('hex');
    run(`sha1 ${h(m)}`, `sha1 random len=${n}`, want);
    run(`sha1chunks ${[1, 7, 64, 100][t % 4] || 1} ${h(m)}`, `sha1 streaming len=${n} t=${t}`, want);
  }
}

// --- AES-128-CBC vs Node (NIST SP 800-38A F.2.1 first) ---
run('cbcenc 2b7e151628aed2a6abf7158809cf4f3c 000102030405060708090a0b0c0d0e0f 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51',
  'SP800-38A cbc enc', '7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2');
run('cbcdec 2b7e151628aed2a6abf7158809cf4f3c 000102030405060708090a0b0c0d0e0f 7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2',
  'SP800-38A cbc dec', '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51');
run(`cbcdec ${'00'.repeat(16)} ${'00'.repeat(16)} ${'00'.repeat(17)}`, 'cbc partial block rejected', 'ERR');
for (let i = 0; i < 60; i++) {
  const k = rnd(16), iv = rnd(16), pt = rnd(16 * (i % 9 + 1) + (i % 5 === 0 ? 4096 : 0));
  const e = crypto.createCipheriv('aes-128-cbc', k, iv); e.setAutoPadding(false);
  const ct = Buffer.concat([e.update(pt), e.final()]);
  run(`cbcenc ${h(k)} ${h(iv)} ${h(pt)}`, `cbc enc random #${i}`, ct.toString('hex'));
  run(`cbcdec ${h(k)} ${h(iv)} ${h(ct)}`, `cbc dec random #${i}`, pt.toString('hex'));
}

// --- RSA ---
const b64 = (s) => Buffer.from(s, 'base64url');
const pad = (b, n) => Buffer.concat([Buffer.alloc(n - b.length), b]);
const big = (b) => BigInt('0x' + (b.length ? b.toString('hex') : '0'));
function modpow(b, e, m) {
  let r = 1n; b %= m;
  while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; }
  return r;
}
const toBuf = (v) => Buffer.from(v.toString(16).padStart(512, '0'), 'hex');

function modinv(a, m) {
  let [r0, r1, t0, t1] = [m, a % m, 0n, 1n];
  while (r1) { const k = r0 / r1; [r0, r1] = [r1, r0 - k * r1]; [t0, t1] = [t1, t0 - k * t1]; }
  return ((t0 % m) + m) % m;
}
const NKEYS = 32;
let benchCmd = null;
let swapped = 0;
for (let ki = 0; ki < NKEYS; ki++) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const j = privateKey.export({ format: 'jwk' });
  const n = pad(b64(j.n), 256), p = pad(b64(j.p), 128), q = pad(b64(j.q), 128);
  const dp = pad(b64(j.dp), 128), dq = pad(b64(j.dq), 128), qi = pad(b64(j.qi), 128);
  const kargs = `${h(n)} ${h(p)} ${h(q)} ${h(dp)} ${h(dq)} ${h(qi)}`;
  const d = big(b64(j.d)), nb = big(n);

  // raw private operation vs Node NO_PADDING and vs BigInt c^d mod n
  const raws = [rnd(256), rnd(256), pad(rnd(255), 256), Buffer.alloc(256, 0), pad(Buffer.from([1]), 256), toBuf(nb - 1n),
    toBuf(nb - 2n), pad(Buffer.from([2]), 256), toBuf(big(p)), toBuf(big(q)), toBuf(big(p) * 3n % nb)];
  raws.forEach((c0, ri) => {
    const c = big(c0) >= nb ? toBuf(big(c0) % nb) : c0;
    const want = toBuf(modpow(big(c), d, nb)).toString('hex');
    run(`rsapriv ${kargs} ${h(c)}`, `key${ki} raw#${ri} vs BigInt`, want);
    if (ri < 3) {
      const nodeOut = crypto.privateDecrypt({ key: privateKey, padding: crypto.constants.RSA_NO_PADDING }, c);
      run(`rsapriv ${kargs} ${h(c)}`, `key${ki} raw#${ri} vs Node`, nodeOut.toString('hex'));
    }
  });
  // same key with the primes swapped (p<q): qinv' = p^-1 mod q
  {
    const qi2 = toBuf(modinv(big(p), big(q))).subarray(128);
    const sk = `${h(n)} ${h(q)} ${h(p)} ${h(dq)} ${h(dp)} ${h(qi2)}`;
    for (let t = 0; t < 3; t++) {
      const c = toBuf(big(rnd(256)) % nb);
      run(`rsapriv ${sk} ${h(c)}`, `key${ki} swapped-primes raw#${t}`, toBuf(modpow(big(c), d, nb)).toString('hex'));
    }
    const m = rnd(40);
    const c2 = crypto.publicEncrypt({ key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1' }, m);
    run(`rsaoaep ${sk} ${h(c2)}`, `key${ki} swapped-primes oaep`, m.toString('hex'));
    swapped++;
  }
  // input >= n must be rejected
  run(`rsapriv ${kargs} ${h(toBuf(nb))}`, `key${ki} c==n rejected`, 'ERR');
  run(`rsapriv ${kargs} ${'ff'.repeat(256)}`, `key${ki} c>n rejected`, 'ERR');

  // PKCS#1 v1.5 and OAEP-SHA1 via publicEncrypt
  const lens = [0, 1, 16, 32, 100, ki % 2 ? 245 : 244];
  for (const L of lens) {
    const m = rnd(L);
    const c1 = crypto.publicEncrypt({ key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING }, m);
    run(`rsapkcs1 ${kargs} ${h(c1)}`, `key${ki} pkcs1 len=${L}`, m.length ? m.toString('hex') : '');
  }
  for (const L of [0, 1, 16, 32, 100, ki % 2 ? 214 : 213]) {
    const m = rnd(L);
    const c2 = crypto.publicEncrypt({ key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1' }, m);
    run(`rsaoaep ${kargs} ${h(c2)}`, `key${ki} oaep len=${L}`, m.length ? m.toString('hex') : '');
  }
  // a pkcs1 block must fail oaep
  const cp1 = crypto.publicEncrypt({ key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING }, rnd(20));
  run(`rsaoaep ${kargs} ${h(cp1)}`, `key${ki} pkcs1 block rejected by oaep`, 'ERR');

  if (ki === 0) benchCmd = `bench ${kargs} ${h(pad(rnd(255), 256))}`;
}

// --- unpadding edge cases (no key) ---
{
  const em = (hdr, ps, body) => Buffer.concat([Buffer.from(hdr), ps, Buffer.from([0]), body]);
  const body = Buffer.from('hello');
  const mk = (ps, hdr = [0, 2]) => { const b = em(hdr, ps, body); return Buffer.concat([b.subarray(0, 2), Buffer.alloc(256 - b.length, 0x77), b.subarray(2)]); };
  run(`unpkcs1 ${h(mk(Buffer.alloc(0)))}`, 'pkcs1 pad filled with 0x77 ok', body.toString('hex'));
  // PS shorter than 8
  const short = Buffer.concat([Buffer.from([0, 2]), Buffer.alloc(7, 0x55), Buffer.from([0]), rnd(256 - 10)]);
  run(`unpkcs1 ${h(short)}`, 'pkcs1 PS < 8 rejected', 'ERR');
  run(`unpkcs1 ${h(Buffer.concat([Buffer.from([0, 1]), Buffer.alloc(254, 0x55)]))}`, 'pkcs1 wrong type rejected', 'ERR');
  run(`unpkcs1 ${h(Buffer.concat([Buffer.from([0, 2]), Buffer.alloc(254, 0x55)]))}`, 'pkcs1 no separator rejected', 'ERR');
  run(`unpkcs1 ${h(Buffer.concat([Buffer.from([0, 2]), Buffer.alloc(8, 0x55), Buffer.from([0]), Buffer.alloc(245 - 0)]).subarray(0, 256))}`,
    'pkcs1 empty message ok-ish', Buffer.alloc(256 - 11, 0).toString('hex'));
  run(`unpkcs1 ${h(Buffer.concat([Buffer.from([0, 2]), Buffer.alloc(253, 0x55), Buffer.from([0])]))}`, 'pkcs1 empty message', '');
  run(`unoaep ${'00'.repeat(256)}`, 'oaep all-zero block rejected', 'ERR');
  run(`unoaep ${h(Buffer.concat([Buffer.from([1]), rnd(255)]))}`, 'oaep leading byte != 0 rejected', 'ERR');
}

const input = jobs.map((j) => j.cmd).join('\n') + '\n' + benchCmd + '\n';
const r = spawnSync(exe, [], { input, encoding: 'utf8', maxBuffer: 1 << 30 });
if (r.status !== 0) { console.error('driver failed', r.status, r.stderr); process.exit(1); }
const lines = r.stdout.split('\n');
jobs.forEach((j, i) => check(j.name, lines[i], j.want));

const bm = /^MS ([0-9.]+)$/.exec(lines[jobs.length] || '');
check('bench output present', !!bm, true);
const ms = bm ? parseFloat(bm[1]) : 1e9;
console.log(`RSA-2048 private op: ${ms.toFixed(2)} ms/op (${NKEYS} keys, ${swapped} also run with primes swapped)`);
check('private op < 200 ms', ms < 200, true);

fs.rmSync(tmp, { recursive: true, force: true });
console.log(`rsa tests: ${passed} passed, ${failed} failed (${jobs.length} driver checks)`);
process.exit(failed ? 1 : 0);
