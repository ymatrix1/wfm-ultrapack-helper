'use strict';
// Tests the native PS5 "FIH" package path of src/pkg_reader.c (+ src/kraken.c).
//  1. Kraken unit test on tests/fixtures/vec_span.bin (always runs).
//  2. End-to-end against a real 134 GB package that lives on a console and is read over HTTP
//     "GET ... Range:" through tests/http_range.c (only GET requests are ever sent). Skipped (not failed)
//     when the console or the file is unreachable. Overrides: GT7_BASE_URL (default
//     http://192.168.15.6:8888), GT7_PKG_PATH (default /data/homebrew/UP9000-PPSA01317_00-GRANTURISMO70000.pkg).
//  The expected values are the outputs of the independent Python reference (fih_read.py / verify_gt7.py).
const { spawnSync } = require('child_process');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');

const root = path.join(__dirname, '..');
const BASE = process.env.GT7_BASE_URL || 'http://192.168.15.6:8888';
const PKG = process.env.GT7_PKG_PATH || '/data/homebrew/UP9000-PPSA01317_00-GRANTURISMO70000.pkg';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'wup-fih-'));
const exe = path.join(tmp, 'fih_driver' + (process.platform === 'win32' ? '.exe' : ''));
const srcs = ['pkg_reader.c', 'fih_reader.c', 'kraken.c', 'crypto.c', 'miniz.c', 'rsa.c'].map((f) => path.join(root, 'src', f));
const cc = spawnSync(process.env.HOST_CC || 'cc', ['-std=gnu99', '-O2', ...(process.env.EXTRA_CFLAGS ? process.env.EXTRA_CFLAGS.split(' ') : []), '-Wall', '-Wextra', '-Werror', '-I', path.join(root, 'src'), '-I', __dirname,
  path.join(__dirname, 'fih_driver.c'), path.join(__dirname, 'http_range.c'), ...srcs, '-o', exe,
  ...(process.platform === 'win32' ? ['-lws2_32'] : [])], { encoding: 'utf8' });
if (cc.status !== 0) { console.error(cc.stdout + cc.stderr); process.exit(1); }

let passed = 0, failed = 0, skipped = 0;
const ok = (m) => { passed++; console.log(`ok ${m}`); };
const bad = (m) => { failed++; console.error(`FAIL ${m}`); };

// ---- 1. Kraken vector: one real 256 KiB span, flags 0x33, first chunk 59300 compressed bytes
{
  const r = spawnSync(exe, ['kraken', path.join(__dirname, 'fixtures', 'vec_span.bin'), '0x33', '59300', '262144'], { encoding: 'utf8' });
  const want = '0acb851e1514afff31835bc475f4228eb9275308d506ea62956f038eacfb82a3';
  if (r.status === 0 && r.stdout.trim() === `SHA256 ${want}`) ok('kraken vec_span.bin decodes to the reference sha256');
  else bad(`kraken vector: status ${r.status} ${r.stdout.trim()} ${r.stderr}`);
}

// ---- 2. console package
function reachable() {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(BASE); } catch (e) { return resolve(`bad GT7_BASE_URL ${BASE}`); }
    const req = http.request({ host: u.hostname, port: u.port || 80, method: 'GET', path: '/fs?path=' + encodeURIComponent(PKG),
      headers: { Range: 'bytes=0-3' }, timeout: 4000 }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const b = Buffer.concat(chunks);
        if (res.statusCode === 206 && b.length === 4 && b.toString('latin1') === '\x7fFIH') resolve(null);
        else resolve(`package not available (HTTP ${res.statusCode}, magic ${b.toString('hex')})`);
      });
    });
    req.on('timeout', () => { req.destroy(new Error('timeout')); });
    req.on('error', (e) => resolve(`console unreachable (${e.message})`));
    req.end();
  });
}

const EXPECT_FILES = {
  'watermark_img.png': [8105, 'd0291ac693e0cb21'],
  'contents/0/0/6J2QN': [2666496, '217e9fddad98d643'],
  'contents/0/0/6VFRJ': [24436736, 'd8d0670c3020d2b1'],
  'eboot.bin': [110575987, 'e3cdeac5e3ce6794'],
};

(async () => {
  const why = await reachable();
  if (why) {
    console.log(`SKIP FIH console package: ${why} (${BASE}${PKG})`);
    skipped++;
  } else {
    const r = spawnSync(exe, ['console', BASE, PKG, '200'], { encoding: 'utf8', maxBuffer: 1 << 26, timeout: 15 * 60 * 1000 });
    const out = (r.stdout || '').split('\n').filter(Boolean);
    const kv = (line) => Object.fromEntries(line.split(' ').slice(1).map((t) => t.split('=')));
    const get = (tag) => out.find((l) => l.startsWith(tag + ' '));
    const fails = out.filter((l) => l.startsWith('FAIL'));
    if (r.status !== 0 || fails.length) bad(`driver exit ${r.status}: ${fails.slice(0, 5).join(' | ')} ${(r.stderr || '').slice(0, 300)}`);
    const info = get('INFO') ? kv(get('INFO')) : null;
    if (!info) bad('no INFO line');
    else {
      const paramHex = (get('PARAM_HEX') || '').split(' ')[1] || '';
      const paramBytes = paramHex.length / 2;
      let pj = null;
      try { pj = JSON.parse(Buffer.from(paramHex, 'hex').toString('utf8')); } catch (e) { /* reported below */ }
      const errs = [];
      if (info.format !== 'FIH') errs.push(`format ${info.format}`);
      if (Number(info.files) - 1 !== 95387) errs.push(`files ${Number(info.files) - 1} != 95387 (+ sce_sys/param.json)`);
      if (Number(info.dirs) !== 1339) errs.push(`dirs ${info.dirs} != 1339`);
      if (Math.abs((Number(info.total) - paramBytes) / 1e9 - 303.0) > 0.05) errs.push(`logical size ${info.total}`);
      if (Number(info.spans) !== 1218395) errs.push(`spans ${info.spans} != 1218395`);
      if (info.content_id !== 'UP9000-PPSA01317_00-GRANTURISMO70000') errs.push(`content id ${info.content_id}`);
      if (!pj || pj.contentId !== 'UP9000-PPSA01317_00-GRANTURISMO70000') errs.push('param.json missing/invalid contentId');
      for (const l of out.filter((x) => x.startsWith('FILE '))) {
        const [, p, size, sha] = l.split(' ');
        const e = EXPECT_FILES[p];
        if (!e) continue;
        if (Number(size) !== e[0]) errs.push(`${p} size ${size} != ${e[0]}`);
        if (!sha.startsWith(e[1])) errs.push(`${p} sha256 ${sha.slice(0, 16)} != ${e[1]}`);
        delete EXPECT_FILES[p];
      }
      for (const p of Object.keys(EXPECT_FILES)) errs.push(`${p} not read`);
      if (get('PNG') !== 'PNG OK') errs.push('PNG chunk CRCs');
      if (get('ELF') !== 'ELF self=1 elf64=1') errs.push(`ELF: ${get('ELF')}`);
      if (!(get('RANDOM') || '').endsWith(' OK')) errs.push(`random reads: ${get('RANDOM')}`);
      const http_ = get('HTTP total') ? kv(get('HTTP total').replace('HTTP total', 'HTTP')) : null;
      if (http_ && Number(http_.bytes) > 600e6) errs.push(`transferred ${http_.bytes} bytes (> 600 MB)`);
      if (errs.length) bad(`GT7 package: ${errs.join('; ')}`);
      else {
        const openMs = (get('OPEN_MS') || '').split(' ')[1];
        const mbps = (get('MBPS') || '').split(' ')[1];
        ok(`GT7 package: ${info.files - 1} files, ${info.dirs} dirs, ${info.spans} spans, open ${openMs} ms, eboot ${mbps} MB/s, ` +
          `${http_ ? (http_.bytes / 1e6).toFixed(0) + ' MB / ' + http_.requests + ' requests' : ''}, ${get('RANDOM')}`);
      }
    }
  }
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`${passed} passed, ${failed} failed, ${skipped} skipped`);
  process.exit(failed ? 1 : 0);
})();
