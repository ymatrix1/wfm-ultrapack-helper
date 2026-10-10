'use strict';
// Tests src/pkg_reader.c against committed manifests (tests/fixtures/<pkg>.manifest.json).
// The .pkg files are NOT in the repo: set PKG_FIXTURE_DIR (default /mnt/c/Users/yuri_/Downloads in WSL).
// A missing package SKIPs that case.
const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const root = path.join(__dirname, '..');
const fixDir = process.env.PKG_FIXTURE_DIR ||
  (fs.existsSync('/mnt/c/Users') ? '/mnt/c/Users/yuri_/Downloads' : path.join(os.homedir(), 'Downloads'));
const PKGS = ['PS5_LAPY20012_v1.00.pkg', 'PS5_ITEM00001_v1.14.pkg'];

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'wup-pkg-'));
const exe = path.join(tmp, 'pkg_driver' + (process.platform === 'win32' ? '.exe' : ''));
const srcs = ['pkg_reader.c', 'fih_reader.c', 'kraken.c', 'crypto.c', 'miniz.c', 'rsa.c'].map((f) => path.join(root, 'src', f));
const cc = spawnSync('gcc', ['-std=gnu99', '-O2', ...(process.env.EXTRA_CFLAGS ? process.env.EXTRA_CFLAGS.split(' ') : []), '-Wall', '-Wextra', '-Werror', '-pthread', '-I', path.join(root, 'src'),
  path.join(__dirname, 'pkg_driver.c'), ...srcs, '-o', exe], { encoding: 'utf8' });
if (cc.status !== 0) { console.error(cc.stdout + cc.stderr); process.exit(1); }

let passed = 0, failed = 0, skipped = 0;
for (const name of PKGS) {
  const pkg = path.join(fixDir, name);
  const manPath = path.join(__dirname, 'fixtures', name.replace(/\.pkg$/, '.manifest.json'));
  if (!fs.existsSync(pkg)) { console.log(`SKIP ${name}: not found in ${fixDir} (set PKG_FIXTURE_DIR)`); skipped++; continue; }
  const man = JSON.parse(fs.readFileSync(manPath, 'utf8'));
  const r = spawnSync(exe, [pkg, '-', '400'], { encoding: 'utf8', maxBuffer: 1 << 26 });
  const out = r.stdout.split('\n').filter(Boolean);
  const files = new Map(), dirs = new Set();
  let randomOk = false, mbps = '?', total = 0;
  for (const l of out) {
    const t = l.split(' ');
    if (t[0] === 'F') files.set(t[1], { size: Number(t[2]), sha256: t[3] });
    else if (t[0] === 'D') dirs.add(t[1]);
    else if (l.startsWith('RANDOM') && l.endsWith('OK')) randomOk = true;
    else if (t[0] === 'MBPS') mbps = t[1];
    else if (t[0] === 'ENTRIES') total = Number(t[3]);
  }
  const errs = [];
  if (r.status !== 0) errs.push(`driver exit ${r.status}: ${out.filter((l) => /FAIL/.test(l)).slice(0, 5).join(' | ')}`);
  if (!randomOk) errs.push('random-access check did not pass');
  let match = 0;
  for (const m of man) {
    const g = files.get(m.path);
    if (!g) errs.push(`missing ${m.path}`);
    else if (g.size !== m.size) errs.push(`size ${m.path}: ${g.size} != ${m.size}`);
    else if (g.sha256 !== m.sha256) errs.push(`sha256 ${m.path}`);
    else match++;
    const parts = m.path.split('/');
    for (let i = 1; i < parts.length; i++) {
      if (!dirs.has(parts.slice(0, i).join('/'))) errs.push(`no dir entry for ${parts.slice(0, i).join('/')}`);
    }
  }
  const want = new Set(man.map((m) => m.path));
  for (const p of files.keys()) if (!want.has(p)) errs.push(`unexpected ${p}`);
  const sum = man.reduce((a, m) => a + m.size, 0);
  if (sum !== total) errs.push(`TOTAL ${total} != manifest sum ${sum}`);
  if (errs.length) { failed++; console.error(`FAIL ${name}: ${errs.slice(0, 10).join('\n  ')}`); }
  else { passed++; console.log(`ok ${name}: ${match}/${man.length} files match, random reads ok, ${mbps} MB/s`); }
}
fs.rmSync(tmp, { recursive: true, force: true });
console.log(`${passed} passed, ${failed} failed, ${skipped} skipped`);
process.exit(failed ? 1 : 0);
