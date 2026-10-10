'use strict';
// Would ShadowMountPlus accept what we produce? Converts sample trees with the real daemon and applies
// the offline ShadowMountPlus checks from tests/shadowmount-check.js (cluster size, PFS container shape,
// sce_sys/param.json rules). The negative cases prove the checker really rejects what the console rejects
// (e.g. the apollo.ffpfsc log line "missing/invalid param.json").
const assert = require('assert');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const { checkImage } = require('./shadowmount-check');

if (process.platform !== 'linux') { console.log('shadowmount-compat test needs Linux; skipping.'); process.exit(0); }

const ROOT = path.resolve(__dirname, '..');
const BIN = path.join(ROOT, 'wfm-ultrapack-helper-linux');
const SOCK = process.env.WUP_SOCKET || '/tmp/wup-smp-compat.sock';
const SANITIZED = /sanitize/.test(process.env.EXTRA_CFLAGS || '');

function frame(type, rid, payload) {
  const b = Buffer.alloc(20 + payload.length);
  b.write('WUPH', 0, 'ascii'); b.writeUInt16BE(type, 4); b.writeUInt32BE(payload.length, 8); b.writeBigUInt64BE(BigInt(rid), 12);
  payload.copy(b, 20);
  return b;
}

function convert(src, dst, fmt) {
  return new Promise((resolve, reject) => {
    const c = net.createConnection(SOCK);
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => { c.destroy(); reject(new Error('timeout')); }, SANITIZED ? 600000 : 60000);
    c.on('connect', () => c.write(frame(10, 1, Buffer.from(`${src}\n${dst}\n${fmt}`))));
    c.on('data', d => {
      buf = Buffer.concat([buf, d]);
      while (buf.length >= 20) {
        const n = buf.readUInt32BE(8);
        if (buf.length < 20 + n) break;
        const type = buf.readUInt16BE(4), msg = buf.subarray(20, 20 + n).toString();
        buf = buf.subarray(20 + n);
        if (type === 24 || type === 25) { clearTimeout(timer); c.end(); resolve({ type, msg }); }
      }
    });
    c.on('error', reject);
  });
}

const results = [];
async function test(name, fn) {
  try { await fn(); results.push(true); console.log('  ok   ' + name); }
  catch (e) { results.push(false); console.log('  FAIL ' + name + '\n       ' + String(e.stack || e).split('\n').slice(0, 4).join('\n       ')); }
}

function makeTree(root, paramJson) {
  fs.mkdirSync(path.join(root, 'sce_sys'), { recursive: true });
  fs.mkdirSync(path.join(root, 'media'), { recursive: true });
  fs.writeFileSync(path.join(root, 'eboot.bin'), require('crypto').randomBytes(300000));
  fs.writeFileSync(path.join(root, 'media', 'data.bin'), Buffer.alloc(200000, 7));
  if (paramJson !== null) fs.writeFileSync(path.join(root, 'sce_sys', 'param.json'), paramJson);
}

(async () => {
  if (!fs.existsSync(BIN)) throw new Error('build the daemon first: make linux');
  try { fs.unlinkSync(SOCK); } catch (_) {}
  const daemon = spawn(BIN, [], { stdio: 'ignore', env: { ...process.env, WUP_SOCKET: SOCK } });
  for (let i = 0; i < 50 && !fs.existsSync(SOCK); i++) await new Promise(r => setTimeout(r, 100));
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'wup-smp-'));
  const GOOD = JSON.stringify({ titleId: 'PPSA12345', localizedParameters: { defaultLanguage: 'en-US', 'en-US': { titleName: 'Test Game' } } });
  const cases = [
    ['good', GOOD, true, null],
    ['no-param', null, false, /param\.json missing/],
    ['bad-json', '{ not json', false, /not valid JSON/],
    ['bad-titleid', JSON.stringify({ titleId: 'ABCD12345' }), false, /not PPSA\|CUSA\|LAPY\|FAKE/],
    ['title_id-key', JSON.stringify({ title_id: 'CUSA00001' }), true, null],
  ];
  try {
    for (const [name, pj, ok, re] of cases) {
      const tree = path.join(work, name);
      makeTree(tree, pj);
      for (const fmt of ['ffpfsc', 'exfat']) {
        await test(`${name} -> ${fmt}: ShadowMountPlus checks ${ok ? 'pass' : 'reject as expected'}`, async () => {
          const out = path.join(work, 'out_' + name + '_' + fmt); fs.mkdirSync(out);
          const r = await convert(tree, out, fmt);
          assert.strictEqual(r.type, 24, r.msg);
          const f = path.join(out, name + '.' + fmt);
          const res = checkImage(fs.readFileSync(f), fmt);
          if (ok) {
            assert.deepStrictEqual(res.problems, [], res.problems.join('; '));
            assert.ok(res.titleId && res.titleName);
            if (name === 'good') assert.strictEqual(res.titleName, 'Test Game');
          } else {
            assert.ok(res.problems.some(p => re.test(p)), 'expected a problem matching ' + re + ', got ' + JSON.stringify(res.problems));
          }
          assert.ok(!res.warnings.some(w => /cluster size/.test(w)), 'cluster must be 64 KiB: ' + res.warnings);
          if (fmt === 'ffpfsc' && name === 'good') assert.strictEqual(res.innerName, 'PPSA12345.exfat'); // titleId from param.json
        });
      }
    }
    // the PS4/PS5 package fixtures: informational (the old-style containers carry param.sfo, not param.json)
    const dir = process.env.PKG_FIXTURE_DIR || '/mnt/c/Users/yuri_/Downloads';
    for (const pkg of ['PS5_LAPY20012_v1.00.pkg', 'PS5_ITEM00001_v1.14.pkg']) {
      if (!fs.existsSync(path.join(dir, pkg))) { console.log('  skip ' + pkg + ' (fixture not present)'); continue; }
      await test(`${pkg} -> ffpfsc is a structurally valid mountable container`, async () => {
        const out = path.join(work, 'out_' + pkg); fs.mkdirSync(out);
        const r = await convert(path.join(dir, pkg), out, 'ffpfsc');
        assert.strictEqual(r.type, 24, r.msg);
        const f = fs.readdirSync(out).find(n => n.endsWith('.ffpfsc'));
        const res = checkImage(fs.readFileSync(path.join(out, f)), 'ffpfsc');
        const structural = res.problems.filter(p => !/param\.json/.test(p));
        assert.deepStrictEqual(structural, [], structural.join('; '));
        console.log('       ' + pkg + ': ' + (res.ok ? 'param.json OK' : 'note: ' + res.problems.join('; ')));
      });
    }
  } finally {
    daemon.kill('SIGKILL');
    try { fs.unlinkSync(SOCK); } catch (_) {}
    fs.rmSync(work, { recursive: true, force: true });
  }
  const passed = results.filter(Boolean).length;
  console.log(`\n${passed}/${results.length} shadowmount-compat tests passed`);
  process.exit(passed === results.length ? 0 : 1);
})().catch(e => { console.error(e); process.exit(1); });
