// End-to-end tests: spawn the real Linux daemon and drive it over its UNIX socket.
// Covers every user-visible error path plus exFAT / PFSC output validation.
// Requires: `make linux` first. exFAT validation additionally needs `fsck.exfat` (exfatprogs).
const assert = require('assert');
const net = require('net');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const { spawn, spawnSync } = require('child_process');
const { parseFfpfsc, unpfsc } = require('./ffpfsc-util');

if (process.platform !== 'linux') {
  console.log('e2e tests require Linux (AF_UNIX path socket); skipping.');
  process.exit(0);
}

const ROOT = path.resolve(__dirname, '..');
const BIN = path.join(ROOT, 'wfm-ultrapack-helper-linux');
const SOCK = process.env.WUP_SOCKET || '/tmp/wfm-ultrapack-helper.sock';
// ASAN/UBSAN/TSAN builds run 5-50x slower: scale frame-wait timeouts.
const SANITIZED = /sanitize/.test(process.env.EXTRA_CFLAGS || '');
process.env.WUP_FIXED_TIME = '1700000000';
const HEADER = 20;
const T = { PING: 1, PONG: 2, CONVERT: 10, CANCEL: 11, STATUS: 12, ACCEPTED: 20, PROGRESS: 21, DONE: 24, ERROR: 25 };

const frame = (type, rid, payload = Buffer.alloc(0)) => {
  const b = Buffer.alloc(HEADER + payload.length);
  b.write('WUPH', 0, 'ascii');
  b.writeUInt16BE(type, 4);
  b.writeUInt32BE(payload.length, 8);
  b.writeBigUInt64BE(BigInt(rid), 12);
  payload.copy(b, HEADER);
  return b;
};

class Client {
  constructor() {
    this.buf = Buffer.alloc(0);
    this.frames = [];
    this.closed = false;
    this.waiters = [];
    this.sock = net.createConnection(SOCK);
    this.sock.on('data', d => {
      this.buf = Buffer.concat([this.buf, d]);
      while (this.buf.length >= HEADER) {
        const n = this.buf.readUInt32BE(8);
        if (this.buf.length < HEADER + n) break;
        this.frames.push({ type: this.buf.readUInt16BE(4), rid: this.buf.readBigUInt64BE(12), payload: this.buf.subarray(HEADER, HEADER + n).toString() });
        this.buf = this.buf.subarray(HEADER + n);
      }
      this.wake();
    });
    const done = () => { this.closed = true; this.wake(); };
    this.sock.on('close', done);
    this.sock.on('error', done);
  }
  wake() { this.waiters.splice(0).forEach(w => w()); }
  ready() { return new Promise((res, rej) => { this.sock.once('connect', res); this.sock.once('error', rej); }); }
  send(buf) { this.sock.write(buf); }
  async until(pred, ms = SANITIZED ? 600000 : 20000) {
    const end = Date.now() + ms;
    for (;;) {
      const f = this.frames.find(pred);
      if (f) return f;
      if (this.closed) return null;
      if (Date.now() > end) throw new Error('timeout waiting for frame; got ' + JSON.stringify(this.frames.map(f => f.type)));
      await new Promise(r => { this.waiters.push(r); setTimeout(r, 200); });
    }
  }
  // Wait for the terminal frame of a request (DONE or ERROR).
  terminal(ms) { return this.until(f => f.type === T.DONE || f.type === T.ERROR, ms); }
  async waitClosed(ms = 5000) {
    const end = Date.now() + ms;
    while (!this.closed) {
      if (Date.now() > end) throw new Error('connection was not closed by daemon');
      await new Promise(r => { this.waiters.push(r); setTimeout(r, 100); });
    }
  }
  close() { this.sock.destroy(); }
}

// .ffpfsc = PFS image + one inner file (PFSC container): parse/inflate helpers live in ffpfsc-util.js.

async function convert(src, dst, fmt, rid = 1) {
  const c = new Client();
  await c.ready();
  c.send(frame(T.CONVERT, rid, Buffer.from(`${src}\n${dst}\n${fmt}`)));
  const t = await c.terminal();
  c.close();
  return t;
}

const sh = (cmd, args) => spawnSync(cmd, args, { encoding: 'utf8' });
const haveFsck = sh('which', ['fsck.exfat']).status === 0;

// True when something is accepting connections on SOCK (a live daemon owns it).
function socketIsLive() {
  return new Promise(res => {
    if (!fs.existsSync(SOCK)) return res(false);
    const c = net.createConnection(SOCK);
    c.once('connect', () => { c.destroy(); res(true); });
    c.once('error', () => res(false));
  });
}

async function startDaemon(env) {
  if (!fs.existsSync(BIN)) throw new Error('build the daemon first: make linux');
  if (await socketIsLive()) {
    throw new Error('another wfm-ultrapack-helper is already listening on ' + SOCK + '; stop it before running the e2e tests');
  }
  try { fs.unlinkSync(SOCK); } catch (_) {} // stale socket file only
  const p = spawn(BIN, [], { stdio: 'ignore', env: env || process.env });
  return p;
}

async function waitSocket() {
  for (let i = 0; i < 50; i++) {
    if (fs.existsSync(SOCK)) return;
    await new Promise(r => setTimeout(r, 100));
  }
  throw new Error('daemon socket did not appear');
}

const results = [];
async function test(name, fn) {
  try { await fn(); results.push([name, true]); console.log('  ok   ' + name); }
  catch (e) { results.push([name, false]); console.log('  FAIL ' + name + '\n       ' + (e.stack || e).toString().split('\n').slice(0, 4).join('\n       ')); }
}


// Minimal exFAT reader: walks the directory tree and returns {path -> Buffer-reader} so tests can
// extract every file from a produced image and hash it independently of the writer.
function exfatFiles(img) {
  const bps = 1 << img[108], cs = bps << img[109];
  const fatOff = img.readUInt32LE(80) * bps, heapOff = img.readUInt32LE(88) * bps;
  const root = img.readUInt32LE(96), clusters = img.readUInt32LE(92);
  const clOff = c => heapOff + (c - 2) * cs;
  const chain = (first, len, noFat) => {
    const parts = []; let c = first, left = len;
    for (let n = 0; left > 0 && n <= clusters; n++) {
      const take = Math.min(cs, left);
      parts.push(img.subarray(clOff(c), clOff(c) + take)); left -= take;
      if (noFat) c++; else { c = img.readUInt32LE(fatOff + c * 4); if (c === 0xffffffff) break; }
    }
    return Buffer.concat(parts);
  };
  const files = new Map();
  const walk = (first, size, prefix, noFat) => {
    const d = chain(first, size, noFat);
    for (let o = 0; o + 32 <= d.length; o += 32) {
      if (d[o] === 0) break;
      if (d[o] !== 0x85) continue;
      const sec = d[o + 1], attr = d.readUInt16LE(o + 4);
      const st = d.subarray(o + 32, o + 64);
      const nameLen = st[3], dataLen = Number(st.readBigUInt64LE(24)), fc = st.readUInt32LE(20), nofat = (st[1] & 2) !== 0;
      let name = '';
      for (let i = 2; i <= sec; i++) name += d.subarray(o + i * 32 + 2, o + i * 32 + 32).toString('utf16le');
      name = name.slice(0, nameLen);
      const full = prefix ? prefix + '/' + name : name;
      if (attr & 0x10) walk(fc, dataLen, full, nofat);
      else files.set(full, { size: dataLen, read: () => (dataLen ? chain(fc, dataLen, nofat) : Buffer.alloc(0)) });
      o += sec * 32;
    }
  };
  // root directory length: follow its FAT chain
  let len = 0; for (let c = root, n = 0; n <= clusters; n++) { len += cs; c = img.readUInt32LE(fatOff + c * 4); if (c === 0xffffffff) break; }
  walk(root, len, '', false);
  return files;
}

async function main() {
  const work = fs.mkdtempSync(path.join('/tmp', 'wup-e2e-'));
  const out = path.join(work, 'out');
  fs.mkdirSync(out);
  const daemon = await startDaemon();
  try {
    await waitSocket();

    // ---------- fixtures ----------
    const tree = path.join(work, 'tree');
    fs.mkdirSync(path.join(tree, 'sce_sys'), { recursive: true });
    fs.mkdirSync(path.join(tree, 'media/sub/deeper'), { recursive: true });
    fs.mkdirSync(path.join(tree, 'empty_dir'));
    fs.writeFileSync(path.join(tree, 'eboot.bin'), require('crypto').randomBytes(3_000_000));
    fs.writeFileSync(path.join(tree, 'media/big.txt'), Buffer.alloc(70000, 'A'));
    fs.writeFileSync(path.join(tree, 'sce_sys/param.json'), '{"a":1}');
    fs.writeFileSync(path.join(tree, 'zero.bin'), '');
    fs.writeFileSync(path.join(tree, 'media/sub/café_日本語.txt'), 'uni');
    fs.writeFileSync(path.join(tree, 'media/sub/deeper/two_clusters.bin'), Buffer.alloc(131072, 7));
    const emptyFile = path.join(work, 'empty.img');
    fs.writeFileSync(emptyFile, '');
    const smallImg = path.join(work, 'small.img');
    const imgData = Buffer.alloc(200000);
    for (let i = 0; i < imgData.length; i++) imgData[i] = (i * 31 + (i >> 9)) & 0xff;
    fs.writeFileSync(smallImg, imgData);

    // ---------- protocol-level errors ----------
    await test('ping/pong', async () => {
      const c = new Client(); await c.ready();
      c.send(frame(T.PING, 5));
      const f = await c.until(f => f.type === T.PONG);
      assert.strictEqual(f.rid, 5n); c.close();
    });
    await test('bad magic closes the connection', async () => {
      const c = new Client(); await c.ready();
      const bad = frame(T.PING, 1); bad.write('XXXX', 0, 'ascii');
      c.send(bad); await c.waitClosed();
    });
    await test('oversized payload closes the connection', async () => {
      const c = new Client(); await c.ready();
      const h = frame(T.CONVERT, 1); h.writeUInt32BE(0x7fffffff, 8);
      c.send(h); await c.waitClosed();
    });
    await test('unknown message type -> ERROR', async () => {
      const c = new Client(); await c.ready();
      c.send(frame(99, 3));
      const f = await c.terminal();
      assert.strictEqual(f.type, T.ERROR); assert.match(f.payload, /Unknown message type/); c.close();
    });
    await test('status reports idle', async () => {
      const c = new Client(); await c.ready();
      c.send(frame(T.STATUS, 4));
      const f = await c.until(f => f.rid === 4n);
      assert.match(f.payload, /idle/); c.close();
    });
    await test('daemon survives abrupt client disconnect mid-convert (SIGPIPE)', async () => {
      const c = new Client(); await c.ready();
      c.send(frame(T.CONVERT, 1, Buffer.from(`${smallImg}\n${out}\nffpfsc`)));
      c.sock.destroy();
      await new Promise(r => setTimeout(r, 500));
      const p = new Client(); await p.ready();
      p.send(frame(T.PING, 9));
      await p.until(f => f.type === T.PONG); p.close();
    });

    // ---------- convert request validation ----------
    await test('missing destination -> ERROR', async () => {
      const c = new Client(); await c.ready();
      c.send(frame(T.CONVERT, 1, Buffer.from(smallImg)));
      const f = await c.terminal();
      assert.strictEqual(f.type, T.ERROR); assert.match(f.payload, /missing destination/); c.close();
    });
    await test('disallowed absolute path -> ERROR', async () => {
      const f = await convert('/etc/passwd', out, 'ffpfsc');
      assert.strictEqual(f.type, T.ERROR); assert.match(f.payload, /Invalid or disallowed path/);
    });
    await test('path traversal (..) -> ERROR', async () => {
      const f = await convert(`${work}/../../etc/passwd`, out, 'ffpfsc');
      assert.strictEqual(f.type, T.ERROR); assert.match(f.payload, /Invalid or disallowed path/);
    });
    await test('disallowed destination -> ERROR', async () => {
      const f = await convert(smallImg, '/etc', 'ffpfsc');
      assert.strictEqual(f.type, T.ERROR); assert.match(f.payload, /Invalid or disallowed path/);
    });
    await test('relative path -> ERROR', async () => {
      const f = await convert('relative/path.img', out, 'ffpfsc');
      assert.strictEqual(f.type, T.ERROR);
    });

    // ---------- conversion errors ----------
    await test('nonexistent source -> ERROR', async () => {
      const f = await convert(path.join(work, 'nope.img'), out, 'ffpfsc');
      assert.strictEqual(f.type, T.ERROR); assert.match(f.payload, /does not exist/);
    });
    await test('unsupported format -> ERROR', async () => {
      const f = await convert(smallImg, out, 'zip');
      assert.strictEqual(f.type, T.ERROR); assert.match(f.payload, /Unsupported target format/);
    });
    await test('empty source image -> ERROR', async () => {
      const f = await convert(emptyFile, out, 'ffpfsc');
      assert.strictEqual(f.type, T.ERROR); assert.match(f.payload, /empty/);
    });
    await test('corrupt/truncated PKG -> clean ERROR, no output left behind', async () => {
      const pkg = path.join(work, 'fake.pkg');
      fs.writeFileSync(pkg, Buffer.concat([Buffer.from([0x7f, 0x43, 0x4e, 0x54]), Buffer.alloc(4096)]));
      const f = await convert(pkg, out, 'ffpfsc');
      assert.strictEqual(f.type, T.ERROR);
      assert.ok(!fs.existsSync(path.join(out, 'fake.ffpfsc')));
      assert.ok(!fs.existsSync(path.join(out, 'fake.exfat')));
    });
    await test('exfat from a regular file -> ERROR', async () => {
      const f = await convert(smallImg, out, 'exfat');
      assert.strictEqual(f.type, T.ERROR); assert.match(f.payload, /already an image file/);
    });
    await test('nonexistent destination dir -> ERROR (ffpfsc)', async () => {
      const f = await convert(smallImg, path.join(work, 'no_such_dir'), 'ffpfsc');
      assert.strictEqual(f.type, T.ERROR); assert.match(f.payload, /Cannot create target/);
    });
    await test('nonexistent destination dir -> ERROR (exfat)', async () => {
      const f = await convert(tree, path.join(work, 'no_such_dir'), 'exfat');
      assert.strictEqual(f.type, T.ERROR); assert.match(f.payload, /Failed to create output file/);
    });
    await test('OS metadata is excluded from exfat images (matches ultrapack IGNORED_NAMES)', async () => {
      const m = path.join(work, 'meta'); fs.mkdirSync(path.join(m, '$RECYCLE.BIN'), { recursive: true });
      fs.writeFileSync(path.join(m, 'keep.txt'), 'k');
      for (const n of ['Desktop.INI', 'Thumbs.db', '.DS_Store', '.Trashes', '._keep.txt', 'ehthumbs.db', '.localized']) fs.writeFileSync(path.join(m, n), 'x');
      fs.writeFileSync(path.join(m, '$RECYCLE.BIN', 'junk'), 'x');
      const f = await convert(m, out, 'exfat');
      assert.strictEqual(f.type, T.DONE, f.payload);
      const img = fs.readFileSync(path.join(out, 'meta.exfat'));
      const has = n => img.includes(Buffer.from(n, 'utf16le'));
      assert.ok(has('keep.txt'), 'control file must be present');
      for (const n of ['Desktop.INI', 'Thumbs.db', '.DS_Store', '.Trashes', '._keep.txt', 'ehthumbs.db', '.localized', '$RECYCLE.BIN', 'junk']) assert.ok(!has(n), n + ' should be excluded');
    });
    await test('case-insensitive duplicate names -> ERROR, no output left behind', async () => {
      const dup = path.join(work, 'dup'); fs.mkdirSync(dup);
      fs.writeFileSync(path.join(dup, 'Foo.txt'), 'a'); fs.writeFileSync(path.join(dup, 'foo.txt'), 'b');
      const f = await convert(dup, out, 'exfat');
      assert.strictEqual(f.type, T.ERROR); assert.match(f.payload, /duplicate|Failed scanning/i);
      assert.ok(!fs.existsSync(path.join(out, 'dup.exfat')));
    });
    await test('symlink loop terminates (no hang / crash)', async () => {
      const loop = path.join(work, 'loop'); fs.mkdirSync(loop);
      fs.writeFileSync(path.join(loop, 'a.txt'), 'x');
      fs.symlinkSync(loop, path.join(loop, 'self'));
      const f = await convert(loop, out, 'exfat');
      assert.ok(f.type === T.DONE || f.type === T.ERROR);
      const p = new Client(); await p.ready(); p.send(frame(T.PING, 1)); await p.until(f => f.type === T.PONG); p.close();
    });

    // ---------- busy + cancel ----------
    await test('second CONVERT while busy -> ERROR; CANCEL aborts and removes output', async () => {
      const big = path.join(work, 'big.img');
      const fd = fs.openSync(big, 'w'); fs.ftruncateSync(fd, 1024 * 1024 * 1024); fs.closeSync(fd);
      const c = new Client(); await c.ready();
      c.send(frame(T.CONVERT, 1, Buffer.from(`${big}\n${out}\nffpfsc`)));
      await c.until(f => f.type === T.ACCEPTED && f.rid === 1n);
      c.send(frame(T.CONVERT, 2, Buffer.from(`${smallImg}\n${out}\nffpfsc`)));
      const busy = await c.until(f => f.type === T.ERROR && f.rid === 2n);
      assert.match(busy.payload, /already in progress/);
      c.send(frame(T.CANCEL, 1));
      const end = await c.until(f => (f.type === T.ERROR || f.type === T.DONE) && f.rid === 1n);
      if (end.type === T.ERROR) {
        assert.match(end.payload, /cancel/i);
        assert.ok(!fs.existsSync(path.join(out, 'big.ffpfsc')), 'partial output must be removed');
      } // if the job finished before CANCEL landed, DONE is acceptable
      c.close(); fs.unlinkSync(big);
    });

    await test('CANCEL mid-stream folder -> ffpfsc aborts and leaves no output or temp files', async () => {
      const ct = path.join(work, 'canceltree'); fs.mkdirSync(ct);
      for (let i = 0; i < 6; i++) fs.writeFileSync(path.join(ct, `r${i}.bin`), require('crypto').randomBytes(40 * 1024 * 1024));
      const cout = path.join(work, 'cancel_out'); fs.mkdirSync(cout);
      const c = new Client(); await c.ready();
      c.send(frame(T.CONVERT, 21, Buffer.from(`${ct}
${cout}
ffpfsc`)));
      await c.until(f => f.type === T.PROGRESS && f.rid === 21n);
      c.send(frame(T.CANCEL, 21));
      const end = await c.until(f => (f.type === T.ERROR || f.type === T.DONE) && f.rid === 21n);
      assert.strictEqual(end.type, T.ERROR, 'conversion finished before the cancel landed');
      assert.match(end.payload, /cancel/i);
      assert.deepStrictEqual(fs.readdirSync(cout), [], 'cancel must leave no partial output or temp files');
      c.close();
      fs.rmSync(ct, { recursive: true, force: true });
    });

    // ---------- success-path validation ----------
    await test('folder -> exfat produces an image that fsck.exfat accepts', async function () {
      const f = await convert(tree, out, 'exfat', 11);
      assert.strictEqual(f.type, T.DONE, f.payload);
      const img = path.join(out, 'tree.exfat');
      const b = fs.readFileSync(img).subarray(0, 512);
      assert.strictEqual(b.toString('ascii', 3, 11), 'EXFAT   ');
      assert.strictEqual(b.readUInt16LE(510), 0xaa55);
      // FAT must chain the root directory (regression: empty FAT => "bad cluster 0x0")
      const fatOff = b.readUInt32LE(80) * 512, root = b.readUInt32LE(96);
      const fat = fs.readFileSync(img).subarray(fatOff, fatOff + 4 * (root + 2));
      assert.notStrictEqual(fat.readUInt32LE(root * 4), 0, 'root directory has no FAT chain');
      // Byte-parity rules with the reference mkpfs writer (ps5-ultrapack exfat_writer.py)
      const whole = fs.readFileSync(img);
      const heap = b.readUInt32LE(88) * 512, spcBytes = 512 << b[109], clusters = b.readUInt32LE(92);
      const rootOff = heap + (root - 2) * spcBytes;
      assert.strictEqual(whole[rootOff], 0x83, 'first root entry is the volume label');
      assert.ok(whole.subarray(rootOff + 1, rootOff + 32).every(x => x === 0), 'volume label must be empty');
      assert.strictEqual(whole[rootOff + 32], 0x81, 'second root entry is the allocation bitmap');
      assert.strictEqual(Number(whole.readBigUInt64LE(rootOff + 32 + 24)), Math.ceil(clusters / 8), 'bitmap length = ceil(clusters/8)');
      assert.strictEqual(whole.readUInt32LE(100), 0x4d6b5046, 'fixed volume serial');
      if (haveFsck) {
        const r = sh('fsck.exfat', [img]);
        assert.strictEqual(r.status, 0, r.stdout + r.stderr);
        assert.match(r.stdout + r.stderr, /clean/);
      } else console.log('       (fsck.exfat not installed; structural checks only)');
    });
    await test('image -> ffpfsc: PFS image wrapping one PFSC file; every block inflates to the source', async () => {
      const f = await convert(smallImg, out, 'ffpfsc', 12);
      assert.strictEqual(f.type, T.DONE, f.payload);
      const d = fs.readFileSync(path.join(out, 'small.ffpfsc'));
      assert.notStrictEqual(d.toString('ascii', 0, 4), 'PFSC', 'PFSC must not sit at file offset 0');
      const p = parseFfpfsc(d);
      assert.strictEqual(p.pfsHeader.version, 2);
      assert.strictEqual(p.pfsHeader.blockSize, 65536);
      assert.strictEqual(p.pfsHeader.mode, 0x8, 'unsigned, unencrypted, 32-bit inodes, case-insensitive');
      assert.strictEqual(p.pfsHeader.readonly, 1);
      assert.strictEqual(p.pfsHeader.inodeCount, 4);
      assert.strictEqual(p.innerName, 'small.img');
      assert.strictEqual(p.innerOffset, 6 * 65536, 'PFSC payload starts at block 6');
      assert.strictEqual(p.rawSize, imgData.length);
      assert.strictEqual(p.pfsc.lbs, 65536);
      assert.strictEqual(p.pfsc.dataLength, Math.ceil(imgData.length / 65536) * 65536);
      assert.strictEqual(p.blocks.length, Math.ceil(imgData.length / 65536));
      assert.strictEqual(p.blocks[0].start, 0x10000, 'PFSC offsets are relative to the PFSC start');
      assert.strictEqual(p.innerSize, p.blocks[p.blocks.length - 1].end);
      assert.strictEqual(p.pfsHeader.ndblock, 6 + Math.ceil(p.innerSize / 65536));
      assert.strictEqual(p.inodes[3].time, 1700000000, 'WUP_FIXED_TIME pins the PFS timestamps');
      const all = p.inflate().subarray(0, imgData.length);
      assert.ok(all.equals(imgData), 'round-tripped data differs from source');
    });
    await test('image -> ffpfsc: inner file is named like ultrapack (title id / sanitized stem + extension)', async () => {
      const o2 = path.join(work, 'names');
      fs.mkdirSync(o2, { recursive: true });
      const cases = [['PPSA28183-app_v1.EXFAT', 'PPSA28183.exfat'], ['My Game.exfat', 'My_Game.exfat'],
                     ['a_very_long_image_name_here.img', 'a_very_long_ima.img']];
      for (const [src, want] of cases) {
        const sp = path.join(work, src);
        fs.writeFileSync(sp, imgData.subarray(0, 70000));
        const f = await convert(sp, o2, 'ffpfsc', 17);
        assert.strictEqual(f.type, T.DONE, f.payload);
        const outName = src.replace(/\.(pkg|exfat|img|iso)$/i, '') + '.ffpfsc';
        assert.strictEqual(parseFfpfsc(fs.readFileSync(path.join(o2, outName))).innerName, want, src);
      }
    });
    await test('folder -> ffpfsc: inner exfat is fsck-clean after decompress', async () => {
      const f = await convert(tree, out, 'ffpfsc', 13);
      assert.strictEqual(f.type, T.DONE, f.payload);
      assert.ok(!fs.existsSync(path.join(out, 'tree.tmp.exfat')), 'temp exfat must be removed');
      const img = path.join(work, 'inner.exfat');
      const pf = parseFfpfsc(fs.readFileSync(path.join(out, 'tree.ffpfsc')));
      assert.strictEqual(pf.innerName, 'tree.exfat');
      fs.writeFileSync(img, pf.inflate());
      assert.strictEqual(fs.readFileSync(img).toString('ascii', 3, 11), 'EXFAT   ');
      if (haveFsck) {
        const r = sh('fsck.exfat', [img]);
        assert.strictEqual(r.status, 0, r.stdout + r.stderr);
      }

      // Zero-staging: convert a ~200 MB tree while polling the output dir; no *.tmp.exfat may ever appear.
      const big = path.join(work, 'bigtree');
      fs.mkdirSync(path.join(big, 'sub'), { recursive: true });
      const crypto = require('crypto');
      for (let i = 0; i < 4; i++) {
        const fd = fs.openSync(path.join(big, i % 2 ? 'sub' : '.', `rand${i}.bin`), 'w');
        for (let k = 0; k < 25; k++) fs.writeSync(fd, crypto.randomBytes(2 * 1024 * 1024)); // 50 MB random
        fs.closeSync(fd);
      }
      fs.writeFileSync(path.join(big, 'zeros.bin'), Buffer.alloc(1024 * 1024 * 3 + 17));
      const bigOut = path.join(work, 'bigout');
      fs.mkdirSync(bigOut);
      const seen = new Set();
      let polls = 0;
      const timer = setInterval(() => {
        polls++;
        for (const n of fs.readdirSync(bigOut)) seen.add(n);
      }, 2);
      let bf;
      try { bf = await convert(big, bigOut, 'ffpfsc', 14); } finally { clearInterval(timer); }
      assert.strictEqual(bf.type, T.DONE, bf.payload);
      assert.ok(polls > 5, 'poller did not run (' + polls + ')');
      assert.ok(seen.has('bigtree.ffpfsc'), 'output was never observed: ' + [...seen]);
      assert.deepStrictEqual([...seen].filter(n => n.endsWith('.tmp.exfat') || n.includes('.tmp')), [], 'staging file appeared');
      assert.deepStrictEqual(fs.readdirSync(bigOut), ['bigtree.ffpfsc']);
      fs.rmSync(bigOut, { recursive: true, force: true });
      fs.rmSync(big, { recursive: true, force: true });
    });
    await test('folder -> ffpfsc decompresses byte-identical to folder -> exfat', async () => {
      const cmp = path.join(work, 'cmpout');
      fs.mkdirSync(cmp, { recursive: true });
      const fe = await convert(tree, cmp, 'exfat', 15);
      assert.strictEqual(fe.type, T.DONE, fe.payload);
      const ff = await convert(tree, cmp, 'ffpfsc', 16);
      assert.strictEqual(ff.type, T.DONE, ff.payload);
      const exfat = fs.readFileSync(path.join(cmp, 'tree.exfat'));
      const inner = unpfsc(fs.readFileSync(path.join(cmp, 'tree.ffpfsc')));
      assert.strictEqual(inner.length, Math.ceil(exfat.length / 65536) * 65536);
      assert.ok(inner.subarray(0, exfat.length).equals(exfat), 'inner image differs from exfat output');
      assert.ok(inner.subarray(exfat.length).every(x => x === 0), 'padding tail must be zero');
    });

    // ---------- real PS5 packages (skipped when the fixtures are absent) ----------
    const fixDir = process.env.PKG_FIXTURE_DIR || '/mnt/c/Users/yuri_/Downloads';
    const bs = 65536;
    const inflateFfpfsc = file => unpfsc(fs.readFileSync(file));
    for (const name of ['PS5_LAPY20012_v1.00.pkg', 'PS5_ITEM00001_v1.14.pkg']) {
      const pkgPath = path.join(fixDir, name);
      if (!fs.existsSync(pkgPath)) { console.log('  skip ' + name + ' (fixture not present)'); continue; }
      const base = name.replace(/\.pkg$/, '');
      await test(`${name}: pkg -> exfat is fsck-clean and holds the package files`, async () => {
        const f = await convert(pkgPath, out, 'exfat', 31);
        assert.strictEqual(f.type, T.DONE, f.payload);
        const img = path.join(out, base + '.exfat');
        if (haveFsck) { const r = sh('fsck.exfat', [img]); assert.strictEqual(r.status, 0, r.stdout + r.stderr); }
        const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'tests/fixtures', base + '.manifest.json'), 'utf8'));
        const entries = (Array.isArray(manifest) ? manifest : (manifest.files || manifest.entries)).filter(x => x.sha256 !== undefined);
        const files = exfatFiles(fs.readFileSync(img));
        let checked = 0;
        for (const e of entries) {
          const f = files.get(e.path);
          assert.ok(f, e.path + ' missing from the exFAT image');
          assert.strictEqual(f.size, e.size, e.path + ' size');
          assert.strictEqual(require('crypto').createHash('sha256').update(f.read()).digest('hex'), e.sha256, e.path + ' sha256');
          checked++;
        }
        assert.ok(checked > 0);
      });
      await test(`${name}: pkg -> ffpfsc streams with no temp files and inflates to the exfat image`, async () => {
        const f = await convert(pkgPath, out, 'ffpfsc', 32);
        assert.strictEqual(f.type, T.DONE, f.payload);
        assert.ok(!fs.readdirSync(out).some(n => /\.tmp/.test(n)), 'no temp files');
        const pk = parseFfpfsc(fs.readFileSync(path.join(out, base + '.ffpfsc')));
        assert.match(pk.innerName, /^[A-Z]{4}\d{5}\.exfat$/, 'inner file is <titleId>.exfat from param.json: ' + pk.innerName);
        const inner = inflateFfpfsc(path.join(out, base + '.ffpfsc'));
        const ex = fs.readFileSync(path.join(out, base + '.exfat'));
        assert.ok(inner.subarray(0, ex.length).equals(ex), 'ffpfsc payload differs from the exfat image');
        assert.ok(inner.subarray(ex.length).every(x => x === 0), 'padding must be zero');
      });
    }
    {
      const pkgPath = path.join(fixDir, 'PS5_LAPY20012_v1.00.pkg');
      if (fs.existsSync(pkgPath)) {
        await test('passcode field is accepted, never echoed (fake PKGs recover the key via the RSA chain)', async () => {
          const c = new Client(); await c.ready();
          const secret = 'WRONGPASSCODE0123456789abcdefghi';
          c.send(frame(T.CONVERT, 33, Buffer.from(`${pkgPath}\n${out}\nexfat\n${secret}`)));
          const f = await c.terminal();
          assert.ok(!f.payload.includes(secret), 'passcode must not be echoed');
          assert.strictEqual(f.type, T.DONE, f.payload);
          c.close();
        });
        await test('PKG whose key digest does not match -> clear ERROR, no output left behind', async () => {
          const bad = path.join(work, 'badkey.pkg');
          const fd = fs.openSync(pkgPath, 'r'); const head = Buffer.alloc(0x3000); fs.readSync(fd, head, 0, head.length, 0); fs.closeSync(fd);
          // ENTRY_KEYS (entry 0x10) data lives at 0x2000: flip the key digest[1] and every RSA key blob
          for (let i = 0x2020; i < 0x2800; i++) head[i] ^= 0xff;
          fs.copyFileSync(pkgPath, bad);
          const w = fs.openSync(bad, 'r+'); fs.writeSync(w, head, 0, head.length, 0); fs.closeSync(w);
          const f = await convert(bad, out, 'exfat', 34);
          fs.unlinkSync(bad);
          assert.strictEqual(f.type, T.ERROR);
          assert.match(f.payload, /EKPFS|passcode|key/i);
          assert.ok(!fs.existsSync(path.join(out, 'badkey.exfat')));
        });
      }
    }
  } finally {
    daemon.kill('SIGKILL');
    try { fs.unlinkSync(SOCK); } catch (_) {}
    fs.rmSync(work, { recursive: true, force: true });
  }
  const failed = results.filter(r => !r[1]);
  console.log(`\n${results.length - failed.length}/${results.length} e2e tests passed`);
  process.exit(failed.length ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
