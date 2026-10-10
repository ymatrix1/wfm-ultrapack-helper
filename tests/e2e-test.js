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

if (process.platform !== 'linux') {
  console.log('e2e tests require Linux (AF_UNIX path socket); skipping.');
  process.exit(0);
}

const ROOT = path.resolve(__dirname, '..');
const BIN = path.join(ROOT, 'wfm-ultrapack-helper-linux');
const SOCK = '/tmp/wfm-ultrapack-helper.sock';
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
  async until(pred, ms = 20000) {
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

function startDaemon() {
  if (!fs.existsSync(BIN)) throw new Error('build the daemon first: make linux');
  try { fs.unlinkSync(SOCK); } catch (_) {}
  const p = spawn(BIN, [], { stdio: 'ignore' });
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

async function main() {
  const work = fs.mkdtempSync(path.join('/tmp', 'wup-e2e-'));
  const out = path.join(work, 'out');
  fs.mkdirSync(out);
  const daemon = startDaemon();
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
      if (haveFsck) {
        const r = sh('fsck.exfat', [img]);
        assert.strictEqual(r.status, 0, r.stdout + r.stderr);
        assert.match(r.stdout + r.stderr, /clean/);
      } else console.log('       (fsck.exfat not installed; structural checks only)');
    });
    await test('image -> ffpfsc: header valid and every block inflates to the source', async () => {
      const f = await convert(smallImg, out, 'ffpfsc', 12);
      assert.strictEqual(f.type, T.DONE, f.payload);
      const d = fs.readFileSync(path.join(out, 'small.ffpfsc'));
      assert.strictEqual(d.toString('ascii', 0, 4), 'PFSC');
      const bs = Number(d.readBigUInt64LE(0x10)), tbl = Number(d.readBigUInt64LE(0x18));
      const logical = Number(d.readBigUInt64LE(0x28));
      assert.strictEqual(bs, 65536);
      const blocks = Math.ceil(imgData.length / bs);
      assert.strictEqual(logical, blocks * bs);
      const rebuilt = [];
      for (let i = 0; i < blocks; i++) {
        const a = Number(d.readBigUInt64LE(tbl + i * 8)), e = Number(d.readBigUInt64LE(tbl + (i + 1) * 8));
        const chunk = d.subarray(a, e);
        rebuilt.push(chunk.length === bs ? chunk : zlib.inflateSync(chunk));
      }
      const all = Buffer.concat(rebuilt).subarray(0, imgData.length);
      assert.ok(all.equals(imgData), 'round-tripped data differs from source');
    });
    await test('folder -> ffpfsc: inner exfat is fsck-clean after decompress', async () => {
      const f = await convert(tree, out, 'ffpfsc', 13);
      assert.strictEqual(f.type, T.DONE, f.payload);
      assert.ok(!fs.existsSync(path.join(out, 'tree.tmp.exfat')), 'temp exfat must be removed');
      const d = fs.readFileSync(path.join(out, 'tree.ffpfsc'));
      const bs = Number(d.readBigUInt64LE(0x10)), tbl = Number(d.readBigUInt64LE(0x18));
      const logical = Number(d.readBigUInt64LE(0x28));
      const parts = [];
      for (let i = 0; i < logical / bs; i++) {
        const a = Number(d.readBigUInt64LE(tbl + i * 8)), e = Number(d.readBigUInt64LE(tbl + (i + 1) * 8));
        const chunk = d.subarray(a, e);
        parts.push(chunk.length === bs ? chunk : zlib.inflateSync(chunk));
      }
      const img = path.join(work, 'inner.exfat');
      fs.writeFileSync(img, Buffer.concat(parts));
      assert.strictEqual(fs.readFileSync(img).toString('ascii', 3, 11), 'EXFAT   ');
      if (haveFsck) {
        const r = sh('fsck.exfat', [img]);
        assert.strictEqual(r.status, 0, r.stdout + r.stderr);
      }
    });
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
