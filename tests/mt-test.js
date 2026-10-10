// Multithreaded PFSC compressor tests: output must be byte-identical for every WUP_THREADS value,
// cancel must stop and join all workers, and 8 threads must be clearly faster than 1.
// Requires: `make linux` first. Set MT_SPEED_MB to change the speed-test size (default 600).
const assert = require('assert');
const net = require('net');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');

if (process.platform !== 'linux') {
  console.log('mt tests require Linux (AF_UNIX path socket); skipping.');
  process.exit(0);
}

const ROOT = path.resolve(__dirname, '..');
const BIN = path.join(ROOT, 'wfm-ultrapack-helper-linux');
const SOCK = '/tmp/wfm-ultrapack-helper.sock';
const HEADER = 20;
const T = { PING: 1, PONG: 2, CONVERT: 10, CANCEL: 11, PROGRESS: 21, ACCEPTED: 20, DONE: 24, ERROR: 25 };
const MB = 1024 * 1024;

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
  async until(pred, ms = 300000) {
    const end = Date.now() + ms;
    for (;;) {
      const f = this.frames.find(pred);
      if (f) return f;
      if (this.closed) return null;
      if (Date.now() > end) throw new Error('timeout waiting for frame');
      await new Promise(r => { this.waiters.push(r); setTimeout(r, 200); });
    }
  }
  terminal() { return this.until(f => f.type === T.DONE || f.type === T.ERROR); }
  close() { this.sock.destroy(); }
}

async function convert(src, dstDir, rid = 1) {
  const c = new Client();
  await c.ready();
  c.send(frame(T.CONVERT, rid, Buffer.from(`${src}\n${dstDir}\nffpfsc`)));
  const t = await c.terminal();
  c.close();
  return t;
}

async function ping() {
  const c = new Client(); await c.ready();
  c.send(frame(T.PING, 1));
  const r = await c.until(f => f.type === T.PONG);
  c.close();
  assert.ok(r, 'daemon must answer PING');
}

function socketIsLive() {
  return new Promise(res => {
    if (!fs.existsSync(SOCK)) return res(false);
    const c = net.createConnection(SOCK);
    c.once('connect', () => { c.destroy(); res(true); });
    c.once('error', () => res(false));
  });
}

async function startDaemon(threads) {
  if (!fs.existsSync(BIN)) throw new Error('build the daemon first: make linux');
  if (await socketIsLive()) throw new Error('another wfm-ultrapack-helper is already listening on ' + SOCK);
  try { fs.unlinkSync(SOCK); } catch (_) {}
  const env = Object.assign({}, process.env, { WUP_THREADS: String(threads) });
  const p = spawn(BIN, [], { stdio: 'ignore', env });
  for (let i = 0; i < 50 && !fs.existsSync(SOCK); i++) await new Promise(r => setTimeout(r, 100));
  if (!fs.existsSync(SOCK)) throw new Error('daemon socket did not appear');
  return p;
}

async function stopDaemon(p) {
  const exited = new Promise(r => p.once('exit', r));
  p.kill('SIGKILL');
  await exited;
  try { fs.unlinkSync(SOCK); } catch (_) {}
}

const sha256 = f => crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');

// Semi-compressible data: runs of repeated words mixed with random bytes (ratio ~ 0.5).
function semiData(n, seed) {
  const b = Buffer.alloc(n);
  const words = ['alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot'];
  let o = 0, i = seed;
  while (o < n) {
    const len = Math.min(n - o, 2048 + (i * 977) % 4096);
    if (i % 3 === 0) {
      crypto.randomFillSync(b, o, len);
    } else {
      const w = Buffer.from(words[i % words.length] + ' ');
      for (let k = 0; k < len; k++) b[o + k] = w[k % w.length];
    }
    o += len; i++;
  }
  return b;
}

function writeBig(file, mb, seed, mode) {
  const fd = fs.openSync(file, 'w');
  for (let i = 0; i < mb; i++) {
    const chunk = mode === 'random' ? crypto.randomBytes(MB) : mode === 'zero' ? Buffer.alloc(MB) : semiData(MB, seed + i);
    fs.writeSync(fd, chunk);
  }
  fs.closeSync(fd);
}

function threadCount(pid) {
  try { return fs.readdirSync(`/proc/${pid}/task`).length; } catch (_) { return -1; }
}

const results = [];
async function test(name, fn) {
  try { await fn(); results.push([name, true]); console.log('  ok   ' + name); }
  catch (e) { results.push([name, false]); console.log('  FAIL ' + name + '\n       ' + (e.stack || e).toString().split('\n').slice(0, 4).join('\n       ')); }
}

async function main() {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'wup-mt-'));
  let daemon = null;
  try {
    // ---------- determinism tree (~100 MB mixed, empty file, odd sizes) ----------
    const tree = path.join(work, 'tree');
    fs.mkdirSync(path.join(tree, 'sub', 'deep'), { recursive: true });
    writeBig(path.join(tree, 'compressible.bin'), 30, 1, 'zero');
    writeBig(path.join(tree, 'semi.bin'), 40, 7, 'semi');
    writeBig(path.join(tree, 'sub', 'random.bin'), 30, 0, 'random');
    fs.writeFileSync(path.join(tree, 'empty.dat'), '');
    for (const n of [1, 511, 4097, 65535, 65536, 65537, 131071, 1000003]) {
      fs.writeFileSync(path.join(tree, 'sub', 'deep', `odd_${n}.bin`), semiData(n, n));
    }
    const tiny = path.join(work, 'tiny'); fs.mkdirSync(tiny);
    fs.writeFileSync(path.join(tiny, 'a.txt'), 'hello');

    const ref = {};
    for (const [label, dir] of [['tree', tree], ['tiny', tiny]]) {
      for (const n of [1, 2, 4, 8]) {
        await test(`WUP_THREADS=${n}: ${label} output byte-identical to WUP_THREADS=1`, async () => {
          daemon = await startDaemon(n);
          try {
            const out = path.join(work, `out_${label}_${n}`); fs.mkdirSync(out);
            const r = await convert(dir, out);
            assert.strictEqual(r.type, T.DONE, r.payload);
            const files = fs.readdirSync(out);
            assert.strictEqual(files.length, 1, 'exactly one output file expected: ' + files);
            const h = sha256(path.join(out, files[0]));
            if (n === 1) ref[label] = h; else assert.strictEqual(h, ref[label]);
            await ping();
          } finally { await stopDaemon(daemon); daemon = null; }
        });
      }
    }

    // ---------- cancel with 8 threads ----------
    await test('WUP_THREADS=8: cancel mid-stream leaves no output, no leaked threads, daemon still works', async () => {
      daemon = await startDaemon(8);
      try {
        const base = threadCount(daemon.pid);
        const ct = path.join(work, 'canceltree'); fs.mkdirSync(ct);
        for (let i = 0; i < 4; i++) writeBig(path.join(ct, `r${i}.bin`), 60, i * 100, 'random');
        const cout = path.join(work, 'cancel_out'); fs.mkdirSync(cout);
        const c = new Client(); await c.ready();
        c.send(frame(T.CONVERT, 31, Buffer.from(`${ct}\n${cout}\nffpfsc`)));
        await c.until(f => f.type === T.PROGRESS && f.rid === 31n);
        c.send(frame(T.CANCEL, 31));
        const end = await c.until(f => (f.type === T.ERROR || f.type === T.DONE) && f.rid === 31n);
        assert.strictEqual(end.type, T.ERROR, 'conversion finished before the cancel landed');
        assert.match(end.payload, /cancel/i);
        assert.deepStrictEqual(fs.readdirSync(cout), [], 'cancel must leave no partial output');
        c.close();
        await ping();
        // worker threads must be joined: thread count returns to idle level (client threads may linger briefly)
        let n = -1;
        for (let i = 0; i < 30; i++) { n = threadCount(daemon.pid); if (n <= base + 1) break; await new Promise(r => setTimeout(r, 100)); }
        assert.ok(n <= base + 1, `leaked threads after cancel: ${n} (idle ${base})`);
        const r = await convert(tiny, cout, 32);
        assert.strictEqual(r.type, T.DONE, r.payload);
        fs.rmSync(ct, { recursive: true, force: true });
      } finally { await stopDaemon(daemon); daemon = null; }
    });

    // ---------- speed ----------
    await test('speed: 8 threads vs 1 thread', async () => {
      const mb = parseInt(process.env.MT_SPEED_MB || '600', 10);
      const big = path.join(work, 'bigtree'); fs.mkdirSync(big);
      const per = 100;
      for (let i = 0; i < Math.ceil(mb / per); i++) writeBig(path.join(big, `s${i}.bin`), Math.min(per, mb - i * per), i * 1000, 'semi');
      const rate = {};
      let hash1 = null;
      for (const n of [1, 8]) {
        daemon = await startDaemon(n);
        try {
          const out = path.join(work, `speed_out_${n}`); fs.mkdirSync(out);
          const t0 = process.hrtime.bigint();
          const r = await convert(big, out, 41);
          const sec = Number(process.hrtime.bigint() - t0) / 1e9;
          assert.strictEqual(r.type, T.DONE, r.payload);
          rate[n] = mb / sec;
          console.log(`       threads=${n}: ${sec.toFixed(2)} s, ${rate[n].toFixed(1)} MB/s`);
          const h = sha256(path.join(out, fs.readdirSync(out)[0]));
          if (n === 1) hash1 = h; else assert.strictEqual(h, hash1, 'speed-test outputs differ');
          fs.rmSync(out, { recursive: true, force: true });
        } finally { await stopDaemon(daemon); daemon = null; }
      }
      const ratio = rate[8] / rate[1];
      console.log(`       speedup 8 vs 1: ${ratio.toFixed(2)}x (${os.cpus().length} CPUs)`);
      if (os.cpus().length >= 8) assert.ok(ratio >= 2.5, `expected >= 2.5x speedup, got ${ratio.toFixed(2)}x`);
      else console.log('       (fewer than 8 CPUs: speedup assertion skipped)');
      fs.rmSync(big, { recursive: true, force: true });
    });
  } finally {
    if (daemon) { try { await stopDaemon(daemon); } catch (_) {} }
    fs.rmSync(work, { recursive: true, force: true });
  }
  const failed = results.filter(r => !r[1]).length;
  console.log(`\n${results.length - failed}/${results.length} passed`);
  process.exit(failed ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
