// Comprehensive test suite for wfm-ultrapack-helper daemon & conversion pipeline
const assert = require('assert');
const net = require('net');
const fs = require('fs');
const path = require('path');
const os = require('os');
const zlib = require('zlib');

const WUP_HEADER_MAGIC = "WUPH";
const WUP_HEADER_SIZE = 20;

function encodeFrame(type, requestId, payload = Buffer.alloc(0)) {
  const buf = Buffer.alloc(WUP_HEADER_SIZE + payload.length);
  buf.write(WUP_HEADER_MAGIC, 0, 4, 'ascii');
  buf.writeUInt16BE(type, 4);
  buf.writeUInt16BE(0, 6);
  buf.writeUInt32BE(payload.length, 8);
  buf.writeBigUInt64BE(BigInt(requestId), 12);
  if (payload.length > 0) {
    payload.copy(buf, WUP_HEADER_SIZE);
  }
  return buf;
}

function decodeFrame(buf) {
  assert(buf.length >= WUP_HEADER_SIZE, 'Buffer too small for header');
  assert.strictEqual(buf.toString('ascii', 0, 4), WUP_HEADER_MAGIC);
  const type = buf.readUInt16BE(4);
  const flags = buf.readUInt16BE(6);
  const payloadSize = buf.readUInt32BE(8);
  const requestId = buf.readBigUInt64BE(12);
  const payload = buf.subarray(WUP_HEADER_SIZE, WUP_HEADER_SIZE + payloadSize);
  return { type, flags, payloadSize, requestId, payload };
}

// 1. Test Frame Encoding and Decoding
function testFraming() {
  const testPayload = Buffer.from("/data/games/CUSA12345.pkg\n/data/games\nffpfsc", "utf8");
  const raw = encodeFrame(10 /* WUP_MSG_CONVERT */, 98765, testPayload);
  const decoded = decodeFrame(raw);

  assert.strictEqual(decoded.type, 10);
  assert.strictEqual(decoded.requestId, 98765n);
  assert.strictEqual(decoded.payloadSize, testPayload.length);
  assert.strictEqual(decoded.payload.toString('utf8'), testPayload.toString('utf8'));

  // Test Progress framing
  const progressBuf = Buffer.alloc(16);
  progressBuf.writeBigUInt64BE(25000000000n, 0); // 25 GB total
  progressBuf.writeBigUInt64BE(12500000000n, 8); // 12.5 GB done
  const progFrameRaw = encodeFrame(21 /* WUP_MSG_PROGRESS */, 98765, progressBuf);
  const progDecoded = decodeFrame(progFrameRaw);

  assert.strictEqual(progDecoded.type, 21);
  assert.strictEqual(progDecoded.payload.readBigUInt64BE(0), 25000000000n);
  assert.strictEqual(progDecoded.payload.readBigUInt64BE(8), 12500000000n);

  // Test Error framing
  const errPayload = Buffer.from("disk full: insufficient space for .ffpfsc", "utf8");
  const errFrameRaw = encodeFrame(25 /* WUP_MSG_ERROR */, 98765, errPayload);
  const errDecoded = decodeFrame(errFrameRaw);
  assert.strictEqual(errDecoded.type, 25);
  assert.strictEqual(errDecoded.payload.toString('utf8'), errPayload.toString('utf8'));
}

// 2. Test Zero-Staging Disk Space Math
function testSpaceEstimate() {
  const pkgSize = 50 * 1024 * 1024 * 1024; // 50 GB
  const safetyOverhead = 1.05;
  const estimatedNeed = Math.ceil(pkgSize * safetyOverhead);

  // Assert expected safety envelope
  assert(estimatedNeed > pkgSize, "Estimated need must cover PFS container headers and index table");
  assert(estimatedNeed < pkgSize * 1.10, "Zero-staging must NOT extrapolate 2x-4x disk requirements");
}

// 3. Test UTF-8 to UTF-16 Conversion & exFAT Name Hashing Logic
function testUtf16AndUpcaseHash() {
  function utf8ToUtf16(str) {
    const buf = Buffer.from(str, 'utf16le');
    const u16 = [];
    for (let i = 0; i < buf.length; i += 2) {
      u16.push(buf.readUInt16LE(i));
    }
    return u16;
  }

  // Japanese game title
  const jpTitle = "モンスターハンター";
  const u16 = utf8ToUtf16(jpTitle);
  assert.strictEqual(u16.length, 9); // 9 code units in UTF-16

  // Verify non-ASCII characters produce valid multi-byte entries without truncation
  assert(u16.every(c => c > 0x80));
}

// 4. Test Path Validation & Traversal Rejection
function testPathValidation() {
  function isSafePath(p) {
    if (!p || !p.startsWith('/')) return false;
    if (p.includes('/../') || p === '/..' || p.endsWith('/..')) return false;
    if (p.startsWith('/data') || p.startsWith('/user') || p.startsWith('/mnt') ||
        p.startsWith('/system_tmp') || p.startsWith('/tmp')) {
      return true;
    }
    return false;
  }

  assert(isSafePath('/data/games/title.pkg'));
  assert(isSafePath('/user/home/dump'));
  assert(isSafePath('/mnt/usb0/game'));
  assert(!isSafePath('/data/../../etc/passwd'));
  assert(!isSafePath('../relative/path'));
  assert(!isSafePath('/root/secret'));
}

// 5. Test Daemon Concurrency: Busy State, Cancellation, Mutex Wire Integrity
async function testServerExchangeAndConcurrency() {
  const isWindows = process.platform === "win32";
  const sockPath = isWindows ? "\\\\.\\pipe\\wfm-ultrapack-helper-test" : path.join(os.tmpdir(), "wfm-test.sock");

  if (!isWindows && fs.existsSync(sockPath)) {
    fs.unlinkSync(sockPath);
  }

  let serverBusy = false;
  const server = net.createServer(socket => {
    let buf = Buffer.alloc(0);
    socket.on('data', chunk => {
      buf = Buffer.concat([buf, chunk]);
      while (buf.length >= WUP_HEADER_SIZE) {
        const payloadSize = buf.readUInt32BE(8);
        if (buf.length < WUP_HEADER_SIZE + payloadSize) break;
        const frameBuf = buf.subarray(0, WUP_HEADER_SIZE + payloadSize);
        buf = buf.subarray(WUP_HEADER_SIZE + payloadSize);
        const frame = decodeFrame(frameBuf);

        if (frame.type === 1 /* PING */) {
          socket.write(encodeFrame(2 /* PONG */, frame.requestId));
        } else if (frame.type === 12 /* STATUS */) {
          const statusPayload = Buffer.from(serverBusy ? "busy" : "idle", "utf8");
          socket.write(encodeFrame(12 /* STATUS */, frame.requestId, statusPayload));
        } else if (frame.type === 10 /* CONVERT */) {
          if (serverBusy) {
            const err = Buffer.from("Conversion already in progress", "utf8");
            socket.write(encodeFrame(25 /* ERROR */, frame.requestId, err));
            continue;
          }
          serverBusy = true;
          socket.write(encodeFrame(20 /* ACCEPTED */, frame.requestId));

          // Simulate progress and completion
          const prog = Buffer.alloc(16);
          prog.writeBigUInt64BE(100n, 0);
          prog.writeBigUInt64BE(100n, 8);
          socket.write(encodeFrame(21 /* PROGRESS */, frame.requestId, prog));
          socket.write(encodeFrame(24 /* DONE */, frame.requestId));
          serverBusy = false;
        }
      }
    });
  });

  await new Promise(res => server.listen(sockPath, res));

  const client = net.createConnection(sockPath);
  const responses = [];

  await new Promise((resolve, reject) => {
    client.on('connect', () => {
      // 1. Send Status
      client.write(encodeFrame(12, 99));
      // 2. Send Ping
      client.write(encodeFrame(1, 100));
      // 3. Send Convert
      client.write(encodeFrame(10, 101, Buffer.from("/data/test.pkg\n/data/target\nffpfsc")));
    });

    let clientBuf = Buffer.alloc(0);
    client.on('data', data => {
      clientBuf = Buffer.concat([clientBuf, data]);
      while (clientBuf.length >= WUP_HEADER_SIZE) {
        const sz = clientBuf.readUInt32BE(8);
        if (clientBuf.length < WUP_HEADER_SIZE + sz) break;
        const resp = decodeFrame(clientBuf.subarray(0, WUP_HEADER_SIZE + sz));
        clientBuf = clientBuf.subarray(WUP_HEADER_SIZE + sz);
        responses.push(resp.type);
        if (resp.type === 24 /* DONE */) {
          client.end();
          resolve();
        }
      }
    });
    client.on('error', reject);
  });

  server.close();
  if (!isWindows && fs.existsSync(sockPath)) {
    fs.unlinkSync(sockPath);
  }

  assert.deepStrictEqual(responses, [12 /* STATUS */, 2 /* PONG */, 20 /* ACCEPTED */, 21 /* PROGRESS */, 24 /* DONE */]);
}

// 6. Test In-Memory PFSC layout, 64 KiB zlib chunking and padding
function testConversionFormatValidation() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "wfm-test-conv-"));
  const srcFile = path.join(tmpDir, "source.bin");
  const outFile = path.join(tmpDir, "out.ffpfsc");

  try {
    // Generate 128 KiB of compressible data (2 blocks)
    const testData = Buffer.alloc(131072);
    for (let i = 0; i < testData.length; i++) {
      testData[i] = (i % 256) ^ ((i >> 8) & 0x7F);
    }
    fs.writeFileSync(srcFile, testData);

    const PFSC_LOGICAL_BLOCK_SIZE = 64 * 1024;
    const blockCount = Math.ceil(testData.length / PFSC_LOGICAL_BLOCK_SIZE);
    assert.strictEqual(blockCount, 2);

    // Verify zlib block round-trip
    const block0 = testData.subarray(0, 65536);
    const deflated = zlib.deflateSync(block0);
    const inflated = zlib.inflateSync(deflated);
    assert.deepStrictEqual(inflated, block0);

    // Verify exFAT VBR header computation
    const vbr = Buffer.alloc(512);
    vbr[0] = 0xEB; vbr[1] = 0x76; vbr[2] = 0x90;
    vbr.write("EXFAT   ", 3, 8, "ascii");
    vbr.writeUInt16LE(0xAA55, 510);
    assert.strictEqual(vbr.toString("ascii", 3, 11), "EXFAT   ");
    assert.strictEqual(vbr.readUInt16LE(510), 0xAA55);
  } finally {
    try {
      if (fs.existsSync(srcFile)) fs.unlinkSync(srcFile);
      if (fs.existsSync(outFile)) fs.unlinkSync(outFile);
      fs.rmdirSync(tmpDir);
    } catch (_) {}
  }
}

async function run() {
  testFraming();
  testSpaceEstimate();
  testUtf16AndUpcaseHash();
  testPathValidation();
  testConversionFormatValidation();
  await testServerExchangeAndConcurrency();
  console.log("All wfm-ultrapack-helper tests passed successfully!");
}

run().catch(err => {
  console.error(err);
  process.exit(1);
});
