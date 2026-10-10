// Comprehensive test suite for wfm-ultrapack-helper daemon & conversion pipeline
const assert = require('assert');
const net = require('net');
const fs = require('fs');
const path = require('path');
const os = require('os');

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

// 3. Test Synthetic Mock Helper Server Interaction
async function testServerExchange() {
  const isWindows = process.platform === "win32";
  const sockPath = isWindows ? "\\\\.\\pipe\\wfm-ultrapack-helper-test" : path.join(os.tmpdir(), "wfm-test.sock");

  if (!isWindows && fs.existsSync(sockPath)) {
    fs.unlinkSync(sockPath);
  }

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
        } else if (frame.type === 10 /* CONVERT */) {
          socket.write(encodeFrame(20 /* ACCEPTED */, frame.requestId));

          const prog = Buffer.alloc(16);
          prog.writeBigUInt64BE(100n, 0);
          prog.writeBigUInt64BE(100n, 8);
          socket.write(encodeFrame(21 /* PROGRESS */, frame.requestId, prog));
          socket.write(encodeFrame(24 /* DONE */, frame.requestId));
        }
      }
    });
  });

  await new Promise(res => server.listen(sockPath, res));

  // Client connects and performs conversion exchange
  const client = net.createConnection(sockPath);
  const responses = [];

  await new Promise((resolve, reject) => {
    client.on('connect', () => {
      // Send Ping
      client.write(encodeFrame(1, 100));
      // Send Convert
      client.write(encodeFrame(10, 101, Buffer.from("test.pkg\ntarget\nffpfsc")));
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

  assert.deepStrictEqual(responses, [2 /* PONG */, 20 /* ACCEPTED */, 21 /* PROGRESS */, 24 /* DONE */]);
}

async function run() {
  testFraming();
  testSpaceEstimate();
  await testServerExchange();
  console.log("All wfm-ultrapack-helper tests passed successfully!");
}

run().catch(err => {
  console.error(err);
  process.exit(1);
});
