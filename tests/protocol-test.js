// Test protocol framing and message structures for wfm-ultrapack-helper
const assert = require('assert');

const WUP_HEADER_MAGIC = "WUPH";
const WUP_HEADER_SIZE = 20;

function encodeFrame(type, requestId, payload = Buffer.alloc(0)) {
  const buf = Buffer.alloc(WUP_HEADER_SIZE + payload.length);
  buf.write(WUP_HEADER_MAGIC, 0, 4, 'ascii');
  buf.writeUInt16BE(type, 4);
  buf.writeUInt16BE(0, 6); // flags
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

function testFraming() {
  const payload = Buffer.from("/data/games/title.pkg\n/data/games\nffpfsc", "utf8");
  const raw = encodeFrame(10 /* WUP_MSG_CONVERT */, 12345, payload);
  const decoded = decodeFrame(raw);

  assert.strictEqual(decoded.type, 10);
  assert.strictEqual(decoded.requestId, 12345n);
  assert.strictEqual(decoded.payloadSize, payload.length);
  assert.strictEqual(decoded.payload.toString('utf8'), payload.toString('utf8'));

  // Test Progress framing
  const progressBuf = Buffer.alloc(16);
  progressBuf.writeBigUInt64BE(1000000000n, 0); // total
  progressBuf.writeBigUInt64BE(500000000n, 8);  // done
  const progFrameRaw = encodeFrame(21 /* WUP_MSG_PROGRESS */, 12345, progressBuf);
  const progDecoded = decodeFrame(progFrameRaw);

  assert.strictEqual(progDecoded.type, 21);
  const total = progDecoded.payload.readBigUInt64BE(0);
  const done = progDecoded.payload.readBigUInt64BE(8);
  assert.strictEqual(total, 1000000000n);
  assert.strictEqual(done, 500000000n);

  console.log("wfm-ultrapack-helper protocol framing test OK");
}

testFraming();
