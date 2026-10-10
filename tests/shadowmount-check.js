'use strict';
// Offline re-implementation of the checks ShadowMountPlus (drakmor/shadowMountPlus, GPL-3.0) applies
// to an image before it will register a game. Sources mirrored:
//   src/sm_image.c   validate_mounted_image(): the mounted filesystem's block size (exFAT cluster size)
//                    must be >= the device sector size (LVD exFAT default 512; 64 KiB clusters recommended)
//   src/sm_gameinfo.c directory_has_param_json() + get_game_info(): sce_sys/ must contain a regular file
//                    param.json, 1 byte .. 1 MiB, strict JSON object with a string titleId/title_id that is
//                    9 chars: PPSA|CUSA|LAPY|FAKE + 5 digits; name from localizedParameters.
//   README           .ffpfsc is a PFS container whose nested image is mounted as its own filesystem.
// Usage: node tests/shadowmount-check.js <file.ffpfsc|file.exfat>   (exit 1 when SMP would reject it)
const fs = require('fs');
const path = require('path');
const { parseFfpfsc } = require('./ffpfsc-util');

const MIN_DEVICE_SECTOR = 512;          // lvd_exfat_sector_size default
const MAX_PARAM_JSON_SIZE = 1024 * 1024;
const TITLE_ID = /^(PPSA|CUSA|LAPY|FAKE)\d{5}$/;

// Minimal exFAT directory walker: {path -> {size, read()}}
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
  const files = new Map(), dirs = new Set();
  const walk = (first, size, prefix, noFat) => {
    const d = chain(first, size, noFat);
    for (let o = 0; o + 32 <= d.length; o += 32) {
      if (d[o] === 0) break;
      if (d[o] !== 0x85) continue;
      const sec = d[o + 1], attr = d.readUInt16LE(o + 4), st = d.subarray(o + 32, o + 64);
      const nameLen = st[3], dataLen = Number(st.readBigUInt64LE(24)), fc = st.readUInt32LE(20), nofat = (st[1] & 2) !== 0;
      let name = '';
      for (let i = 2; i <= sec; i++) name += d.subarray(o + i * 32 + 2, o + i * 32 + 32).toString('utf16le');
      name = name.slice(0, nameLen);
      const full = prefix ? prefix + '/' + name : name;
      if (attr & 0x10) { dirs.add(full); walk(fc, dataLen, full, nofat); }
      else files.set(full, { size: dataLen, read: () => (dataLen ? chain(fc, dataLen, nofat) : Buffer.alloc(0)) });
      o += sec * 32;
    }
  };
  let len = 0;
  for (let c = root, n = 0; n <= clusters; n++) { len += cs; c = img.readUInt32LE(fatOff + c * 4); if (c === 0xffffffff) break; }
  walk(root, len, '', false);
  return { files, dirs, bytesPerSector: bps, clusterSize: cs };
}

function titleNameOf(root) {
  const loc = root.localizedParameters;
  const str = v => (typeof v === 'string' && v.length > 0 && v.length < 256 ? v : null);
  if (loc && typeof loc === 'object') {
    if (loc['en-US'] && str(loc['en-US'].titleName)) return loc['en-US'].titleName;
    const def = loc.defaultLanguage;
    if (typeof def === 'string' && loc[def] && str(loc[def].titleName)) return loc[def].titleName;
  }
  if (str(root.titleName)) return root.titleName;
  if (loc && typeof loc === 'object') for (const k of Object.keys(loc)) if (loc[k] && str(loc[k].titleName)) return loc[k].titleName;
  return null;
}

/** Game-info check, identical rules to sm_gameinfo.c get_game_info(). */
function checkGameInfo(files, dirs) {
  const problems = [];
  if (!dirs.has('sce_sys')) problems.push('sce_sys directory missing');
  const pj = files.get('sce_sys/param.json');
  if (!pj) { problems.push('sce_sys/param.json missing (ShadowMountPlus: "missing/invalid param.json")'); return { problems }; }
  if (pj.size <= 0 || pj.size > MAX_PARAM_JSON_SIZE) { problems.push('param.json size ' + pj.size + ' outside 1..1 MiB'); return { problems }; }
  const raw = pj.read();
  if (raw[0] === 0xEF && raw[1] === 0xBB && raw[2] === 0xBF) problems.push('param.json has a UTF-8 BOM (strict json-c parse rejects it)');
  let root;
  try { root = JSON.parse(raw.toString('utf8')); } catch (e) { problems.push('param.json is not valid JSON: ' + e.message); return { problems }; }
  if (!root || typeof root !== 'object' || Array.isArray(root)) { problems.push('param.json is not a JSON object'); return { problems }; }
  const id = typeof root.titleId === 'string' ? root.titleId : (typeof root.title_id === 'string' ? root.title_id : null);
  if (!id) problems.push('param.json has no string titleId / title_id');
  else if (!TITLE_ID.test(id)) problems.push('titleId "' + id + '" is not PPSA|CUSA|LAPY|FAKE + 5 digits');
  return { problems, titleId: id, titleName: titleNameOf(root) || id };
}

/** Check a whole image file buffer. kind: 'ffpfsc' | 'exfat'. */
function checkImage(buf, kind) {
  const problems = [], warnings = [];
  let exfat = buf, innerName = null;
  if (kind === 'ffpfsc') {
    let p;
    try { p = parseFfpfsc(buf); } catch (e) { return { ok: false, problems: ['not a valid PFS-wrapped .ffpfsc: ' + e.message], warnings }; }
    if (p.pfsHeader.magic !== 20130315) problems.push('PFS magic is not 20130315');
    if (p.pfsHeader.blockSize !== 65536) problems.push('PFS block size ' + p.pfsHeader.blockSize + ' (expected 65536)');
    innerName = p.innerName;
    if (!/\.exfat$/i.test(innerName)) warnings.push('inner file "' + innerName + '" does not end in .exfat');
    exfat = p.inflate();
  }
  if (exfat.toString('ascii', 3, 11) !== 'EXFAT   ' || exfat.readUInt16LE(510) !== 0xAA55) {
    problems.push('nested image is not an exFAT volume');
    return { ok: false, problems, warnings, innerName };
  }
  const fsx = exfatFiles(exfat);
  if (fsx.clusterSize < MIN_DEVICE_SECTOR) problems.push('exFAT cluster ' + fsx.clusterSize + ' < device sector ' + MIN_DEVICE_SECTOR + ' (SMP: image rejected, cluster too small)');
  if (fsx.clusterSize !== 65536) warnings.push('exFAT cluster size ' + fsx.clusterSize + ' (SMP recommends 65536 for the LVD fast path)');
  if (fsx.bytesPerSector !== 512) warnings.push('exFAT bytes/sector ' + fsx.bytesPerSector + ' (SMP default logical sector is 512)');
  const gi = checkGameInfo(fsx.files, fsx.dirs);
  problems.push(...gi.problems);
  return { ok: problems.length === 0, problems, warnings, innerName, titleId: gi.titleId, titleName: gi.titleName, fileCount: fsx.files.size };
}

module.exports = { checkImage, checkGameInfo, exfatFiles };

if (require.main === module) {
  const f = process.argv[2];
  if (!f) { console.error('usage: node tests/shadowmount-check.js <file.ffpfsc|file.exfat>'); process.exit(2); }
  const kind = /\.ffpfsc$/i.test(f) ? 'ffpfsc' : 'exfat';
  const r = checkImage(fs.readFileSync(path.resolve(f)), kind);
  console.log(JSON.stringify(r, null, 2));
  process.exit(r.ok ? 0 : 1);
}
