# wfm-ultrapack-helper

Standalone PS5 companion helper daemon for **PS5 Web File Manager** providing high-performance game format conversions:
- **`.pkg` (fPKG) -> `.ffpfsc`** (compressed PFS container for ShadowMountPlus)
- **`.ffpfsc` -> `.pkg`**
- **Direct extraction / packing** without redundant disk round-trips.

## Architecture

This daemon runs alongside `web-file-mgr.elf` on the PS5.
- It listens on UNIX domain socket `/system_tmp/wfm-ultrapack-helper.sock` (or `/tmp/wfm-ultrapack-helper.sock` on Linux).
- It can be auto-launched by PS5 Web File Manager via `localhost:9021` (elfldr) from `/data/wfm/wfm-ultrapack-helper.elf`.
- Uses frame-based communication (`WUPH` header magic) with non-blocking streaming progress and cancellation.

## Conversion Pipeline: PKG to FFPFSC

1. **Outer PKG / CNT Parser:**
   - Reads CNT header and entry table (param.json, icon0.png).
   - Resolves outer PFS to locate `pfs_image.dat` and `naps_pkg_layout.dat`.
2. **Inner Image Streaming:**
   - Mounts/decodes NAPS Kraken spans on-the-fly.
   - Streams logical inner PFS blocks into the PFS compression writer (zlib level 1-9) in 64 KiB blocks.
3. **Outer PFS Wrap:**
   - Assembles outer PFS with ShadowMountPlus metadata headers.
   - Emits finished `<Title> [TITLEID] [vXX.YYY] [fwN.NN].ffpfsc`.

## Building

Requires the PS5 Payload SDK:
```bash
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
make
```

For local Linux testing:
```bash
make linux
./wfm-ultrapack-helper-linux
```
