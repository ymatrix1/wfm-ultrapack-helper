# wfm-ultrapack-helper

Standalone high-performance PS5 companion helper daemon for [PS5 Web File Manager](https://github.com/ymatrix1/ps5-web-file-manager). It brings game format conversion and packaging features directly to the console with optimized disk and streaming pipelines.

## Features & Architecture

- **Supported Formats & Conversions** (all zero-staging: no temporary image is ever written; disk use is the output file only):
  - **`.pkg` (PS4-family fake PKG / PS5 homebrew fPKG)** ➔ **`.ffpfsc`** or **`.exfat`**: the package is read in place by random access (outer PFS AES-XTS decrypt, PFSC inner image, key recovered from the passcode or the RSA IMAGE_KEY chain) and its `/app0` tree plus the `sce_sys` files stored in the package header are streamed straight into the exFAT writer and PFSC encoder. Validated on two real packages against a Python reference (every file SHA-256 matches, `fsck.exfat` clean).
  - **Folder dump (`/app0`)** ➔ **`.exfat`**: forward-only cluster serialization, byte-identical to ps5-ultrapack's `mkpfs` writer.
  - **Folder dump (`/app0`)** ➔ **`.ffpfsc`**: the exFAT stream feeds the PFSC encoder directly (no interim `.exfat`); the output is a real PFS image wrapping one `<titleId>.exfat` PFSC file, the layout ShadowMountPlus mounts.
  - **Raw / `.exfat` image** ➔ **`.ffpfsc`**: wrapped into the same PFS image (inner file named after the source) and streamed through 64 KiB zlib compression with a block offset table.
  - **Not supported:** retail / Sony-encrypted packages and real PS5 NAPS/Kraken packages (rejected with an error); `.ffpfsc` ➔ `.pkg`.
- **Robust Daemon & Multi-Threading:**
  - Listens on UNIX domain socket `/system_tmp/wfm-ultrapack-helper.sock` (or `/tmp/wfm-ultrapack-helper.sock` on Linux).
  - Socket write synchronization via per-client mutex (`send_lock`) to guarantee clean, uncorrupted wire frames.
  - Single active task guard (`busy` check) per client with cooperative cancellation (`WUP_MSG_CANCEL`).
  - Progress updates throttled to ~4/sec (250 ms) to avoid overwhelming the socket buffer.
  - Signal protection (`SIGPIPE` ignored; `SIGINT`/`SIGTERM` for graceful socket cleanup).
  - Automatic error and transaction logging to `/data/wfm/helper.log`.
- **Filesystem & Unicode Compliance:**
  - Full UTF-8 to UTF-16 LE translation for directory entry file names.
  - Official exFAT upcase table lookup for checksums and name hashing.
  - `lstat` protection against symlink loops, duplicate entry collision checks, and heap-allocated transfer buffers.

---

## Building

### PS5 Native ELF (via PS5 Payload SDK)
Ensure you have the [PS5 Payload SDK](https://github.com/ps5-payload-dev/sdk) installed:
```bash
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
make ps5
```
Output: `wfm-ultrapack-helper.elf`

Deploy the binary to your console at:
```text
/data/wfm/wfm-ultrapack-helper.elf
```
PS5 Web File Manager will automatically detect and boot the helper daemon via `localhost:9021` when a conversion task begins.

### Linux Testing Build
For running the test harness and verifying server behavior on Linux/macOS:
```bash
make linux
./wfm-ultrapack-helper-linux
```

---

## Testing & Quality Assurance

Run the protocol framing, concurrency, and format validation tests:
```bash
npm test
```
Or directly with Node.js:
```bash
node tests/protocol-test.js
```

---

## License

This project is licensed under the GPL-3.0 License. Embedded `miniz` is licensed under the MIT License.
