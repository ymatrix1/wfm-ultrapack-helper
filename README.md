# wfm-ultrapack-helper

Standalone high-performance PS5 companion helper daemon for [PS5 Web File Manager](https://github.com/ymatrix1/ps5-web-file-manager). It brings game format conversion and packaging features directly to the console with optimized disk and streaming pipelines.

## Features & Architecture

- **Supported Formats & Conversions:**
  - **Folder dump (`/app0`)** ➔ **`.exfat`**: Direct forward-only cluster serialization with zero intermediate scratch files.
  - **Folder dump (`/app0`)** ➔ **`.ffpfsc`**: Direct pipeline via interim `.exfat` into compressed PFSC blocks with monotonic progress tracking.
  - **Raw / `.exfat` Image** ➔ **`.ffpfsc`**: Streaming 64 KiB zlib compression with dynamic block offset index table.
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
