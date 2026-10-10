# CLAUDE.md

Guidelines and architecture instructions for `wfm-ultrapack-helper`.

## Build and Test Commands
- **Build Linux Daemon:** `make linux`
- **Build PS5 Native ELF:** `make ps5` (requires `PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk`)
- **Clean:** `make clean`
- **Run Protocol & End-to-End Tests:** `npm test` or `node tests/protocol-test.js`

## Architecture & Code Structure
- `src/main.c`: UNIX domain socket server (`/system_tmp/wfm-ultrapack-helper.sock` on PS5, `/tmp/wfm-ultrapack-helper.sock` on Linux).
  - Handles client framing: `WUP_MSG_PING`, `WUP_MSG_CONVERT`, `WUP_MSG_CANCEL`, `WUP_MSG_STATUS`.
  - Multithreaded client worker dispatch with `send_lock` socket mutex to guarantee uncorrupted frames.
  - Progress updates throttled to ~4/sec (250ms intervals).
  - Safe path validation preventing directory traversal and restricting access to `/data`, `/user`, `/mnt`, `/tmp`, `/system_tmp`.
  - Signal protection: `SIGPIPE` ignored to prevent process crashes on socket drop; `SIGINT`/`SIGTERM` for graceful socket unlink.
  - Logging directed to `/data/wfm/helper.log`.
- `src/exfat_engine.c` & `src/exfat_engine.h`:
  - Direct zero-staging exFAT generator; emits the image in strict offset order through a sink callback (`convert_folder_to_exfat_stream`), with `convert_folder_to_exfat` as the file sink.
  - Source-agnostic: `convert_listing_to_exfat_stream` takes a flat `exfat_listing_entry_t` list plus an `exfat_src_ops_t.read` callback (random access, strict offset order, short read = error); the folder path is just a listing builder (`scan_directory`) + pread read op on top of it. `convert_listing_to_ffpfsc` is the zero-staging .ffpfsc equivalent. Tested by `tests/listing-test.js`.
  - UTF-8 to UTF-16 conversion for filenames.
  - Up-case table lookup for checksums and name hashing.
  - `lstat` protection against symlink loops, duplicate entry detection, and heap-allocated copy buffers.
- `src/convert_engine.c` & `src/convert_engine.h`:
  - Streaming PFSC (`.ffpfsc`) 64 KiB zlib compression.
  - State reuse via `deflateReset`.
  - Folder -> ffpfsc is zero-staging: exFAT stream feeds the PFSC encoder directly (no temp image), header/offset table backpatched at the end; single monotonic 0..100% progress.
  - Trailing slash sanitization.
- `src/miniz.c` & `src/miniz.h`: Standalone amalgamated zlib library.
- `src/protocol.h`: Wire protocol framing and constants.

## Code Conventions
- Strict C99 with POSIX extensions.
- Heap allocate large buffers (never place 64 KiB+ buffers on pthread worker stacks).
- Always synchronize socket writes with `pthread_mutex_t`.
- Always check `fwrite`, `fseek`, and `fclose` return values.
