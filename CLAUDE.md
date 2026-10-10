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
  - `.ffpfsc` is a PFS filesystem image (as ShadowMountPlus / the PS5 kernel expect), not a bare PFSC: unsigned, unencrypted, 64 KiB blocks, 32-bit inodes, case-insensitive, containing ONE inner file (`<titleId>.exfat` for folder/`.pkg` sources, the (renamed) source name for raw images) whose data is a PFSC container. Fixed layout (ultrapack `build_pfs_stream_from_exfat`): block 0 header, 1 inode table (4 inodes), 2 super_root dirents, 3 flat path table, 4 reserved empty, 5 uroot dirents, 6.. PFSC (header 0x30, offset table at +0x400, zlib 64 KiB blocks, offsets relative to the PFSC start). Sizes/inode/header total are backpatched at the end. Timestamps are `time(NULL)`, or `WUP_FIXED_TIME` (seconds) for deterministic output.
  - Streaming PFSC 64 KiB zlib compression (multithreaded; see `WUP_THREADS`).
  - State reuse via `deflateReset`.
  - Folder -> ffpfsc is zero-staging: exFAT stream feeds the PFSC encoder directly (no temp image), PFS metadata + PFSC header/offset table backpatched at the end; single monotonic 0..100% progress.
  - Trailing slash sanitization.
  - Inner file naming: folder = `sce_sys/param.json` titleId (else folder name); `.pkg` = param.json titleId, else the title id in the package file name; raw image = ultrapack `resolve_single_file_inner_name` (title id in the stem, else stem collapsed to 15 ASCII chars, plus lower-cased extension).
  - Test helper `tests/ffpfsc-util.js` (`parseFfpfsc`) parses PFS -> inner file -> PFSC; `tests/pfs_parity.py` compares our output with ultrapack's mkpfs and runs its reader (see the file header).
- `src/pkg_reader.c` & `src/pkg_reader.h`: random-access, no-extraction reader for PS4-family fake PKGs (CNT header, ENTRY_KEYS/EKPFS derivation, outer PFS XTS, PFSC, inner PFS, CNT-resident `sce_sys` files). Keys in the generated `src/pkg_keys.h` (public LibOrbisPkg keysets).
- `src/fih_reader.c` & `src/kraken.c`: native PS5 `FIH` (7F 46 49 48) packages behind the same `pkgr_*` API (PlaintextNoAuth outer PFS, NAPS span plan, stored/zero/Kraken spans, inner PPR-PFS; GPL-3 Kraken port). `pkgr_open_io` takes a pluggable byte source (`pkgr_io_t`); `tests/http_range.c` is a GET-Range test backend, `tests/fih-test.js` skips when the console is unreachable.
- `src/crypto.c` & `src/rsa.c`: SHA-1/SHA-256, HMAC-SHA256, AES-128 (ECB/CBC/XTS), RSA-2048 CRT private op with PKCS#1 v1.5 / OAEP unpadding. No external crypto dependency.
- The exFAT writer takes any source through a flat listing + read callback (`convert_listing_to_exfat` / `convert_listing_to_ffpfsc`); the folder and `.pkg` paths both use it.
- Convert request payload: `source\ndest\nformat[\npasscode]`; the optional passcode is scrubbed after parsing and never logged or echoed.
- `src/miniz.c` & `src/miniz.h`: Standalone amalgamated zlib library.
- `src/protocol.h`: Wire protocol framing and constants.

- `tests/shadowmount-check.js` + `tests/shadowmount-compat-test.js`: offline copy of the checks ShadowMountPlus (GPL-3.0, drakmor/shadowMountPlus) applies before registering a game: nested exFAT cluster size >= device sector (64 KiB recommended), PFS container shape, `sce_sys/param.json` rules (1 B..1 MiB, strict JSON object, titleId PPSA|CUSA|LAPY|FAKE + 5 digits). `node tests/shadowmount-check.js <file>` checks a real image.

## Code Conventions
- Strict C99 with POSIX extensions.
- Heap allocate large buffers (never place 64 KiB+ buffers on pthread worker stacks).
- Always synchronize socket writes with `pthread_mutex_t`.
- Always check `fwrite`, `fseek`, and `fclose` return values.
