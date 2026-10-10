# wfm-ultrapack-helper

Standalone high-performance PS5 companion helper daemon for [PS5 Web File Manager](https://github.com/owendswang/ps5-web-file-manager). It brings the game format conversion and packaging features of [PS5 UltraPack](https://github.com/owendswang/ps5-web-file-manager) directly to the console with minimal temporary disk usage.

## Highlights & Zero-Staging Architecture

- **Zero intermediate extraction (Minimal Disk Footprint):**
  - Traditional tools unpack a 50–100 GB game to disk, modify files, and re-pack to another image, multiplying free space requirements (up to 3×–4× disk space).
  - `wfm-ultrapack-helper` reads the inner PPR-PFS filesystem via random-access NAPS block streaming (`InnerImage` plan).
  - Streams blocks directly from the `.pkg` into the compressed PFS `.ffpfsc` encoder in 64 KiB chunks—**requiring only the final output file's disk space**.
- **Supported Formats & Conversions:**
  - **Folder dump (`/app0`)** ➔ **`.exfat`** (contiguous cluster forward-only layout)
  - **Folder dump (`/app0`)** ➔ **`.ffpfsc`** (outer PFSC zlib compressed container for ShadowMountPlus)
  - **`.pkg` (fPKG)** ➔ **`.ffpfsc`** / **`.exfat`**
  - **Raw / `.exfat` Image** ➔ **`.ffpfsc`** (64 KiB block compression with offset index)
  - **`.ffpfsc` / `.ffpfs`** ➔ **`.pkg`** / `/app0` folder dump
- **Auto-organization & naming:**
  - Automatically identifies title ID, title name, app version, and minimum firmware tag:
    `<Title> [<TitleID>] [v<Version>] [fw<FW>].ffpfsc`
- **Non-blocking Daemon:**
  - Listens on UNIX domain socket `/system_tmp/wfm-ultrapack-helper.sock` (or `/tmp/wfm-ultrapack-helper.sock` on Linux).
  - Real-time progress, speed, ETA, and cooperative cancellation (`WUP_MSG_CANCEL`).

---

## Zero-Staging Conversion Pipeline

```
┌────────────────────────────────────────────────────────────────────────┐
│  Source Input: .pkg (fPKG), Game Folder Dump (/app0), or Raw Image     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
    ┌───────────────────────────────┴────────────────────────────────┐
    │                                                                │
 [PKG / Container Source]                                  [Folder Dump Source]
    │                                                                │
    ├─ 1. Parse CNT & Outer Superblock                               ├─ 1. Scan tree & sort dirents
    ├─ 2. Parse NAPS Layout & PPR-PFS Inodes                         ├─ 2. Assign contiguous clusters
    └─ 3. In-memory Kraken/zlib span stream                          └─ 3. Compute VBR & FAT tables
                                    │                                │
                                    └───────────────┬────────────────┘
                                                    │
┌───────────────────────────────────────────────────▼────────────────────┐
│  Direct In-Memory Streaming Engine (32 MiB rolling buffers)            │
│  - Zero intermediate scratch files or multi-step staging on disk       │
│  - Direct-to-stream exFAT serializer (VBR -> FAT -> Heap)              │
│  - Direct-to-stream PFSC block encoder (64 KiB zlib chunks + offsets)  │
└───────────────────────────────────────────────────┬────────────────────┘
                                                    │
                        Stream directly to target storage
                                                    │
┌───────────────────────────────────────────────────▼────────────────────┐
│  Destination Target Format:                                            │
│  • .ffpfsc (ShadowMountPlus compressed container)                      │
│  • .exfat  (LVD/BFS fast-path mountable image)                         │
│  • .pkg    (fPKG installable payload)                                  │
│                                                                        │
│  Disk space used: ~1x output only (no 2x-4x scratch footprint)         │
└────────────────────────────────────────────────────────────────────────┘
```

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

Run the protocol framing and streaming tests:
```bash
npm test
```
Or directly with Node.js (no dependencies required):
```bash
node tests/protocol-test.js
```

---

## License

This project is licensed under GPLv3. Third-party components retain their respective licenses (LibProsperoPkg / LibOrbisPkg GPL-3.0).
