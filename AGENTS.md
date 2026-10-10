# AGENTS.md

Agent instructions for `wfm-ultrapack-helper`.

See [CLAUDE.md](CLAUDE.md) for build, testing commands, architecture, and code conventions.

## Key Invariants to Maintain
1. **Thread Safety & Sockets:**
   - Any writes to client socket descriptors MUST acquire `ctx->send_lock`.
   - Never access stack variables across thread boundaries; workers receive heap-allocated job contexts.
   - Ignore `SIGPIPE` at startup to prevent daemon termination if a remote client disconnects.
2. **exFAT Filesystem:**
   - Always encode directory entry filenames in UTF-16 LE and compute hashes via `UPCASE_TABLE`.
   - Use `lstat` to reject symlinks and detect case-insensitive collisions.
   - Allocate transfer buffers on the heap; do not blow worker thread stacks.
3. **PFSC Compression Engine:**
   - `.ffpfsc` must be a PFS image (header, inodes, flat path table) holding ONE inner file whose data is the PFSC container (PFSC is NOT at file offset 0); keep byte parity of the metadata with ultrapack (`tests/pfs_parity.py`).
   - Maintain 64 KiB block alignment with zero padding for uncompressed tail blocks.
   - Reuse `z_stream` state across chunks with `deflateReset`.
   - Map multi-stage progress (e.g. folder -> exfat -> ffpfsc) to a monotonic 0..100% envelope.
4. **Testing:**
   - Every bugfix and error condition must have a corresponding test case in `tests/protocol-test.js` or unit test suite.
