#!/usr/bin/env python3
"""Structural parity of our .ffpfsc output with ultrapack's mkpfs.

Subcommands (run with the Windows python; avoid shell metacharacters in arguments):

  gen-folder <ultrapack_backend_dir> <folder> <out.ffpfsc> <fixed_time>
      Reference build with build_pfs_stream_from_exfat (time.time pinned to <fixed_time>).
  gen-image  <ultrapack_backend_dir> <image> <out.ffpfsc> <fixed_time>
      Reference build with build_pfs_stream_single_file (the `mkpfs pack file` path).
  compare    <ref.ffpfsc> <ours.ffpfsc>
      Parse both files and compare every field. Everything outside the zlib payloads must be byte
      identical (PFS header block, inode table except the three size fields that depend on the compressed
      length, dirents, flat path table, PFSC header and table geometry); the inflated inner image must be
      identical. Exit code 0 = parity, 1 = difference.
  check      <ultrapack_backend_dir> <file.ffpfsc|file.exfat> [source_folder]
      Run ultrapack's own reader on a file: run_image_check (PFS structure, flat path table, payload
      decode), open_inner_file_view + ExfatReader (file list with sha256), verify_exfat_image (optionally
      against a source folder) and extract_exfat_image. Exit code 0 = no errors.
"""
import struct
import sys
import zlib

BS = 0x10000


def parse(path):
    d = open(path, "rb").read()
    h = struct.unpack_from("<qqq", d, 0)
    version, magic = h[0], h[1]
    assert magic == 20130315, "PFS magic"
    mode = struct.unpack_from("<H", d, 0x1C)[0]
    block_size, = struct.unpack_from("<I", d, 0x20)
    nblock, inode_count, ndblock, inode_blocks = struct.unpack_from("<qqqq", d, 0x28)
    inodes = []
    for i in range(inode_count):
        o = block_size + i * 0xA8
        mode_i, nlink, flags = struct.unpack_from("<HHI", d, o)
        size, size_c = struct.unpack_from("<qq", d, o + 8)
        blocks, = struct.unpack_from("<I", d, o + 0x60)
        db = list(struct.unpack_from("<12i", d, o + 0x64))
        inodes.append(dict(mode=mode_i, nlink=nlink, flags=flags, size=size, size_c=size_c,
                           blocks=blocks, db=db, raw=d[o:o + 0xA8]))
    file_ino = inodes[3]
    base = file_ino["db"][0] * block_size
    magic_p, unk4, unk8, lbs32 = struct.unpack_from("<iiii", d, base)
    lbs, off_off, data_off, data_len = struct.unpack_from("<qqQq", d, base + 0x10)
    assert magic_p == 0x43534650, "PFSC magic at inner file"
    nb = data_len // lbs
    offs = list(struct.unpack_from("<%dQ" % (nb + 1), d, base + off_off))
    blocks = []
    for i in range(nb):
        s = d[base + offs[i]: base + offs[i + 1]]
        blocks.append(s if len(s) == lbs else zlib.decompress(s))
    inner = b"".join(blocks)
    return dict(d=d, version=version, mode=mode, bs=block_size, nblock=nblock, inode_count=inode_count,
                ndblock=ndblock, inode_blocks=inode_blocks, inodes=inodes, base=base,
                pfsc_hdr=d[base:base + 0x30], lbs=lbs, off_off=off_off, data_off=data_off, data_len=data_len,
                offs=offs, inner=inner, nb=nb)


def compare(ref_path, our_path):
    r, o = parse(ref_path), parse(our_path)
    bad = []
    ok = []

    def eq(name, a, b):
        (ok if a == b else bad).append("%s: ref=%r ours=%r" % (name, a, b) if a != b else name)

    for k in ("version", "mode", "bs", "nblock", "inode_count", "inode_blocks", "base", "lbs", "off_off",
              "data_off", "data_len", "nb"):
        eq("field " + k, r[k], o[k])
    eq("inner image bytes (inflated)", r["inner"] == o["inner"], True)
    # PFS front blocks: block 0 header (ndblock differs only if compressed sizes differ), blocks 2..5 dirents/fpt/empty
    hr, ho = bytearray(r["d"][:BS]), bytearray(o["d"][:BS])
    nd_r, nd_o = r["ndblock"], o["ndblock"]
    hr[0x38:0x40] = b"\0" * 8
    ho[0x38:0x40] = b"\0" * 8
    eq("PFS header block 0 (bytes, ndblock masked)", bytes(hr), bytes(ho))
    for b, name in ((2, "super_root dirents"), (3, "flat_path_table"), (4, "reserved empty block"),
                    (5, "uroot dirents")):
        eq("block %d %s (bytes)" % (b, name), r["d"][b * BS:(b + 1) * BS], o["d"][b * BS:(b + 1) * BS])
    for i in range(3):
        eq("inode %d (bytes)" % i, r["inodes"][i]["raw"], o["inodes"][i]["raw"])
    ri, oi = r["inodes"][3], o["inodes"][3]
    for k in ("mode", "nlink", "flags", "size_c", "db"):
        eq("file inode " + k, ri[k], oi[k])
    # these three depend on the compressed length
    same_comp = r["offs"] == o["offs"]
    if same_comp:
        eq("file inode size/blocks + ndblock (compressed bytes identical)", (ri["size"], ri["blocks"], nd_r),
           (oi["size"], oi["blocks"], nd_o))
    else:
        # internal consistency of ours instead
        eq("ours: file size == last PFSC offset", o["offs"][-1], oi["size"])
        eq("ours: file blocks == ceil(size/bs)", -(-oi["size"] // BS), oi["blocks"])
        eq("ours: ndblock == db0 + blocks", oi["db"][0] + oi["blocks"], nd_o)
        eq("ours: file length == ndblock*bs", len(o["d"]), nd_o * BS)
        eq("ref: file length == ndblock*bs", len(r["d"]), nd_r * BS)
    eq("PFSC header 0x30 (bytes)", r["pfsc_hdr"], o["pfsc_hdr"])
    eq("PFSC data start offset", r["offs"][0], o["offs"][0])
    # timestamps present in inodes/header (covered by byte equality above); report them
    t = struct.unpack_from("<q", o["d"], BS + 0x18)[0]
    print("timestamp in ours: %d" % t)
    print("compressed bytes identical:", r["d"] == o["d"])
    print("ref  size %d bytes, ours %d bytes" % (len(r["d"]), len(o["d"])))
    print("%s (%d ok, %d different):" % ("PASS" if not bad else "FAIL", len(ok), len(bad)))
    for x in ok:
        print("   ok   " + x)
    for x in bad:
        print("   DIFF " + x)
    return 1 if bad else 0


def setup_path(backend):
    sys.path.insert(0, backend)


def pinned_time(fixed):
    import time
    fixed = float(fixed)
    real = time.time
    time.time = lambda: fixed
    return real


def gen_folder(backend, folder, out, fixed):
    setup_path(backend)
    from pathlib import Path
    pinned_time(fixed)
    from mkpfs import pfs
    pfs.build_pfs_stream_from_exfat(
        source_root=Path(folder), output_path=Path(out), block_size=65536, pfs_version=2,
        case_insensitive=True, zlib_level=7, threshold_gain=0, cpu_count=1)
    return 0


def gen_image(backend, image, out, fixed):
    setup_path(backend)
    from pathlib import Path
    pinned_time(fixed)
    from mkpfs import pfs
    src = Path(image)
    pfs.build_pfs_stream_single_file(
        source_file=src, output_path=Path(out), block_size=65536, pfs_version=2, case_insensitive=True,
        zlib_level=7, threshold_gain=0, min_file_gain=0, min_compress_size=65536, cpu_count=1, compress=True,
        inner_file_name=pfs.resolve_single_file_inner_name(source_name=src.name, rename_inner_image=True))
    return 0


def check(backend, path, source=None):
    """ultrapack's own reader on a .ffpfsc (or a raw .exfat): PFS check, then the inner exFAT."""
    setup_path(backend)
    import hashlib
    import os
    import tempfile
    from pathlib import Path
    from mkpfs import pfs
    from mkpfs.cli import run_image_check
    from mkpfs.exfat import EXFAT_SIGNATURE, ExfatReader

    image = Path(path)
    rc = 0
    with open(image, "rb") as f:
        raw_exfat = f.read(11)[3:] == EXFAT_SIGNATURE
    if not raw_exfat:
        errors, warnings, _tree, _uroot = run_image_check(image, None, print_tree=False, emit_report=False)
        for w in warnings:
            print("WARNING:", w)
        for e in errors:
            print("ERROR:", e)
        print("run_image_check: errors=%d warnings=%d" % (len(errors), len(warnings)))
        rc |= 1 if errors else 0
        opened = pfs.open_inner_file_view(image)
        if opened is None:
            print("ERROR: no single inner file view")
            return 1
        view, fh, name = opened
        print("inner file:", name)
        tmp = tempfile.NamedTemporaryFile(prefix="inner_", suffix=".exfat", delete=False)
        try:
            view.seek(0)
            while True:
                chunk = view.read(4 << 20)
                if not chunk:
                    break
                tmp.write(chunk)
        finally:
            tmp.close()
            fh.close()
        inner = Path(tmp.name)
    else:
        inner = image
    try:
        with open(inner, "rb") as f:
            reader = ExfatReader(f)
            n = 0
            for entry in sorted(reader.iter_files(), key=lambda e: e.rel_path):
                h = hashlib.sha256()
                for chunk in reader.read_file(entry):
                    h.update(chunk)
                print("FILE %s %d %s" % (entry.rel_path.replace(chr(92), "/").lstrip("/"), entry.length, h.hexdigest()))
                n += 1
            print("exfat files: %d" % n)
        errs, warns = pfs.verify_exfat_image(inner, Path(source) if source else None)
        for w in warns:
            print("WARNING:", w)
        for e in errs:
            print("ERROR:", e)
        print("verify_exfat_image%s: errors=%d warnings=%d" % (" (vs source)" if source else "", len(errs), len(warns)))
        rc |= 1 if errs else 0
        out = tempfile.mkdtemp(prefix="unpack_")
        res = pfs.extract_exfat_image(inner, Path(out))
        print("extract_exfat_image: %s bytes written" % res.bytes_written)
    finally:
        if not raw_exfat:
            os.unlink(inner)
    return rc


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    cmd = argv[1]
    if cmd == "compare" and len(argv) == 4:
        return compare(argv[2], argv[3])
    if cmd == "gen-folder" and len(argv) == 6:
        return gen_folder(*argv[2:])
    if cmd == "gen-image" and len(argv) == 6:
        return gen_image(*argv[2:])
    if cmd == "check" and len(argv) in (4, 5):
        return check(*argv[2:])
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
