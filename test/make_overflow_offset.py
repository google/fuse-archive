#!/usr/bin/env python3
"""Generate a GNU sparse tar that triggers signed integer overflow in CacheEntryData.

The archive contains two entries:
  1. A 1-byte regular file — causes g_cache_size (file_start_offset) to be 1
     after it is cached.
  2. A GNU sparse file with a single data block at offset 100 (small, so the
     cache write succeeds) but with realsize = INT64_MAX. When libarchive
     signals end-of-file it reports offset = INT64_MAX (the logical file size).

With the unfixed code, the ARCHIVE_EOF branch computes:
  dest_offset = file_start_offset + offset
              = 1 + INT64_MAX                 → signed integer overflow (UB)

Verified with UBSan:
  runtime error: signed integer overflow: 1 + 9223372036854775807 cannot
  be represented in type 'long int'
  fuse-archive aborts with SIGABRT (exit 134).

With the fix applied, __builtin_add_overflow detects the overflow and throws
ExitCode::INVALID_ARCHIVE_CONTENTS (exit 32) — no crash, no UB.

Usage:
  python3 test/make_overflow_offset.py > /tmp/overflow_offset.tar
  fuse-archive /tmp/overflow_offset.tar /mnt/test   # exits 32 with fix, crashes without
"""

import sys

INT64_MAX = (1 << 63) - 1  # 0x7FFFFFFFFFFFFFFF


def encode_base256(value: int, width: int = 12) -> bytes:
    """Encode a large integer using GNU tar base-256 (high bit of first byte set)."""
    result = bytearray(width)
    result[0] = 0x80
    for i in range(width - 1, 0, -1):
        result[i] = value & 0xFF
        value >>= 8
    return bytes(result)


def tar_field(value: int, width: int) -> bytes:
    """Encode a tar numeric field; use base-256 for values too large for octal."""
    if value < 8 ** (width - 1):
        return f"{value:0{width-1}o}\0".encode()
    return encode_base256(value, width)


def checksum_for(header: bytearray) -> int:
    h = bytearray(header)
    h[148:156] = b"        "
    return sum(h)


def regular_file_header(name: bytes, size: int) -> bytes:
    hdr = bytearray(512)
    hdr[0 : len(name)] = name
    hdr[100:108] = b"0000644\0"
    hdr[108:116] = b"0001750\0"
    hdr[116:124] = b"0001750\0"
    hdr[124:136] = tar_field(size, 12)
    hdr[136:148] = tar_field(0, 12)
    hdr[148:156] = b"        "
    hdr[156] = ord("0")
    hdr[257:263] = b"ustar\0"
    hdr[263:265] = b"00"
    csum = checksum_for(hdr)
    hdr[148:156] = f"{csum:06o}\0 ".encode()
    return bytes(hdr)


def gnu_sparse_header(name: bytes, sparse_offset: int,
                      sparse_len: int, realsize: int) -> bytes:
    hdr = bytearray(512)
    hdr[0 : len(name)] = name
    hdr[100:108] = b"0000644\0"
    hdr[108:116] = b"0001750\0"
    hdr[116:124] = b"0001750\0"
    # size field = physical (non-hole) bytes on disk
    hdr[124:136] = tar_field(sparse_len, 12)
    hdr[136:148] = tar_field(0, 12)
    hdr[148:156] = b"        "
    hdr[156] = ord("S")               # GNU sparse type
    hdr[257:265] = b"ustar  \0"       # GNU magic
    hdr[265:297] = b"root" + b"\0" * 28
    hdr[297:329] = b"root" + b"\0" * 28
    # Sparse map at offset 386: sp[0].offset[12] + sp[0].size[12]
    hdr[386:398] = tar_field(sparse_offset, 12)
    hdr[398:410] = tar_field(sparse_len, 12)
    hdr[482] = 0                       # isextended = 0
    hdr[483:495] = tar_field(realsize, 12)
    csum = checksum_for(hdr)
    hdr[148:156] = f"{csum:06o}\0 ".encode()
    return bytes(hdr)


def make_poc_tar() -> bytes:
    blocks = bytearray()

    # --- Entry 1: 1-byte regular file ---
    # After caching, g_cache_size = 1, so file_start_offset = 1 for entry 2.
    blocks += regular_file_header(b"tiny.txt\0", size=1)
    data = bytearray(512)
    data[0] = ord("X")
    blocks += bytes(data)

    # --- Entry 2: GNU sparse file ---
    # One real byte at a small offset (100) so the cache write succeeds.
    # realsize = INT64_MAX: libarchive reports offset=INT64_MAX at ARCHIVE_EOF.
    #
    # Unfixed code at ARCHIVE_EOF:
    #   dest_offset = file_start_offset + offset
    #               = 1 + INT64_MAX              → signed integer overflow (UB)
    blocks += gnu_sparse_header(
        name=b"sparse.bin\0",
        sparse_offset=100,
        sparse_len=1,
        realsize=INT64_MAX,
    )
    data2 = bytearray(512)
    data2[0] = ord("A")
    blocks += bytes(data2)

    # Two EOF blocks
    blocks += bytes(1024)

    return bytes(blocks)


if __name__ == "__main__":
    sys.stdout.buffer.write(make_poc_tar())
