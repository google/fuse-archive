#!/usr/bin/env python3
"""Generate a GNU sparse tar that triggers signed integer overflow in CacheEntryData.

The archive contains two entries:
  1. A 1-byte regular file — causes g_cache_size (file_start_offset) to be 1
     after it is cached.
  2. A GNU sparse file with a single sparse block at offset (INT64_MAX - 1)
     and length 1, so realsize = INT64_MAX (a valid int64_t).

When fuse-archive processes entry 2 with file_start_offset=1:
  ARCHIVE_OK path (original code, without the fix):
    dest_offset = 1 + (INT64_MAX - 1) = INT64_MAX   # no overflow here
    dest_offset += 1                                  # INT64_MAX + 1 → signed overflow (UB)

With the fixed code both additions are validated and
ExitCode::INVALID_ARCHIVE_CONTENTS is thrown before any overflow occurs.

Usage:
  python3 test/make_overflow_offset.py > /tmp/overflow_offset.tar
  # Without fix:  triggers UB / potential write to wrong cache offset
  # With fix:     fuse-archive exits with INVALID_ARCHIVE_CONTENTS
"""

import struct
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
    """Build a POSIX ustar header for a regular file."""
    hdr = bytearray(512)
    hdr[0 : len(name)] = name
    hdr[100:108] = b"0000644\0"
    hdr[108:116] = b"0001750\0"
    hdr[116:124] = b"0001750\0"
    hdr[124:136] = tar_field(size, 12)
    hdr[136:148] = tar_field(0, 12)       # mtime = 0
    hdr[148:156] = b"        "            # checksum placeholder
    hdr[156] = ord("0")                   # regular file
    hdr[257:263] = b"ustar\0"
    hdr[263:265] = b"00"
    csum = checksum_for(hdr)
    hdr[148:156] = f"{csum:06o}\0 ".encode()
    return bytes(hdr)


def gnu_sparse_header(name: bytes, sparse_offset: int,
                      sparse_len: int, realsize: int) -> bytes:
    """Build a GNU tar header for a sparse file with one sparse entry."""
    hdr = bytearray(512)
    hdr[0 : len(name)] = name
    hdr[100:108] = b"0000644\0"
    hdr[108:116] = b"0001750\0"
    hdr[116:124] = b"0001750\0"
    # size field holds the amount of real (non-hole) data on disk = sparse_len
    hdr[124:136] = tar_field(sparse_len, 12)
    hdr[136:148] = tar_field(0, 12)       # mtime = 0
    hdr[148:156] = b"        "
    hdr[156] = ord("S")                   # GNU sparse type
    hdr[257:265] = b"ustar  \0"           # GNU magic
    hdr[265:297] = b"root" + b"\0" * 28
    hdr[297:329] = b"root" + b"\0" * 28

    # Sparse map at offset 386: sp[0].offset[12] + sp[0].size[12]
    hdr[386:398] = tar_field(sparse_offset, 12)
    hdr[398:410] = tar_field(sparse_len, 12)

    # isextended = 0 (no extension blocks)
    hdr[482] = 0

    # realsize at offset 483 (the logical file size)
    hdr[483:495] = tar_field(realsize, 12)

    csum = checksum_for(hdr)
    hdr[148:156] = f"{csum:06o}\0 ".encode()
    return bytes(hdr)


def make_poc_tar() -> bytes:
    blocks = bytearray()

    # --- Entry 1: 1-byte regular file ---
    # This causes g_cache_size = 1 after caching, so file_start_offset = 1
    # for the second entry.
    blocks += regular_file_header(b"tiny.txt\0", size=1)
    data = bytearray(512)
    data[0] = ord("X")
    blocks += bytes(data)

    # --- Entry 2: GNU sparse file ---
    # sparse_offset = INT64_MAX - 1, sparse_len = 1, realsize = INT64_MAX
    #
    # With file_start_offset = 1 (from entry 1):
    #   dest_offset = 1 + (INT64_MAX - 1) = INT64_MAX            [OK]
    #   dest_offset += 1  -->  INT64_MAX + 1  -->  OVERFLOW (UB)
    sparse_offset = INT64_MAX - 1
    sparse_len = 1
    realsize = INT64_MAX  # = sparse_offset + sparse_len, fits in int64_t

    blocks += gnu_sparse_header(b"sparse.bin\0", sparse_offset, sparse_len, realsize)
    data2 = bytearray(512)
    data2[0] = ord("A")   # the 1 real byte
    blocks += bytes(data2)

    # Two EOF blocks
    blocks += bytes(1024)

    return bytes(blocks)


if __name__ == "__main__":
    sys.stdout.buffer.write(make_poc_tar())
