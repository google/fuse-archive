---
title: fuse-archive
section: 1
header: User Manual
footer: fuse-archive 1.13
date: April 2025
---

# NAME

**fuse-archive** - Mount an archive or compressed file as a FUSE file system.

# SYNOPSIS

**fuse-archive** [*options*] *archive-file* [*mount-point*]

# DESCRIPTION

**fuse-archive** is a program that serves an archive or compressed file (e.g.
`foo.tar`, `foo.tar.gz`, `foo.xz` or `foo.zip`) as a read-only
[FUSE](https://en.wikipedia.org/wiki/Filesystem_in_Userspace) file system.

It is similar to [**mount-zip**](https://github.com/google/mount-zip) and
[**fuse-zip**](https://bitbucket.org/agalanin/fuse-zip) but speaks a larger
range of archive or compressed file formats.

It is similar to [**archivemount**](https://github.com/cybernoid/archivemount)
but can be much faster (see the Performance section below) although it can only
mount read-only, not read-write.

# OPTIONS

**-\-help** or **-h**
:   Print help

**-\-version** or **-V**
:   Print version

**-o quiet** or **-q**
:   Print fewer log messages

**-o verbose** or **-v**
:   Print more log messages

**-o redact**
:   Redact file names from log messages

**-o force**
:   Continue despite errors

**-o lazycache**
:   Incremental caching of uncompressed data

**-o nocache**
:   No caching of uncompressed data

**-o nospecials**
:   Hide special files (FIFOs, sockets, devices)

**-o nosymlinks**
:   Hide symbolic links

**-o nohardlinks**
:   No files with multiple hard links

**-o dmask=M**
:   Directory permission mask in octal (default 0022)

**-o fmask=M**
:   File permission mask in octal (default 0022)

**-o uid=N**
:   Set the file owner of all the items in the mounted archive (default is
    current user)

**-o gid=N**
:   Set file group of all the items in the mounted archive (default is current
    group)

**-o default_permissions**
:   Use the file owner (UID), group (GID) and permissions stored with each item
    in the archive.

**-f**
:   Foreground mode

**-d**
:   Foreground mode with debug output

# ARCHIVE FORMATS

**fuse-archive** determines the archive format from its filename extension. It
recognizes the following extensions:

*   Archive formats `7z`, `7zip`, `a`, `ar`, `cab`, `cpio`, `iso`, `iso9660`,
    `jar`, `mtree`, `rar`, `rpm`, `tar`, `warc`, `xar`, `zip`, `zipx`
*   ZIP-based file formats `crx`, `odf`, `odg`, `odp`, `ods`, `odt`, `docx`,
    `ppsx`, `pptx`, `xlsx`
*   Compressed TARs `tb2`, `tbz`, `tbz2`, `tz2`, `tgz`, `tlz4`, `tlz`, `tlzma`,
    `txz`, `tz`, `taz`, `tzst`, `tar.gz`, `tar.bz2`, `tar.xz`...
*   Compression filters `br`, `brotli`, `bz2`, `bzip2`, `grz`, `grzip`, `gz`,
    `gzip`, `lha`, `lrz`, `lrzip`, `lz4`, `lz`, `lzip`, `lzma`, `lzo`, `lzop`,
    `xz`, `z`, `zst`, `zstd`
*   ASCII encoding filters `b64`, `base64`, `uu`

If the filename extension is not recognized, then **fuse-archive** determines
the archive format by looking at its byte contents. This heuristic works all
right most of the time, but there are corner cases for which it might get
confused.

**fuse-archive** relies on the availability of the following filter programs:
`base64`, `brotli`, `compress`, `lrzip` and `lzop`.

# CACHING

By default, **fuse-archive** decompresses and caches the whole archive before
serving its contents. This ensures that the served files can be accessed in any
order without any performance issue.

Decompressed data is cached in an anonymous file created in the `tmp` directory
(`$TMPDIR` or `/tmp` by default). This cache can use a significant amount of
disk space, but it is automatically deleted when the archive is unmounted.

If there is not enough temporary space to cache the whole archive,
**fuse-archive** can be run with the `-o nocache` or the `-o lazycache` options.
However, this can cause **fuse-archive** to be much slower at serving files.

# PERFORMANCE

Create a single `.tar.gz` file that is 256 MiB decompressed and 255 KiB
compressed (the file just contains repeated 0x00 NUL bytes):

```
$ truncate --size=256M zeroes
$ tar cfz zeroes-256mib.tar.gz zeroes
```

Here are **fuse-archive**'s timings:

```
$ time fuse-archive zeroes-256mib.tar.gz mnt
real    0m0.443s

$ dd if=mnt/zeroes of=/dev/null status=progress
268435456 bytes (268 MB, 256 MiB) copied, 0.836048 s, 321 MB/s

$ fusermount -u mnt
```

For comparison, here are **archivemount**'s timings:

```
$ time archivemount zeroes-256mib.tar.gz mnt
real    0m0.581s

$ dd if=mnt/zeroes of=/dev/null status=progress
268435456 bytes (268 MB, 256 MiB) copied, 570.146 s, 471 kB/s

$ fusermount -u mnt
```

In this case, **fuse-archive** takes about the same time to load the archive as
**archivemount**, but it is **~700× faster** (0.83s vs 570s) to copy out the
decompressed contents. This is because **fuse-archive** fully caches the archive
and does not use **archivemount**'s
[quadratic complexity algorithm](https://github.com/cybernoid/archivemount/issues/21).

# RETURN VALUE

**0**
:   Success.

**1**
:   Generic error code for: missing command line argument, too many command line
    arguments, unknown option, mount point is not empty, etc.

**10**
:   Cannot create the mount point.

**11**
:   Cannot open the archive file.

**12**
:   Cannot create the cache file.

**13**
:   Cannot write to the cache file. This is most likely the indication that
    there is not enough temp space.

**20**
:   The archive contains an encrypted file, but no password was provided.

**21**
:   The archive contains an encrypted file, and the provided password does not
    decrypt it.

**22**
:   The archive contains an encrypted file, and the encryption method is not
    supported.

**30**
:   Cannot recognize the archive format.

**31**
:   Invalid archive header.

**32**
:   Cannot read and extract the archive.

# SEE ALSO

archivemount(1), mount-zip(1), fuse-zip(1), fusermount(1), fuse(8), umount(8)
