---
title: fuse-archive
section: 1
header: User Manual
footer: fuse-archive 0.1.15
date: September 2024
---

# Name

**fuse-archive** - Mount an archive or compressed file as a FUSE file system.

# Synopsis

**fuse-archive** [*options*] *archive-file* [*mount-point*]

# Description

**fuse-archive** is a program that serves an archive or compressed file (e.g.
`foo.tar`, `foo.tar.gz`, `foo.xz` or `foo.zip`) as a read-only
[FUSE](https://en.wikipedia.org/wiki/Filesystem_in_Userspace) file system.

It is similar to [**mount-zip**](https://github.com/google/mount-zip) and
[**fuse-zip**](https://bitbucket.org/agalanin/fuse-zip) but speaks a larger
range of archive or compressed file formats.

It is similar to [**archivemount**](https://github.com/cybernoid/archivemount)
but can be much faster (see the Performance section below) although it can only
mount read-only, not read-write.

# Options

**-\-help** **-h**
:   Print help

**-\-version**
:   Print version

**-\-quiet** **-q**
:   Print fewer log messages

**-\-verbose** **-v**
:   Print more log messages

**-\-redact**
:   Redact file names from log messages

**-o force**
:   Continue despite errors

**-o nocache**
:   No caching of uncompressed data

**-o nospecials**
:   Hide special files (FIFOs, sockets, devices)

**-o nosymlinks**
:   Hide symbolic links

**-o nohardlinks**
:   No files with multiple hardlinks

**-o dmask=M**
:   Directory permission mask in octal (default 0022)

**-o fmask=M**
:   File permission mask in octal (default 0022)

**-o uid=N**
:   Set the file owner of all the items in the mounted archive (default is current user)

**-o gid=N**
:   Set file group of all the items in the mounted archive (default is current group)

**-o default_permissions**
:   Use the file owner (UID), group (GID) and permissions stored with each item in the archive. 

**-f**
:   Foreground mode

**-d**
:   Foreground mode with debug output

# Performance

Create a single `.tar.gz` file that is 256 MiB decompressed and 255 KiB
compressed (the file just contains repeated 0x00 NUL bytes):

```
$ truncate --size=256M zeroes
$ tar cfz zeroes-256mib.tar.gz zeroes
```

**fuse-archive** timings:

```
$ time fuse-archive zeroes-256mib.tar.gz mnt
real    0m0.443s

$ dd if=mnt/zeroes of=/dev/null status=progress
524288+0 records in
524288+0 records out
268435456 bytes (268 MB, 256 MiB) copied, 0.836048 s, 321 MB/s

$ fusermount -u mnt
```

**archivemount** timings:

```
$ time archivemount zeroes-256mib.tar.gz mnt
real    0m0.581s

$ dd if=mnt/zeroes of=/dev/null status=progress
268288512 bytes (268 MB, 256 MiB) copied, 569 s, 471 kB/s
524288+0 records in
524288+0 records out
268435456 bytes (268 MB, 256 MiB) copied, 570.146 s, 471 kB/s

$ fusermount -u mnt
```

Here, **fuse-archive** takes about the same time to scan the archive, bind the
mountpoint and daemonize, but it is **~700× faster** (0.83s vs 570s) to copy out
the decompressed contents. This is because **fuse-archive** does not use
**archivemount**'s
[quadratic complexity algorithm](https://github.com/cybernoid/archivemount/issues/21).

# Return Value

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

# Disclaimer

This is not an official Google product. It is just code that happens to be owned
by Google.

# See Also

archivemount(1), mount-zip(1), fuse-zip(1), fusermount(1), fuse(8), umount(8)
