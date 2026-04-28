---
title: fuse-archive
section: 1
header: User Manual
footer: fuse-archive 1.21
date: April 2026
---

# NAME

**fuse-archive** - Mount archives as a read-only FUSE file system.

# SYNOPSIS

* **fuse-archive** [*options*] *archive* [*mount_point*]
* **fuse-archive** [*options*] *archive* ... *mount_point*

# DESCRIPTION

**fuse-archive** serves one or several archives or compressed files (e.g.,
`foo.tar`, `foo.tar.gz`, `foo.xz`, or `foo.zip`) as a read-only
[FUSE](https://en.wikipedia.org/wiki/Filesystem_in_Userspace) file system.

It is similar to [**mount-zip**](https://github.com/google/mount-zip) and
[**fuse-zip**](https://bitbucket.org/agalanin/fuse-zip) but supports a larger
range of archive or compressed file formats.

It is similar to [**archivemount**](https://github.com/cybernoid/archivemount)
but can be much faster (see the Performance section below), although it can only
mount read-only, not read-write.

**fuse-archive** automatically creates the target mount point if needed and
automatically removes it when the file system is unmounted. If the mount point
already existed before **fuse-archive** was started, it is not removed.

If no mount point is specified, **fuse-archive** uses the name of the archive
(without its filename extension) as a mount point in the current working
directory. If that directory already exists, it will try to create one with a
numeric suffix (e.g., `archive (1)`).

# OPTIONS

**-\-help** or **-h**
:   Print help.

**-\-version** or **-V**
:   Print version info.

**-o quiet** or **-q**
:   Print fewer log messages.

**-o verbose** or **-v**
:   Print more log messages.

**-o redact**
:   Redact file names from log messages.

**-o force**
:   Continue despite errors.

**-o maxfilters=N**
:   Maximum number of filters per archive (default is 1).

**-o lazycache**
:   Incremental caching of uncompressed data.

**-o nocache**
:   No caching of uncompressed data.

**-o memcache**
:   Caching in memory (Linux only).

**-o nomerge**
:   Do not merge multiple archives on top of each other. Instead, create a
    subdirectory for each archive inside the mount point.

**-o notrim**
:   Do not trim the base of the tree. Keep all the intermediate directories as
    specified in the archive(s).

**-o nodirs**
:   No directories. Flatten the archive structure by presenting all its files in
    its root directory. This might make sense if you're not interested in the
    archive tree structure, but only in its file data, e.g., for malware scanning.

**-o nospecials**
:   Hide special files (FIFOs, sockets, devices).

**-o nosymlinks**
:   Hide symbolic links.

**-o noholes**
:   Do not report holes in sparse files.

**-o nohardlinks**
:   Do not report files with multiple hard links.

**-o noxattrs**
:   Do not report extended attributes.

**-o dmask=M**
:   Directory permission mask in octal (default is 0022).

**-o fmask=M**
:   File permission mask in octal (default is 0022).

**-o uid=N**
:   Set the file owner of all the items in the mounted archive (default is the
    current user).

**-o gid=N**
:   Set the file group of all the items in the mounted archive (default is the
    current group).

**-o default_permissions**
:   Use the file owner (UID), group (GID), and permissions stored with each item
    in the archive.

**-f**
:   Foreground mode.

**-d**
:   Foreground mode with debug output.

# USAGE EXAMPLES

Mount a single archive:

```
$ fuse-archive foobar.tar.gz mnt
```

The mounted archive can be explored and read using any application:

```
$ tree mnt
mnt
└── foo
    └── bar.txt

1 directory, 1 file

$ cat mnt/foo/bar.txt
Hello, world!
```

Mount multiple archives into the same mount point (merged view):

```
$ fuse-archive archive1.zip archive2.tar.bz2 mnt
```

Mount multiple archives as separate subdirectories:

```
$ fuse-archive -o nomerge archive1.zip archive2.7z mnt
$ ls mnt
archive1 archive2
```

Consult a GPG-encrypted file securely without decrypting it to disk:

```
$ fuse-archive secret.txt.gpg mnt
Password >
$ cat mnt/secret.txt
```

When finished, unmount the file system:

```
$ umount mnt
```

# FEATURES

*   **Read-only view**: Archives are served as a safe, read-only file system.
*   **Wide format support**: Supports ZIP, 7Z, RAR, TAR, ISO, and many other
    formats through [**libarchive**](https://libarchive.org).
*   **Encryption**: Handles both native archive encryption (e.g., ZIP) and
    [**GnuPG**](https://gnupg.org/) encryption.
*   **Flexible Caching**: Offers pre-emptive, incremental (lazy), and memory-based
    caching strategies.
*   **Multiple Archives**: Can mount several archives simultaneously, either
    merging them into a single tree or keeping them separate.
*   **Automatic Mount Management**: Automatically creates and removes mount
    point directories as needed.
*   **File System Support**:
    *   **Special Files**: Supports named sockets, FIFOs, and devices.
    *   **Links**: Correctly handles symbolic links and hard links.
    *   **Sparse Files**: Detects and exposes "holes" in sparse files for
        efficient reading.
    *   **Extended Attributes**: Supports reading xattrs from archives.
*   **Permissions**: Honors Unix access modes, ownership (UID/GID), and special
    bits (SUID/SGID/SVTX).
*   **Deduplication**: Gracefully handles name collisions between multiple
    archives or within a single archive.
*   **Performance**: Optimized for speed through efficient caching.

# ARCHIVE FORMATS

**fuse-archive** is built on top of the [**libarchive**](https://libarchive.org)
library. It supports a wide variety of archive formats and compression methods,
either natively through **libarchive** or by invoking external filter programs.

The exact set of supported formats depends on:

*   The version and build-time configuration of the **libarchive** library.
*   The availability of external filter programs in your system's `PATH`.

To see the version of **libarchive** and other libraries linked with your build
of **fuse-archive**, use the `--version` option:

```
$ fuse-archive --version
```

## Filename Extensions

**fuse-archive** primarily determines an archive's format from its filename
extension. It recognizes the following:

*   **Archive formats**: `7z`, `7zip`, `a`, `ar`, `cab`, `cpio`, `deb`, `iso`,
    `iso9660`, `jar`, `lha`, `lzh`, `mtree`, `rar`, `rpm`, `tar`, `war`, `warc`,
    `xar`, `zip`, `zipx`.
*   **ZIP-based formats**: `aab`, `apk`, `cbz`, `crx`, `docx`, `epub`, `ipa`,
    `jar`, `odf`, `odg`, `odp`, `ods`, `odt`, `ppsx`, `pptx`, `war`, `whl`,
    `xlsx`, `xpi`, `zip`, `zipx`.
*   **RAR-based formats**: `rar`, `cbr`.
*   **Compressed TARs**: `tb2`, `tbr`, `tbz`, `tbz2`, `tz2`, `tgz`, `tlz`, `tlz4`,
    `tlzip`, `tlzma`, `tlrz`, `tlzo`, `tlzop`, `txz`, `tz`, `taz`, `tzs`, `tzst`,
    `tzstd`.
*   **Compression filters**: `br`, `brotli`, `bz`, `bz2`, `bzip2`, `grz`,
    `grzip`, `gz`, `gzip`, `lrz`, `lrzip`, `lz`, `lz4`, `lzip`, `lzma`, `lzo`,
    `lzop`, `xz`, `z`, `zst`, `zstd`.
*   **ASCII encoding filters**: `b64`, `base64`, `uu`.
*   **Encryption filters**: `asc`, `gpg`, `pgp`.

If the filename extension is not recognized, **fuse-archive** will attempt to
detect the format by examining the file's byte contents.

## External Filter Programs

For some formats and encodings, **fuse-archive** relies on the following
external programs being available in your `PATH`:

*   `base64`: For `b64` and `base64` encodings.
*   `brotli`: For `br` and `brotli` compression.
*   `compress`: For `z`, `taz`, and `tz` compression (if not supported natively
    by **libarchive**).
*   `gpg`: For `asc`, `gpg`, and `pgp` encryption.
*   `lrzip`: For `lrz` and `tlrz` compression.
*   `lzop`: For `lzo`, `lzop`, `tlzo`, and `tlzop` compression (if not supported
    natively by **libarchive**).

Other formats, such as `uu` (UUencoded), `lzip`, `xz`, `gzip`, and `bzip2`, are
typically handled natively by the **libarchive** library and do not require
external programs.

# ARCHIVE TREE STRUCTURE

By default, **fuse-archive** optimizes the presentation of the mounted archives
by merging them and trimming redundant top-level directories. This behavior can
be modified with the `-o nomerge` and `-o notrim` options.

## Merging Multiple Archives

When mounting several archives, **fuse-archive** merges their contents into a
single unified directory tree by default. If multiple archives contain the same
file path, the files are deduplicated by adding a numeric suffix (e.g.,
`file (1).txt`).

With the `-o nomerge` option, **fuse-archive** creates a separate subdirectory
for each archive at the root of the mount point, named after the archive's
filename.

## Trimming the Base Tree

**fuse-archive** automatically "trims" the common base directory of the archive
to provide more direct access to its contents. For example, if an archive
contains only `a/b/c/file.txt`, it will be presented as `file.txt` at the root
of the mount point.

The `-o notrim` option disables this behavior, preserving all intermediate
directories as they are recorded in the archive.

## Interaction Table

The following table summarizes how these options interact when mounting archives
`arch1.zip` (containing `a/b/c/f1`) and `arch2.zip` (containing `a/b/d/f2`):

Option              | Resulting Structure
:------------------ | :------------------
(Default)           | `/c/f1`, `/d/f2`
`-o notrim`         | `/a/b/c/f1`, `/a/b/d/f2`
`-o nomerge`        | `/arch1/f1`, `/arch2/f2`
`-o nomerge,notrim` | `/arch1/a/b/c/f1`, `/arch2/a/b/d/f2`

# ENCRYPTION

**fuse-archive** supports two distinct types of encryption: native archive
encryption and GPG-based encryption.

## Native Archive Encryption

Some archive formats (such as ZIP) have native encryption capabilities built-in.
**fuse-archive** can leverage these when supported by the underlying
**libarchive** library.

*   **ZIP**: Supported (may require specific **libarchive** build options).
*   **7Z and RAR**: Native encryption for these formats is currently **not**
    supported.

When mounting a natively encrypted archive, **fuse-archive** will securely
prompt for a password in the terminal. You can also pipe the password to
**fuse-archive**'s standard input.

## GPG Encryption

**fuse-archive** also supports archives and individual files encrypted with
[GnuPG](https://gnupg.org/) (e.g., `archive.tar.gpg`, `archive.7z.pgp`, or
`romeo.txt.asc`). This is handled by invoking the external `gpg` command-line
tool.

Using GPG encryption is particularly useful for consulting sensitive documents
without having to store a decrypted copy on the local disk, which avoids the
risk of leaving confidential data behind in temporary folders.

When mounting a GPG-encrypted item, **fuse-archive** leverages your existing
GnuPG configuration and environment:

*   **Passphrase Management**: It can work with `gpg-agent` to reuse cached
    passphrases.
*   **Secure Prompting**: It can use `pinentry` to securely prompt for
    passphrases via your preferred method (GUI or terminal).
*   **Hardware Support**: It supports decryption via hardware tokens (like
    YubiKeys) if they are configured in your system's GnuPG setup.
*   **Nested Encodings**: It can handle multiple layers of compression and
    encryption (e.g., `archive.tar.gz.gpg`). Use the `-o maxfilters` option to
    support these scenarios.

Ensure that the `gpg` program is installed and available in your `PATH`.

# CACHING

**fuse-archive** only does the minimum amount of work required to serve the
requested data. It offers several caching strategies and storage options to
balance performance, mount time, and resource usage.

## Caching Strategies

The following strategies are mutually exclusive. If none is specified,
pre-emptive caching is used by default.

### Pre-emptive Caching (Default)

By default, **fuse-archive** decompresses and caches the whole archive before
serving its contents. The cost of decompression is incurred upfront at mount
time, ensuring that subsequent access to any file is instantaneous and supports
efficient random access.

### Incremental Caching (`-o lazycache`)

With `-o lazycache`, **fuse-archive** decompresses data on-the-go as it is
requested by applications. This results in nearly instant mounting for archives
that support random access to metadata (such as ZIP, 7Z, or RAR). Once a section
of the archive has been read, it is cached for future access.

Note that for solidly compressed archives (e.g., `.tar.gz`, `.tar.xz`) or
encrypted archives, the entire file must still be processed at mount time to
retrieve the file list, which may take some time for very large archives.

### No Caching (`-o nocache`)

The `-o nocache` option disables long-term caching. **fuse-archive** will use a
small rolling buffer in memory to serve data. This minimizes disk and memory
usage but can be significantly slower for non-sequential access patterns or if
the same files are read repeatedly, as data may need to be re-decompressed.

## Storage Options

### Disk Caching (Default)

By default, decompressed data is cached in an anonymous temporary file (in
`$TMPDIR` or `/tmp`). This cache can use a significant amount of disk space but
is automatically deleted when the archive is unmounted.

### Memory Caching (`-o memcache`)

The `-o memcache` option instructs **fuse-archive** to store the cache in RAM
instead of a temporary file. This provides the highest performance but can
consume a large amount of memory. It can be used with both pre-emptive and
incremental caching strategies. This option is only available on Linux.

# ADVANCED OPTIONS

## Handling Errors (`-o force`)

The `-o force` option allows **fuse-archive** to continue mounting an archive
even if some errors are encountered. This includes:

*   Wrong or missing decryption passwords.
*   Unsupported compression or encryption methods.

In these cases, files that cannot be correctly processed will still be listed in
the directory tree, but attempting to read them will result in an Input/Output
error (EIO).

## Nested Encodings (`-o maxfilters=N`)

Some archives may have multiple layers of compression or encryption (e.g.,
`archive.tar.gz.gpg`). By default, **fuse-archive** only processes one layer of
filtering.

To mount archives with nested encodings, you must increase the `-o maxfilters`
value (e.g., `-o maxfilters=2`).

## Permissions and Ownership

By default, **fuse-archive** presents all files as being owned by the current
user and group, with standard read permissions.

### User and Group IDs (`-o uid=N`, `-o gid=N`)

You can explicitly set the owner and group of all items in the mounted archive
using the `-o uid` and `-o gid` options with the desired numerical IDs.

### Using Archive Permissions (`-o default_permissions`)

The `-o default_permissions` option instructs **fuse-archive** to use the exact
UID, GID, and Unix permission bits stored within the archive for each item. This
includes support for special bits such as **SUID**, **SGID**, and **SVTX**
(sticky bit).

### Permission Masks (`-o dmask=M`, `-o fmask=M`)

You can apply an octal permission mask to directories (`dmask`) and files
(`fmask`). For example, `-o fmask=077` would remove all permissions for group
and others from files.

# LOG MESSAGES

**fuse-archive** records log messages to the system logger (**syslog**). These
messages can help troubleshoot issues, such as I/O errors or archives that
refuse to mount.

To read **fuse-archive**'s log messages on most Linux systems:

```
$ journalctl -t fuse-archive
```

Alternatively, you can run **fuse-archive** in the foreground with the `-f`
option to see log messages directly on your terminal.

By default, **fuse-archive** writes **INFO** and **ERROR** messages. You can
decrease the logging level to just **ERROR** messages with the `-o quiet`
option, or increase it to include **DEBUG** messages with the `-o verbose`
option.

## Redaction

To prevent sensitive file names from being recorded in the system logs, use the
`-o redact` option. When enabled, file paths in log messages will be replaced
with `(redacted)`.

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

$ umount mnt
```

For comparison, here are **archivemount**'s timings:

```
$ time archivemount zeroes-256mib.tar.gz mnt
real    0m0.581s

$ dd if=mnt/zeroes of=/dev/null status=progress
268435456 bytes (268 MB, 256 MiB) copied, 570.146 s, 471 kB/s

$ umount mnt
```

In this case, **fuse-archive** takes about the same time to load the archive as
**archivemount**, but it is **~700× faster** (0.83s vs. 570s) to copy out the
decompressed contents. This is because **fuse-archive** fully caches the archive
and does not use **archivemount**'s
[quadratic complexity algorithm](https://github.com/cybernoid/archivemount/issues/21).

# COMPARISON

Feature                   | **fuse-archive** | **mount-zip** | **archivemount**
:------------------------ | :--------------: | :-----------: | :--------------:
Read-Write Support        | ❌                | ❌             | ✅
Format Support            | Wide             | ZIP           | Wide
GPG Encryption            | ✅                | ❌             | ❌
Native ZIP Encryption     | ✅                | ✅             | ✅
Native 7Z/RAR Encryption  | ❌                | ❌             | ❌
Lazy Decompression        | ✅                | ✅             | ❌
Memory Caching            | ✅                | ✅             | ❌
Sparse File Detection     | ✅                | ❌             | ❌
Several Archives          | ✅                | ✅             | ❌
Automatic Mount Point     | ✅                | ✅             | ❌
Linear Complexity         | ✅                | ✅             | ❌

# RETURN VALUE

**0**
:   Success.

**1**
:   Generic error code for: missing command-line argument, too many command-line
    arguments, unknown option, mount point is not empty, etc.

**10**
:   Cannot create the mount point.

**11**
:   Cannot open the archive file.

**12**
:   Cannot create the cache file.

**13**
:   Cannot write to the cache file. This is most likely an indication that
    there is not enough temporary space.

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
