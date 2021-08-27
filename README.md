# Fuse-Archive

`fuse-archive` is a program that serves an archive or compressed file (e.g.
foo.tar, foo.tar.gz, foo.xz, foo.zip) as a
[FUSE](https://en.wikipedia.org/wiki/Filesystem_in_Userspace) file system.

It is similar to the [`fuse-zip`](https://bitbucket.org/agalanin/fuse-zip)
program but speaks a larger range of archive or compressed file formats.

It is similar to the
[`archivemount`](https://github.com/cybernoid/archivemount) program but can be
much faster (see the Performance section below) although it can only mount
read-only, not read-write.


## Build

    $ git clone https://github.com/google/fuse-archive.git
    $ g++ -O3 fuse-archive/src/main.cc `pkg-config libarchive fuse --cflags --libs` -o my-fuse-archive

On a Debian system, you may first need to install some dependencies:

    $ sudo apt install libarchive-dev libfuse-dev


## Performance

Create a single `.tar.gz` file that is 256 MiB decompressed and 255 KiB
compressed (the file just contains repeated 0x00 NUL bytes):

    $ truncate --size=256M zeroes
    $ tar cfz zeroes-256mib.tar.gz zeroes

`fuse-archive` timings:

    $ time ./my-fuse-archive zeroes-256mib.tar.gz ~/mnt
    real    0m0.010s
    $ dd if=~/mnt/zeroes of=/dev/null status=progress
    524288+0 records in
    524288+0 records out
    268435456 bytes (268 MB, 256 MiB) copied, 0.836048 s, 321 MB/s
    $ fusermount -u ~/mnt

`archivemount` timings:

    $ time archivemount      zeroes-256mib.tar.gz ~/mnt
    real    0m0.581s
    $ dd if=~/mnt/zeroes of=/dev/null status=progress
    268288512 bytes (268 MB, 256 MiB) copied, 569 s, 471 kB/s
    524288+0 records in
    524288+0 records out
    268435456 bytes (268 MB, 256 MiB) copied, 570.146 s, 471 kB/s
    $ fusermount -u ~/mnt

Here, `fuse-archivemount` was 58x faster (0.010s vs 0.581s) to bind the
mountpoint and daemonize, and 682x faster (0.836048s vs 570.146s) to copy out
the decompressed contents.

For the second ratio, the key difference is that `fuse-archive` does not use
`archivemount`'s [quadratic complexity
algorithm](https://github.com/cybernoid/archivemount/issues/21).


## Disclaimer

This is not an official Google product, it is just code that happens to be
owned by Google.


---

Updated on August 2021.
