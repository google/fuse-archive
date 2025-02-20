# How to Build

## Prerequisites

To build **fuse-archive**, you need the following libraries:

*   [Boost Intrusive](https://www.boost.org)
*   [libfuse >= 3.1](https://github.com/libfuse/libfuse)
*   [libarchive >= 3.7](https://libarchive.org)

On Debian systems, you can get these libraries by installing the following
packages:

```sh
$ sudo apt install libboost-container-dev libfuse3-dev libarchive-dev
```

For compatibility reasons, **fuse-archive** can optionally use the old FUSE 2
library [libfuse >= 2.9](https://github.com/libfuse/libfuse). On Debian systems,
you can install FUSE 2 by installing the following package:

```sh
$ sudo apt install libfuse-dev
```

To build **fuse-archive**, you also need the following tools:

*   C++20 compiler (g++ or clang++)
*   [pkg-config](https://www.freedesktop.org/wiki/Software/pkg-config/)
*   [GNU make](https://www.gnu.org/software/make/)
*   [Pandoc](https://pandoc.org) to regenerate the man page

On Debian systems, you can get these tools by installing the following packages:

```sh
$ sudo apt install g++ pkg-config make pandoc
```

To test **fuse-archive**, you also need the following tools:

*   [Python 3](https://www.python.org)
*   [brotli](https://github.com/google/brotli)
*   [lrzip](https://github.com/ckolivas/lrzip)
*   [lzop](https://www.lzop.org/)

On Debian systems, you can get these tools by installing the following packages:

```sh
$ sudo apt install python3 brotli lrzip lzop
```

## Get the Source Code

```sh
$ git clone https://github.com/google/fuse-archive.git
$ cd fuse-archive
```

## Build **fuse-archive**

```sh
$ make
```

### With debugging assertions

```sh
$ DEBUG=1 make
```

### With FUSE 2

```sh
$ FUSE_MAJOR_VERSION=2 make
```

## Test **fuse-archive**

```sh
$ make check
```

## Install **fuse-archive**:

```sh
$ sudo make install
```

## Uninstall **fuse-archive**:

```sh
$ sudo make uninstall
```
