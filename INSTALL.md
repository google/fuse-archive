# How to Build

## Prerequisites

To build **fuse-archive**, you need the following libraries:

*   [Boost Intrusive](https://www.boost.org)
*   [libfuse >= 2.7](https://github.com/libfuse/libfuse)
*   [libarchive >= 3.7](https://libarchive.org)

On Debian systems, you can get these libraries by installing the following
packages:

```sh
$ sudo apt install libboost-container-dev libfuse-dev libarchive-dev
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

*   [Python >= 3.8](https://www.python.org)

On Debian systems, you can get these tools by installing the following packages:

```sh
$ sudo apt install python3
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
