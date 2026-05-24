// Copyright 2021 The Fuse-Archive Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef LIB_COMMON_H
#define LIB_COMMON_H

#include <archive.h>
#include <archive_entry.h>
#include <sys/types.h>

#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "file_descriptor.h"
#include "util.h"

namespace fuse_archive {

// Possible caching strategies.
enum class Cache {
  None,  // No caching.
  Lazy,  // Incremental caching.
  Full,  // Full caching.
};

struct Options {
  unsigned int dmask = 0022;
  unsigned int fmask = 0022;
  int max_filter_count = 1;

  int force = 0;
  int merge = 1;
  int trim = 1;
  int dirs = 1;
  int specials = 1;
  int symlinks = 1;
  int holes = 1;
  int hardlinks = 1;
  int xattrs = 1;
  int bidding = 1;
  int enforce_permissions = 0;

#if FUSE_USE_VERSION >= 30
  int direct_io = 0;
#endif

  Cache cache = Cache::Full;
  int memcache = 0;
  int redact = 0;
};

// We support 'cooked' archive files (e.g. foo.tar.gz or foo.zip) but also what
// libarchive calls 'raw' files (e.g. foo.gz), which are compressed but not
// explicitly an archive (a collection of files). libarchive can still present
// it as an implicit archive containing 1 file.
enum class ArchiveFormat : int {
  NONE = 0,
  RAW = ARCHIVE_FORMAT_RAW,
};

// Formats an ArchiveFormat for logging output.
std::ostream& operator<<(std::ostream& out, ArchiveFormat f);

// An open archive file descriptor with other archive metadata.
struct ArchiveDescriptor {
  // Command line argument naming the archive file.
  std::string path;

  // Archive name without its extension.
  std::string name_without_extension;

  // File descriptor of the opened archive file.
  FileDescriptor fd;

  // Size of this archive file.
  i64 size = 0;

  // Format of this archive.
  ArchiveFormat format = ArchiveFormat::NONE;

  // Number of decompression or decoding filters (e.g. `gz`, `bz2`, `br`, `uu`,
  // `b64`).
  int filter_count = 0;

  // Is there an archive format that requires caching and random access to the
  // decompressed data?
  bool is_seekable_format = false;
};

enum class FileType : mode_t {
  BlockDevice = S_IFBLK,  // Block-oriented device
  CharDevice = S_IFCHR,   // Character-oriented device
  Directory = S_IFDIR,    // Directory
  Fifo = S_IFIFO,         // FIFO or pipe
  File = S_IFREG,         // Regular file
  Socket = S_IFSOCK,      // Socket
  Symlink = S_IFLNK,      // Symbolic link
};

// Returns the FileType corresponding to the given POSIX file mode bits.
FileType GetFileType(mode_t mode);

// Formats a FileType for logging output.
std::ostream& operator<<(std::ostream& out, FileType t);

using Archive = struct archive;
using Entry = struct archive_entry;

// Custom deleter for libarchive handles to ensure proper resource cleanup.
struct ArchiveDeleter {
  void operator()(Archive* const a) const { archive_read_free(a); }
};

using ArchivePtr = std::unique_ptr<Archive, ArchiveDeleter>;

}  // namespace fuse_archive

#endif  // LIB_COMMON_H
