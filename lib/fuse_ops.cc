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

#include "fuse_ops.h"

#include <archive.h>
#include <archive_entry.h>
#include <fcntl.h>
#include <fuse.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cassert>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#include "common.h"
#include "file_descriptor.h"
#include "hashed_string.h"
#include "node.h"
#include "path.h"
#include "reader.h"
#include "tree.h"
#include "util.h"

namespace fuse_archive {
namespace {

struct FileHandle {
  Node* node = nullptr;
  Reader::Ptr reader;
};

// Returns the tree from the FUSE context.
Tree& GetTree() {
  auto const tree = static_cast<Tree*>(fuse_get_context()->private_data);
  assert(tree);
  return *tree;
}

// Finds a node by full path.
Node* FindNode(std::string_view const path) {
  return GetTree().FindNode(path);
}

// Gets file attributes.
int GetAttr(const char* const path,
#if FUSE_USE_VERSION >= 30
            Stat* const z,
            fuse_file_info* const fi) {
#else
            Stat* const z) {
  fuse_file_info* const fi = nullptr;
#endif
  const Node* n;

  if (fi) {
    FileHandle* const h = reinterpret_cast<FileHandle*>(fi->fh);
    assert(h);
    n = h->node;
    assert(n);
  } else {
    assert(path);
    n = FindNode(path);
    if (!n) {
      LOG(DEBUG) << "Cannot stat " << Path(path) << ": No such item";
      return -ENOENT;
    }
  }

  assert(n);
  assert(z);
  *z = n->GetStat();
  return 0;
}

// Gets extended attributes.
int GetXattr(const char* const path,
             const char* const xattr_name,
             char* const dst_ptr,
#if defined(__APPLE__) && FUSE_USE_VERSION < 30
             size_t const dst_len,
             uint32_t) {
#else
             size_t const dst_len) {
#endif
  assert(path);
  assert(xattr_name);

  const Node* const node = FindNode(path);
  if (!node) {
    LOG(ERROR) << "Cannot get xattr " << std::quoted(xattr_name) << " of "
               << Path(path) << ": No such file or directory";
    return -ENOENT;
  }

  const Node::Attributes& attributes = node->GetTarget()->attributes;

  if (attributes.empty()) {
    // The node has no extended attributes.
    LOG(DEBUG) << *node << " has no xattr " << std::quoted(xattr_name);
    return -ENODATA;
  }

  const HashedString* const key = GetUniqueOrNull(xattr_name);
  if (!key) {
    // No extended attribute has ever been recorded with the given name.
    LOG(DEBUG) << *node << " has no xattr " << std::quoted(xattr_name);
    return -ENODATA;
  }

  auto const it = std::ranges::find(attributes, key, &Node::Attribute::key);
  if (it == attributes.end()) {
    // The node has some extended attributes, but none matching the given name.
    LOG(DEBUG) << *node << " has no xattr " << std::quoted(xattr_name);
    return -ENODATA;
  }

  assert(it->key->string == xattr_name);
  const std::string& value = it->value;

  if (dst_len > 0) {
    assert(dst_ptr);
    if (dst_len < value.size()) {
      LOG(ERROR) << "Cannot get xattr " << std::quoted(xattr_name) << " of "
                 << *node << ": The destination buffer of " << dst_len
                 << " bytes is too small: Needs at least " << value.size()
                 << " bytes";
      return -ERANGE;
    }

    std::copy_n(value.data(), value.size(), dst_ptr);
  }

  if (value.size() > std::numeric_limits<int>::max()) {
    LOG(ERROR) << "Cannot get xattr " << std::quoted(xattr_name) << " of "
               << *node << ": The value is " << value.size()
               << " bytes long, which is greater than MAX_INT";
    return -E2BIG;
  }

  LOG(DEBUG) << "Get xattr " << std::quoted(xattr_name) << " of " << *node
             << " -> " << value.size() << " bytes";

  return static_cast<int>(value.size());
}

// Lists extended attributes.
int ListXattr(const char* const path,
              char* const dst_ptr,
              size_t const dst_len) {
  assert(path);

  const Node* const node = FindNode(path);
  if (!node) {
    LOG(ERROR) << "Cannot list xattrs of " << Path(path)
               << ": No such file or directory";
    return -ENOENT;
  }

  const Node::Attributes& attributes = node->GetTarget()->attributes;

  size_t total_bytes = 0;
  if (dst_len == 0) {
    // Compute required buffer size.
    for (const Node::Attribute& a : attributes) {
      const std::string& key = a.key->string;
      total_bytes += key.size() + 1;
    }
  } else {
    assert(dst_ptr);
    std::span<char> dst(dst_ptr, dst_len);

    for (const Node::Attribute& a : attributes) {
      const std::string& key = a.key->string;
      const size_t n = key.size() + 1;

      if (dst.size() < n) {
        LOG(ERROR) << "Cannot list " << attributes.size() << " xattrs of "
                   << *node << ": The destination buffer of " << dst_len
                   << " bytes is too small";
        return -ERANGE;
      }

      // Copy the NUL terminator as well.
      std::copy_n(key.c_str(), n, dst.data());
      dst = dst.subspan(n);
      total_bytes += n;
    }
  }

  if (total_bytes > std::numeric_limits<int>::max()) {
    LOG(ERROR) << "Cannot list " << attributes.size() << " xattrs of " << *node
               << ": The list is " << total_bytes
               << " bytes long, which is greater than MAX_INT";
    return -E2BIG;
  }

  LOG(DEBUG) << "List " << attributes.size() << " xattrs of " << *node << " -> "
             << total_bytes << " bytes";

  return static_cast<int>(total_bytes);
}

// Reads the target of a symbolic link.
int ReadLink(const char* const path, char* const buf, size_t const size) {
  assert(path);
  assert(buf);
  assert(size > 1);

  const Node* const n = FindNode(path);
  if (!n) {
    LOG(ERROR) << "Cannot read link " << Path(path) << ": No such item";
    return -ENOENT;
  }

  const Node* const t = n->GetTarget();
  assert(t);

  if (t->GetType() != FileType::Symlink) {
    LOG(ERROR) << "Cannot read link " << *n << ": Not a symlink";
    return -ENOLINK;
  }

  snprintf(buf, size, "%s", t->symlink.c_str());
  return 0;
}

// Opens a file.
int Open(const char* const path, fuse_file_info* const fi) try {
  assert(path);

  Node* const n = FindNode(path);
  if (!n) {
    LOG(ERROR) << "Cannot open " << Path(path) << ": No such item";
    return -ENOENT;
  }

  Node* const t = n->GetTarget();
  assert(t);

  if (t->IsDir()) {
    LOG(ERROR) << "Cannot open " << *n << ": It is a directory";
    return -EISDIR;
  }

  assert(t->index_within_archive > 0);

  Cache const cache = GetTree().GetOptions().cache;
  if (cache == Cache::Full && t->cache_offset < 0) {
    LOG(ERROR) << "Cannot open " << *n << ": No cached data";
    return -EIO;
  }

  assert(fi);
  static_assert(sizeof(fi->fh) >= sizeof(FileHandle*));
  fi->fh = reinterpret_cast<uintptr_t>(new FileHandle{.node = n});

  int const fd_count = ++t->fd_count;
  assert(fd_count > 0);
  if (fd_count == 1) {
    LOG(DEBUG) << "Opened " << *n;
  } else {
    LOG(DEBUG) << "Opened " << *n << " (" << fd_count
               << " file descriptors currently open)";
  }

  return 0;
} catch (...) {
  LOG(DEBUG) << "Caught exception";
  return -EIO;
}

// Reads from an opened file.
int Read(const char*,
         char* const dst_ptr,
         size_t const dst_len,
         off_t offset,
         fuse_file_info* const fi) try {
  if (offset < 0 || dst_len > std::numeric_limits<int>::max()) {
    return -EINVAL;
  }

  std::span dst(dst_ptr, dst_len);

  assert(fi);
  FileHandle* const h = reinterpret_cast<FileHandle*>(fi->fh);
  assert(h);

  Node* const node = h->node;
  assert(node);
  Node* const t = node->GetTarget();
  assert(t);

  i64 const size = t->size;
  assert(size >= 0);

  i64 const remaining = size - offset;
  if (remaining <= 0) {
    // No data past the end of a file.
    return 0;
  }

  if (dst.size() > remaining) {
    // No data past the end of a file.
    dst = dst.first(static_cast<ssize_t>(remaining));
  }

  if (dst.empty()) {
    return 0;
  }

  Tree& tree = GetTree();
  Cache const cache = tree.GetOptions().cache;

  if (cache == Cache::Lazy) {
    tree.CacheUpTo(*t, offset + dst.size());
    assert(t->cache_offset >= 0);
  }

  if (cache != Cache::None) {
    assert(t->cache_offset >= 0);
    offset += t->cache_offset;

    // Read data from the cache file.
    ssize_t const n = pread(tree.GetCacheFd(), dst.data(), dst.size(), offset);
    if (n < 0) {
      int const e = errno;
      PLOG(ERROR) << "Cannot read " << dst.size()
                  << " bytes from cache at offset " << offset;
      return -e;
    }

    assert(n <= dst.size());
    return n;
  }

  // Not using the cache. Read directly from the archive.
  Reader::Ptr& r = h->reader;
  if (r) {
    assert(r->descriptor == t->descriptor);
    assert(r->index_within_archive == t->index_within_archive);

    if (offset < r->GetBufferOffset()) {
      // libarchive is designed for streaming access, not random access. If we
      // need to seek backwards, there's more work to do.
      LOG(DEBUG) << *r << " cannot jump " << r->offset_within_entry - offset
                 << " bytes backwards from offset " << r->offset_within_entry
                 << " to " << offset;
      r.reset();
    } else if (offset > r->offset_within_entry + r->rolling_buffer_size) {
      LOG(DEBUG) << *r << " might have to jump "
                 << offset - r->offset_within_entry
                 << " bytes forwards from offset " << r->offset_within_entry
                 << " to " << offset;
      r.reset();
    }
  }

  if (!r) {
    r = tree.GetReader(t->descriptor, t->index_within_archive, offset);
  }

  assert(r);
  assert(r->index_within_archive == t->index_within_archive);
  assert(r->offset_within_entry <= offset + r->rolling_buffer_size);

  ssize_t n = r->Read(offset, dst);
  assert(n >= 0);
  assert(n <= dst.size());
  dst = dst.subspan(n);

  // Fill end of buffer with NUL bytes in case of premature EOF.
  // This is a workaround for
  // https://github.com/libarchive/libarchive/issues/1194.
  // See https://github.com/google/fuse-archive/issues/40.
  std::ranges::fill(dst, '\0');
  n += dst.size();

  return static_cast<int>(n);
} catch (...) {
  LOG(DEBUG) << "Caught exception";
  return -EIO;
}

// Releases an opened file.
int Release(const char*, fuse_file_info* const fi) {
  assert(fi);
  FileHandle* const h = reinterpret_cast<FileHandle*>(fi->fh);
  assert(h);

  Node* const n = h->node;
  assert(n);
  Node* const t = n->GetTarget();
  assert(t);

  int const fd_count = --t->fd_count;
  assert(fd_count >= 0);

  delete h;

  if (fd_count > 0) {
    LOG(DEBUG) << "Closed " << *n << " (" << fd_count
               << " file descriptors are still open)";
  } else {
    LOG(DEBUG) << "Closed " << *n;

    Cache const cache = GetTree().GetOptions().cache;
    if (cache == Cache::Lazy) {
      // Put the reader into the recycle bin.
      t->reader = nullptr;
    }
  }

  return 0;
}

// Opens a directory.
int OpenDir(const char* const path, fuse_file_info* const fi) {
  assert(path);

  const Node* const n = FindNode(path);
  if (!n) {
    LOG(ERROR) << "Cannot open " << Path(path) << ": No such item";
    return -ENOENT;
  }

  if (!n->IsDir()) {
    LOG(ERROR) << "Cannot open " << *n << ": Not a directory";
    return -ENOTDIR;
  }

  assert(fi);
  static_assert(sizeof(fi->fh) >= sizeof(Node*));
  fi->fh = reinterpret_cast<uintptr_t>(n);

#if FUSE_USE_VERSION >= 30
  fi->cache_readdir = true;
#endif

  return 0;
}

// Reads a directory.
int ReadDir(const char*,
            void* const buf,
            fuse_fill_dir_t const filler,
            off_t,
#if FUSE_USE_VERSION >= 30
            fuse_file_info* const fi,
            fuse_readdir_flags const flags) try {
#else
            fuse_file_info* const fi) try {
#endif
  assert(filler);
  assert(fi);

  const Node* const n = reinterpret_cast<const Node*>(fi->fh);
  assert(n);
  assert(n->IsDir());

#if FUSE_USE_VERSION >= 30
  const bool plus = (flags & FUSE_READDIR_PLUS) != 0;
#else
  const bool plus = true;
#endif

  const auto add = [buf, filler, n, plus](const char* const name,
                                          const Stat* const st) {
#if FUSE_USE_VERSION >= 30
    const fuse_fill_dir_flags flags =
        plus ? FUSE_FILL_DIR_PLUS : fuse_fill_dir_flags(0);
    if (filler(buf, name, st, 0, flags)) {
#else
    if (filler(buf, name, st, 0)) {
#endif
      LOG(ERROR) << "Cannot list items in " << *n << ": Cannot allocate memory";
      throw std::bad_alloc();
    }
  };

  Stat z;
  auto const f = [&z, plus](const Node& n) {
    return plus ? &(z = n.GetStat()) : nullptr;
  };

  Timer const timer;

  add(".", f(*n));
  add("..", n->IsRoot() ? nullptr : f(*n->parent));

  for (const Node& child : n->children) {
    add(child.name.c_str(), f(child));
  }

  LOG(DEBUG) << "List " << *n << " -> " << n->children.size() << " items in "
             << timer;

  return 0;
} catch (const std::bad_alloc&) {
  return -ENOMEM;
}

// Gets file system statistics.
int StatFs(const char*, StatVfs* const z) {
  assert(z);

  Tree& tree = GetTree();

  z->f_bsize = block_size;
  z->f_frsize = block_size;
  z->f_blocks = tree.GetBlockCount();
  z->f_bfree = 0;
  z->f_bavail = 0;
  z->f_files = tree.GetInodeCount();
  z->f_ffree = 0;
  z->f_favail = 0;
  z->f_flag = ST_RDONLY;
  z->f_namemax = NAME_MAX;

  LOG(DEBUG) << "Got filesystem stats";

  return 0;
}

#if FUSE_USE_VERSION >= 30
// Initializes the file system.
void* Init(fuse_conn_info*, fuse_config* const cfg) {
  assert(cfg);
  // Respect inode numbers.
  cfg->use_ino = true;
  cfg->nullpath_ok = true;
  cfg->direct_io = GetTree().GetOptions().direct_io;

  LOG(DEBUG) << "Initialized FUSE server";

  return fuse_get_context()->private_data;
}

// Find next data or hole.
off_t Seek(const char*,
           off_t const offset,
           int const whence,
           fuse_file_info* const fi) {
  assert(fi);

  const FileHandle* const h = reinterpret_cast<const FileHandle*>(fi->fh);
  assert(h);
  const Node* const n = h->node;
  assert(n);

  LOG(DEBUG) << "Seeking " << *n << " with whence = " << Whence(whence)
             << " and offset = " << offset;

  const Node* const t = n->GetTarget();

  i64 const last_hole_start = t->GetSizeToLastHole();

  Holes::const_iterator const it =
      std::ranges::upper_bound(t->holes, offset, std::less<i64>(), &Hole::to);

  switch (whence) {
    case SEEK_DATA:
      if (offset < 0) {
        return -EINVAL;
      }

      if (offset >= last_hole_start) {
        // offset is in terminal hole
        LOG(DEBUG) << "Past the start of the last hole";
        return -ENXIO;
      }

      if (it != t->holes.end() && it->from <= offset) {
        assert(offset < it->to);
        // offset is located in a non-terminal hole
        LOG(DEBUG) << "In " << *it;
        return it->to;
      }

      LOG(DEBUG) << "In Data";
      return offset;

    case SEEK_HOLE:
      if (offset < 0) {
        return -EINVAL;
      }

      if (offset >= t->size) {
        // offset is past the end of the file
        LOG(DEBUG) << "Past the end of the file";
        return -ENXIO;
      }

      if (offset >= last_hole_start) {
        // offset is in terminal hole
        LOG(DEBUG) << "In the last hole";
        return offset;
      }

      if (it == t->holes.end()) {
        // offset is data before the terminal hole
        LOG(DEBUG) << "In Data before the last hole";
        return last_hole_start;
      }

      assert(it != t->holes.end());
      assert(offset < it->to);

      if (it->from <= offset) {
        // offset is located in a hole
        LOG(DEBUG) << "In " << *it;
        return offset;
      }

      // offset is before a hole
      assert(offset < it->from);
      LOG(DEBUG) << "In Data before " << *it;
      return it->from;
  }

  LOG(ERROR) << "Cannot seek " << *n << " with whence = " << Whence(whence)
             << " and offset = " << offset;

  return -EINVAL;
}
#endif

}  // namespace

fuse_operations GetFuseOperations() {
  return {
      .getattr = GetAttr,
      .readlink = ReadLink,
      .open = Open,
      .read = Read,
      .statfs = StatFs,
      .release = Release,
      .getxattr = GetXattr,
      .listxattr = ListXattr,
      .opendir = OpenDir,
      .readdir = ReadDir,
#if FUSE_USE_VERSION >= 30
      .init = Init,
      .lseek = Seek,
#else
      .flag_nullpath_ok = true,
      .flag_nopath = true,
#endif
  };
}

}  // namespace fuse_archive
