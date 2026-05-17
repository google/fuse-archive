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

#ifndef LIB_NODE_H
#define LIB_NODE_H

#include <sys/types.h>

#include <atomic>
#include <memory>
#include <ostream>
#include <string>
#include <string_view>
#include <vector>

#include <boost/intrusive/slist.hpp>
#include <boost/intrusive/unordered_set.hpp>

#include "common.h"
#include "hashed_string.h"
#include "reader.h"
#include "util.h"

namespace fuse_archive {

namespace bi = boost::intrusive;

class Tree;

// A node of the virtual file system: either a directory or a file.
struct Node {
  // Nodes are dynamically allocated and passed around by unique_ptr when
  // the ownership is transferred.
  using Ptr = std::unique_ptr<Node>;

  // Constants and settings shared by all nodes.
  static ino_t ino_count;

#ifdef NDEBUG
  using LinkMode = bi::link_mode<bi::normal_link>;
#else
  using LinkMode = bi::link_mode<bi::safe_link>;
#endif

  // --- 16-byte members (Highest alignment) ---

  timespec mtime;
  timespec atime;
  timespec ctime;

  // --- 8-byte members (Fixed size) ---

  // Index of the entry represented by this node in the archive, or 0 if it is
  // not directly represented in the archive (like any directory).
  i64 const index_within_archive = 0;

  // Inode-specific data.
  ino_t ino = ++ino_count;

  // Number of bytes of this file.
  i64 size = 0;

  // Where does the cached data start in the cache file?
  i64 cache_offset = -1;

  // How many bytes have been cached so far for this file?
  i64 cached_size = 0;

  // Position of the last recorded hole for this file in the cache file.
  i64 last_hole_start = -1;

  // Number of blocks saved by "holes" (sparse regions) in the file.
  i64 saved_blocks = 0;

  // Device number for special files.
  dev_t dev = 0;

  // --- Architecture-dependent members (8 bytes on 64-bit, 4 bytes on 32-bit)

  // File descriptor of the archive holding the entry represented by this node,
  // or nullptr if it is not directly represented in the archive (like any
  // directory).
  ArchiveDescriptor* const descriptor = nullptr;

  // If this Node is a hardlink, this points to the target node.
  Node* hardlink_target = nullptr;

  // Pointer to the parent node. Should be non null. The only exception is the
  // root directory which has a null parent pointer.
  Node* parent = nullptr;

  Reader::Ptr reader;

  size_t path_length = 0;
  size_t path_hash = 0;

  // --- Intrusive Hooks (8-24 bytes on 64-bit, 4-12 bytes on 32-bit) ---

  // Hook used to index Nodes by parent.
  using ByParent = bi::slist_member_hook<LinkMode>;
  ByParent by_parent;

  // Children of this node. The children are not sorted and their order is not
  // relevant. This collection doesn't own the children nodes. The |parent|
  // pointer of every child in |children| should point back to this node.
  using Children = bi::slist<Node,
                             bi::member_hook<Node, ByParent, &Node::by_parent>,
                             bi::constant_time_size<false>,
                             bi::linear<true>,
                             bi::cache_last<true>>;
  Children children;

  // Hook used to index Nodes by full path.
  using ByPath = bi::unordered_set_member_hook<LinkMode, bi::store_hash<false>>;
  ByPath by_path;

  // --- Remaining members (Strings and 4-byte types) ---

  // Name of this node in the context of its parent. This name should be a valid
  // and non-empty filename, and it shouldn't contain any '/' separator. The
  // only exception is the root directory, which is just named "/".
  std::string name;

  // Symbolic link target.
  std::string symlink;

  uid_t uid;
  gid_t gid;
  mode_t mode = 0;
  mutable nlink_t nlink = 1;

  // Number of entries whose name have initially collided with this node.
  int collision_count = 0;

  // Number of open file descriptors that are currently reading this file node.
  std::atomic<int> fd_count = 0;

  // List of holes in this sparse file.
  Holes holes;

  // Extended attributes.
  struct Attribute {
    const HashedString* key;
    std::string value;
  };

  using Attributes = std::vector<Attribute>;
  Attributes attributes;

  // Returns true if this node is the root directory of the virtual file system.
  bool IsRoot() const { return !parent; }

  // Returns the FileType (e.g. Regular file, Directory, Symlink) of this node.
  FileType GetType() const { return GetFileType(mode); }

  // Returns true if this node is a directory.
  bool IsDir() const { return S_ISDIR(mode); }

  // Adds a child node to this directory node.
  // This directory becomes the owner of the child's parent pointer.
  // Precondition: IsDir() is true.
  void AddChild(Node* child);

  // Recomputes this Node's path length and hash based on its name and its
  // parent's path length and hash. This is used for fast lookup by path.
  void ComputePathHash();

  // Returns the number of blocks used by this node in the virtual file system.
  // This accounts for the file size and any holes (sparse regions).
  i64 GetBlockCount() const;

  // Returns a pointer to the actual data node. If this node is a hardlink,
  // returns the target node; otherwise returns 'this'.
  const Node* GetTarget() const { return hardlink_target ?: this; }
  Node* GetTarget() { return hardlink_target ?: this; }

  // Returns the POSIX 'struct stat' representation of this node's metadata.
  Stat GetStat() const;

  // Returns the full absolute path of this node within the virtual file system.
  std::string GetPath() const;

  // Returns true if this node's full absolute path matches the given string.
  bool HasPath(std::string_view path) const;

  // If this node is a directory which only has one child which is also a
  // directory, returns a pointer to that child. Otherwise returns nullptr.
  // This is used for tree trimming/optimization.
  Node* GetUniqueChildDirectory();

  // Is the contents of this file fully cached?
  bool IsFullyCached() const { return cached_size == size; }

  i64 GetSizeToLastHole() const {
    return IsFullyCached() ? last_hole_start - cache_offset : size;
  }

  // Performs a sparse seek (SEEK_DATA or SEEK_HOLE) on this node.
  // Returns the new offset or a negative error code (e.g., -ENXIO, -EINVAL).
  off_t SparseSeek(off_t offset, int whence) const;
};

// Formats a Node for logging output (e.g. "File /path/to/file").
std::ostream& operator<<(std::ostream& out, const Node& n);

}  // namespace fuse_archive

#endif  // LIB_NODE_H
