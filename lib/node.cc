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

#include "node.h"

#include <sys/stat.h>

#include <algorithm>
#include <cassert>
#include <limits>
#include <ostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/functional/hash.hpp>

#include "common.h"
#include "path.h"
#include "reader.h"
#include "tree.h"
#include "util.h"

namespace fuse_archive {

void Node::AddChild(Node* const child) {
  assert(child);
  assert(!child->parent);
  assert(IsDir());
  assert(!hardlink_target);
  assert(nlink >= 2);
  // Count one "block" for each directory entry.
  size += block_size;
  nlink += child->IsDir();
  child->parent = this;
  children.push_back(*child);
}

// Recomputes this Node's path length and hash.
void Node::ComputePathHash() {
  path_length = 0;
  path_hash = 0;

  if (!IsRoot()) {
    path_length = parent->path_length;
    path_hash = parent->path_hash;
    if (!parent->IsRoot()) {
      ++path_length;
      boost::hash_combine(path_hash, '/');
    }
  }

  path_length += name.size();
  for (char const c : name) {
    boost::hash_combine(path_hash, c);
  }
}

// Returns the number of blocks used by this node.
i64 Node::GetBlockCount() const {
  if (size <= 0) {
    return 0;
  }

  i64 const size = GetSizeToLastHole();
  i64 const n = size / block_size + (size % block_size != 0) - saved_blocks;
  return std::max<i64>(0, n);
}

Stat Node::GetStat() const {
  Stat z = {};
  assert((nlink == 0) == (hardlink_target != nullptr));
  z.st_nlink = GetTarget()->nlink;
  assert(z.st_nlink > 0);
  z.st_ino = ino;
  z.st_mode = mode;
  z.st_uid = uid;
  z.st_gid = gid;
  z.st_size = size;
  z.st_blksize = block_size;
  z.st_blocks = GetBlockCount();
  z.st_rdev = dev;

#if __APPLE__
  z.st_atimespec = atime;
  z.st_mtimespec = mtime;
  z.st_ctimespec = ctime;
#else
  z.st_atim = atime;
  z.st_mtim = mtime;
  z.st_ctim = ctime;
#endif

  return z;
}

off_t Node::SparseSeek(off_t const offset, int const whence) const {
  const Node* const t = GetTarget();
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
        return -ENXIO;
      }

      if (it != t->holes.end() && it->from <= offset) {
        assert(offset < it->to);
        // offset is located in a non-terminal hole
        return it->to;
      }

      return offset;

    case SEEK_HOLE:
      if (offset < 0) {
        return -EINVAL;
      }

      if (offset >= t->size) {
        // offset is past the end of the file
        return -ENXIO;
      }

      if (offset >= last_hole_start) {
        // offset is in terminal hole
        return offset;
      }

      if (it == t->holes.end()) {
        // offset is data before the terminal hole
        return last_hole_start;
      }

      if (offset < it->from) {
        // offset is in data between holes
        return it->from;
      }

      // offset is in a non-terminal hole
      return offset;

    default:
      return -EINVAL;
  }
}

// Gets the full absolute path of this node.
std::string Node::GetPath() const {
  if (IsRoot()) {
    assert(name == "/");
    return "/";
  }

  std::vector<const Node*> nodes;
  nodes.reserve(32);

  size_t n = 0;
  const Node* node = this;
  do {
    assert(!node->IsRoot());
    nodes.push_back(node);
    n += node->name.size() + 1;
    node = node->parent;
  } while (!node->IsRoot());

  assert(node);
  assert(node->IsRoot());
  assert(node->name == "/");

  std::string path;
  path.reserve(n);

  do {
    assert(!nodes.empty());
    path += '/';
    path += nodes.back()->name;
    nodes.pop_back();
  } while (!nodes.empty());

  assert(nodes.empty());
  assert(path.size() == n);
  return path;
}

bool Node::HasPath(std::string_view path) const {
  const Node* node = this;

  if (!node->IsRoot()) {
    while (true) {
      if (!path.ends_with(node->name)) {
        return false;
      }

      path.remove_suffix(node->name.size());
      node = node->parent;
      if (node->IsRoot()) {
        break;
      }

      if (!path.ends_with('/')) {
        return false;
      }

      path.remove_suffix(1);
    }
  }

  assert(node->IsRoot());
  return path == node->name;
}

// If this node is a directory which only has one child which is a directory
// as well, then this method returns a pointer to this child. Otherwise it
// returns a null pointer.
Node* Node::GetUniqueChildDirectory() {
  if (!IsDir()) {
    // LOG(DEBUG) << *this << " is not a dir";
    return nullptr;
  }

  Node::Children::iterator const it = children.begin();
  if (it == children.end()) {
    // LOG(DEBUG) << *this << " has no children";
    return nullptr;
  }

  if (std::next(it) != children.end()) {
    // LOG(DEBUG) << *this << " has more than one child";
    return nullptr;
  }

  if (!it->IsDir()) {
    // LOG(DEBUG) << *it << " is not a dir";
    return nullptr;
  }

  return &*it;
}

std::ostream& operator<<(std::ostream& out, const Node& n) {
  out << n.GetType() << " [" << n.ino;
  if (n.hardlink_target) {
    out << "->" << n.hardlink_target->ino;
  }
  out << "]";
  if (n.index_within_archive > 0) {
    out << " index [" << n.index_within_archive << "]";
  }
  return out << " " << Path(n.GetPath());
}

ino_t Node::count = 0;

}  // namespace fuse_archive
