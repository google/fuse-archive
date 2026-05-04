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

#ifndef LIB_TREE_H
#define LIB_TREE_H

#include <memory>
#include <string>
#include <vector>

#include <boost/intrusive/unordered_set.hpp>

#include "common.h"
#include "node.h"
#include "util.h"

#include <boost/intrusive/list.hpp>

namespace fuse_archive {

namespace bi = boost::intrusive;

struct Reader;

// Hard link to resolve.
struct Hardlink {
  i64 index_within_archive;
  std::string source_path;
  std::string target_path;
};

class Tree {
 public:
  // Creates an empty virtual file system tree.
  Tree() = default;

  // Destroys the tree and all its nodes.
  ~Tree() = default;

  // Finds a node in the tree using a pre-computed path hash.
  Node* FindNode(const HashedStringView& path);

  // Finds a node in the tree by its full absolute path.
  Node* FindNode(std::string_view path);

  // Returns a warm reader from the recycle bin or creates a new one,
  // positioned at the requested entry and offset.
  Reader::Ptr GetReader(ArchiveDescriptor* descriptor,
                        i64 want_index_within_archive,
                        i64 want_offset_within_entry);

  // Scans the provided archives and populates the virtual file system tree.
  void Load(std::span<const std::string> archives);

  // Sets the options and password for the virtual filesystem.
  void SetOptions(const Options& options) { options_ = options; }

  // Returns the current options for the virtual filesystem.
  const Options& GetOptions() const { return options_; }

  // Returns the cache file descriptor.
  const FileDescriptor& GetCacheFd() const { return cache_fd_; }

  // Sets the cache file descriptor.
  void SetCacheFd(FileDescriptor fd);

  // Returns the current size of the cache file.
  i64 GetCacheSize() const { return cache_size_; }

  // Reads and caches data for the given regular file node from its source
  // archive into the global cache file, up to the specified size.
  //
  // Preconditions:
  // - `want_cached_size <= node.size` (the total decompressed size of the
  // file).
  // - `node` must represent a valid regular file within an archive.
  //
  // Postconditions:
  // - The uncompressed data up to `want_cached_size` is written to
  // `g_cache_fd`.
  // - `node.cached_size` and `node.cache_offset` are updated.
  // - Global block counts are adjusted based on the new cached data.
  //
  // Throws ExitCode::CANNOT_WRITE_CACHE in case of an I/O error.
  void CacheUpTo(Node& node, i64 want_cached_size);

  // Returns the total number of nodes (files and directories) in the tree.
  size_t GetNodeCount() const { return nodes_by_path_.size(); }

  // Returns the total number of 512-byte blocks used by the entire tree.
  i64 GetBlockCount() const { return block_count_; }

  // Returns the total number of unique inodes in the tree.
  i64 GetInodeCount() const { return inode_count_; }

 private:
  friend class TreeTest;
  friend struct Reader;

  // Returns true if entries of the given type should be ignored during loading.
  bool ShouldSkip(FileType ft) const;

  // Verifies that a raw archive (e.g. .gz) only contains one entry.
  void CheckRawArchive(Reader& r) const;

  // Normalizes an archive entry path to be used within the virtual tree.
  void GetNormalizedEntryPath(const Reader& r, std::string* path) const;

  // Processes a single archive entry and adds it to the tree.
  void ProcessEntry(Reader& r, std::string& path, Node* local_root);

  // Checks for name collisions and renames the node if necessary (e.g. "foo
  // (1)").
  Node* RenameIfCollision(Node::Ptr node);

  // Returns a directory node for the given path, creating it and its parents if
  // missing.
  Node* GetOrCreateDirNode(std::string_view path);

  // Resolves all pending hardlink entries saved during the Load process.
  void ResolveHardlinks();

  // Increases the hash table bucket count if the load factor is too high.
  void RehashIfNecessary();

  // Removes a node from the path-based lookup index.
  void Deindex(Node& node);

  // Adds a node to the path-based lookup index.
  void Reindex(Node& node);

  // Optimizes the tree by collapsing redundant single-child directory
  // hierarchies.
  void Trim(Node& a);

  // Hashing logic for the intrusive unordered_set of nodes.
  struct GetHash {
    size_t operator()(const HashedStringView& hsv) const { return hsv.hash; }
    size_t operator()(const Node& n) const { return n.path_hash; }
  };

  // Equality logic for the intrusive unordered_set of nodes.
  struct HasSamePath {
    bool operator()(const Node& a, const Node& b) const {
      return a.path_hash == b.path_hash && a.parent == b.parent &&
             a.name == b.name;
    }

    bool operator()(const HashedStringView& hsv, const Node& n) const {
      return hsv.hash == n.path_hash && hsv.string.size() == n.path_length &&
             n.HasPath(hsv.string);
    }
  };

  using NodesByPathBase =
      bi::unordered_set<Node,
                        bi::member_hook<Node, Node::ByPath, &Node::by_path>,
                        bi::constant_time_size<true>,
                        bi::power_2_buckets<true>,
                        bi::compare_hash<false>,
                        bi::equal<HasSamePath>,
                        bi::hash<GetHash>>;

  // Specialized container for fast path-to-node lookup.
  struct NodesByPath : NodesByPathBase {
    using NodesByPathBase::NodesByPathBase;
    ~NodesByPath();
  };

  // The root of the virtual filesystem.
  Node* root_ = nullptr;

  // Filesystem configuration and password state.
  Options options_;
  std::string password_;
  int password_count_ = 0;
  bool password_checked_ = false;

  // Cache state.
  FileDescriptor cache_fd_;
  i64 cache_size_ = 0;

  // Environmental constants captured at tree creation.
  uid_t const uid_ = getuid();
  gid_t const gid_ = getgid();
  time_t const now_ = SystemClock::to_time_t(SystemClock::now());

  // Statistics for the entire tree.
  i64 block_count_ = 1;
  i64 inode_count_ = 1;

  // Collection of archives that form the virtual filesystem.
  std::vector<ArchiveDescriptor> archives_;

  // Temporary storage for hardlinks found during Load(), resolved at the end.
  std::vector<Hardlink> hardlinks_;

  // Collection of warm Reader instances ready for reuse.
  struct RecycledReaders : bi::list<Reader> {
    ~RecycledReaders() { clear_and_dispose(std::default_delete<Reader>()); }
  };

  RecycledReaders recycled_readers_;

  // Storage for the intrusive hash table buckets.
  using Bucket = NodesByPath::bucket_type;
  using Buckets = std::vector<Bucket>;
  Buckets buckets_{1 << 4};
  NodesByPath nodes_by_path_{{buckets_.data(), buckets_.size()}};
};

}  // namespace fuse_archive

#endif  // LIB_TREE_H
