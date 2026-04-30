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

#include "tree.h"

#include <fcntl.h>
#include <algorithm>
#include <climits>
#include <vector>

#include <boost/functional/hash.hpp>

#include "common.h"
#include "path.h"
#include "reader.h"
#include "util.h"

namespace fuse_archive {
namespace {

bool IsAsciiDigit(char const c) {
  return c >= '0' && c <= '9';
}

void RemoveNumericSuffix(std::string& s) {
  size_t i = s.size();
  if (i == 0 || s[--i] != ')') {
    return;
  }

  if (i == 0 || !IsAsciiDigit(s[--i])) {
    return;
  }

  while (i > 0 && IsAsciiDigit(s[i - 1])) {
    --i;
  }

  if (i == 0 || s[--i] != '(') {
    return;
  }

  if (i == 0 || s[--i] != ' ') {
    return;
  }

  s.resize(i);
}

struct Segment {
  std::string_view name;
  size_t path_length;
  size_t path_hash;
};

using Segments = std::vector<Segment>;

Segments GetSegments(std::string_view const path) {
  Segments segments;
  segments.reserve(std::ranges::count(path, '/'));
  size_t path_hash = 0;
  assert(path.starts_with('/'));

  size_t i = 0;
  size_t segment_begin = i + 1;
  boost::hash_combine(path_hash, path[i]);

  while (++i < path.size()) {
    char const c = path[i];
    if (c == '/') {
      assert(segment_begin < i);
      segments.emplace_back(path.substr(segment_begin, i - segment_begin), i,
                            path_hash);
      segment_begin = i + 1;
    }
    boost::hash_combine(path_hash, c);
  }

  assert(segment_begin < i);
  segments.emplace_back(path.substr(segment_begin, i - segment_begin), i,
                        path_hash);
  return segments;
}

}  // namespace

Tree::NodesByPath::~NodesByPath() {
#ifndef NDEBUG
  for (Node& n : *this) {
    n.children.clear();
  }
#endif
  clear_and_dispose(std::default_delete<Node>());
}

Node* Tree::FindNode(const HashedStringView& path) {
  auto const it = nodes_by_path_.find(path, nodes_by_path_.hash_function(),
                                      nodes_by_path_.key_eq());
  return it == nodes_by_path_.end() ? nullptr : &*it;
}

Node* Tree::FindNode(std::string_view const path) {
  return FindNode(HashedStringView(Path(path).WithoutTrailingSeparator()));
}

void Tree::RehashIfNecessary() {
  if (nodes_by_path_.size() > buckets_.size()) {
    Buckets new_buckets(buckets_.size() * 2);
    buckets_.swap(new_buckets);
    nodes_by_path_.rehash({buckets_.data(), buckets_.size()});
  }
}

Node* Tree::RenameIfCollision(Node::Ptr node) {
  assert(node);
  auto const [pos, ok] = nodes_by_path_.insert(*node);
  if (ok) {
    RehashIfNecessary();
    return node.release();  // Now owned by |nodes_by_path_|.
  }

  // There is a name collision
  LOG(DEBUG) << *node << " conflicts with " << *pos;

  // Extract filename extension
  std::string& f = node->name;
  std::string::size_type const e =
      node->IsDir() ? f.size() : Path(f).ExtensionPosition();
  std::string const ext(f, e);
  f.resize(e);
  RemoveNumericSuffix(f);
  std::string const base = f;

  // Add a number before the extension
  for (int* i = nullptr;;) {
    std::string const suffix =
        StrCat(" (", std::to_string(i ? ++*i + 1 : 1), ")", ext);
    f.assign(base, 0, Path(base).TruncationPosition(NAME_MAX - suffix.size()));
    f += suffix;

    node->ComputePathHash();

    auto const [pos2, ok2] = nodes_by_path_.insert(*node);
    if (ok2) {
      LOG(DEBUG) << "Resolved conflict for " << *node;
      RehashIfNecessary();
      return node.release();  // Now owned by |nodes_by_path_|.
    }

    LOG(DEBUG) << *node << " conflicts with " << *pos2;
    if (!i) {
      i = &pos2->collision_count;
    }
  }
}

// Gets or creates the directory hierarchy for the given path.
//
// Preconditions:
// - `path` must be an absolute path (starting with '/').
//
// Postconditions:
// - Returns a pointer to the Node corresponding to `path`.
// - If the Node did not exist, it and any missing ancestor directories are
//   created and indexed.
Node* Tree::GetOrCreateDirNode(std::string_view path) {
  if (!options_.dirs || path.size() <= 1) {
    return root_;
  }

  Segments const segments = GetSegments(path);
  Node* node = nullptr;
  size_t i = segments.size();

  // Find the deepest directory that already exists.
  while (!node && i > 0) {
    const Segment& segment = segments[--i];
    node = FindNode(HashedStringView(path.substr(0, segment.path_length),
                                     segment.path_hash));
  }

  Node::Ptr to_rename;
  if (!node) {
    assert(i == 0);
    node = root_;
    --i;
  } else if (!node->IsDir()) {
    // There is an existing node but it is not a directory. We'll rename it
    // because we need a directory at this location.
    LOG(DEBUG) << "Found conflicting " << *node << " while creating Dir "
               << Path(path);

    // Remove it from nodes_by_path_, in order to insert it again later with a
    // different name.
    nodes_by_path_.erase(nodes_by_path_.iterator_to(*node));
    to_rename.reset(node);
    node = node->parent;
    --i;
  }

  assert(node);
  assert(node->IsDir());

  // Create and index all missing directories.
  while (++i < segments.size()) {
    const Segment& segment = segments[i];
    Node::Ptr child(new Node{
        .mtime = {.tv_sec = now_},
        .atime = {.tv_sec = now_},
        .ctime = {.tv_sec = now_},
        .path_length = segment.path_length,
        .path_hash = segment.path_hash,
        .name = std::string(segment.name),
        .uid = uid_,
        .gid = gid_,
        .mode = static_cast<mode_t>(S_IFDIR | (0777 & ~options_.dmask)),
        .nlink = 2,
    });

    inode_count_ += 1;
    block_count_ += 1;
    node->AddChild(child.get());

#ifndef NDEBUG
    child->ComputePathHash();
    assert(child->path_length == segment.path_length);
    assert(child->path_hash == segment.path_hash);
#endif

    node = RenameIfCollision(std::move(child));
  }

  if (to_rename) {
    // Re-insert the conflicting node with a new name.
    RenameIfCollision(std::move(to_rename));
  }

  return node;
}

void Tree::ResolveHardlinks() {
  Timer const timer;

  for (const Hardlink& entry : hardlinks_) {
    Node* target = FindNode(entry.target_path);
    if (!target) {
      LOG(DEBUG) << "Skipped hard link [" << entry.index_within_archive << "] "
                 << Path(entry.source_path) << ": Cannot find target "
                 << Path(entry.target_path);
      continue;
    }

    // A hard link to a hard link should point to the original target.
    while (target->hardlink_target) {
      target = target->hardlink_target;
    }

    if (target->IsDir()) {
      LOG(DEBUG) << "Skipped hard link [" << entry.index_within_archive << "] "
                 << Path(entry.source_path) << ": Target "
                 << Path(entry.target_path) << " is a directory";
      continue;
    }

    if (const Node* const source = FindNode(entry.source_path)) {
      if (source->GetTarget() == target) {
        LOG(DEBUG) << "Skipped duplicate hard link ["
                   << entry.index_within_archive << "] "
                   << Path(entry.source_path) << " -> " << *target;
        continue;
      }
    }

    auto const [parent_path, name] = Path(entry.source_path).Split();

    // Get or create the parent node.
    Node* const parent = GetOrCreateDirNode(parent_path);
    assert(parent);
    assert(parent->IsDir());

    // Create the node for this entry.
    Node::Ptr node(new Node{
        .mtime = target->mtime,
        .atime = target->atime,
        .ctime = target->ctime,
        .index_within_archive = target->index_within_archive,
        .ino = target->ino,
        .size = target->size,
        .cache_offset = target->cache_offset,
        .cached_size = target->cached_size,
        .last_hole_start = target->last_hole_start,
        .saved_blocks = target->saved_blocks,
        .dev = target->dev,
        .descriptor = target->descriptor,
        .hardlink_target = target->GetTarget(),
        .name = std::string(name.empty() ? "data" : name),
        .symlink = target->symlink,
        .uid = target->uid,
        .gid = target->gid,
        .mode = target->mode,
        .nlink = 0,  // treated specially in hardlinks
        .holes = target->holes,
        .attributes = target->attributes,
    });

    if (options_.hardlinks) {
      // Then the new node and the target node share the same inode number.
      target->nlink++;
    } else {
      // Then the new Node gets its own inode number.
      node->ino = ++Node::count;
      // And it counts as an extra separate inode.
      node->nlink = 1;
      inode_count_++;
      block_count_ += node->GetBlockCount();
      // And it's not a hardlink anymore.
      node->hardlink_target = nullptr;
    }

    block_count_ += 1;
    parent->AddChild(node.get());
    node->ComputePathHash();
    Node* const n = RenameIfCollision(std::move(node));

    LOG(DEBUG) << "Resolved hard link [" << entry.index_within_archive << "] "
               << Path(n->GetPath()) << " -> " << *target;
  }

  hardlinks_.clear();
  LOG(DEBUG) << "Resolved hard links in " << timer;
}

bool Tree::ShouldSkip(FileType const ft) const {
  switch (ft) {
    case FileType::BlockDevice:
    case FileType::CharDevice:
    case FileType::Fifo:
    case FileType::Socket:
      return !options_.specials;

    case FileType::Symlink:
      return !options_.symlinks;

    case FileType::Directory:
      return !options_.dirs;

    case FileType::File:
      return false;
  }

  return true;
}

void Tree::CheckRawArchive(Reader& r) const {
  if (r.descriptor->format != ArchiveFormat::RAW) {
    return;
  }

  if (r.descriptor->filter_count == 0) {
    LOG(ERROR) << "Archive " << Path(r.descriptor->path)
               << " is a regular file but not a recognized archive";
    throw ExitCode::UNKNOWN_ARCHIVE_FORMAT;
  }

  if (r.index_within_archive > 1) {
    LOG(ERROR) << "A raw archive (" << Path(r.descriptor->path)
               << ") should only contain 1 entry, but at least "
               << r.index_within_archive << " were found";
    throw ExitCode::UNKNOWN_ARCHIVE_FORMAT;
  }

  if (r.descriptor->filter_count > 0 && options_.cache != Cache::Full) {
    LOG(WARNING) << "Using the lazycache or the nocache option with this kind "
                    "of archive can result in poor performance";
  }
}

void Tree::GetNormalizedEntryPath(const Reader& r,
                                  std::string* const path) const {
  assert(path);
  const char* const s =
      archive_entry_pathname_utf8(r.entry) ?: archive_entry_pathname(r.entry);

  LOG(DEBUG) << "GetNormalizedEntryPath: s=" << (s ? s : "nullptr");

  if (!s || !*s) {
    LOG(ERROR) << "Archive entry " << r.index_within_archive << " of "
               << Path(r.descriptor->path) << " has no name";
    throw ExitCode::INVALID_ARCHIVE_HEADER;
  }

  Path(s).NormalizeAppend(path);
}

void Tree::ProcessEntry(Reader& r, std::string& path, Node* const local_root) {
  Entry* const e = r.entry;
  i64 const i = r.index_within_archive;
  mode_t const mode = archive_entry_mode(e);
  FileType const ft = GetFileType(mode);
  assert(path.starts_with('/'));
  size_t const original_path_size = path.size();
  GetNormalizedEntryPath(r, &path);

  if (r.descriptor->format == ArchiveFormat::RAW &&
      r.descriptor->filter_count > 0) {
    path.resize(original_path_size);
    Path(r.descriptor->name_without_extension).NormalizeAppend(&path);
  }

  assert(path.starts_with('/'));

  if (const char* const s =
          archive_entry_hardlink_utf8(e) ?: archive_entry_hardlink(e)) {
    // Entry is a hard link.
    if (options_.hardlinks) {
      // Save it for further resolution.
      hardlinks_.push_back({
          .index_within_archive = i,
          .source_path = path,
          .target_path = Path(s).Normalized(path.substr(0, original_path_size)),
      });
    } else {
      LOG(DEBUG) << "Skipped hard link [" << i << "] " << Path(path) << " -> "
                 << Path(s);
    }
    return;
  }

  if (ShouldSkip(ft)) {
    LOG(DEBUG) << "Skipped entry " << i << ": It is a " << ft;
    return;
  }

  // Is this entry a directory?
  if (ft == FileType::Directory) {
    assert(options_.dirs);
    Node* const node = GetOrCreateDirNode(path);
    assert(node);

    if (archive_entry_mtime_is_set(e)) {
      node->mtime = {.tv_sec = archive_entry_mtime(e),
                     .tv_nsec = archive_entry_mtime_nsec(e)};
    }
    if (archive_entry_atime_is_set(e)) {
      node->atime = {.tv_sec = archive_entry_atime(e),
                     .tv_nsec = archive_entry_atime_nsec(e)};
    }
    if (archive_entry_ctime_is_set(e)) {
      node->ctime = {.tv_sec = archive_entry_ctime(e),
                     .tv_nsec = archive_entry_ctime_nsec(e)};
    }

    if (options_.default_permissions) {
      node->uid = archive_entry_uid(e);
      node->gid = archive_entry_gid(e);
      mode_t const pbits = 07777;
      node->mode &= ~pbits;
      node->mode |= mode & pbits & ~options_.dmask;
    }

    LOG(DEBUG) << "Created " << *node;
    return;
  }

  if (path.size() == original_path_size) {
    Path::Append(&path, "data");
  }

  auto const [parent_path, name] = Path(path).Split();

  // Get or create the parent directory node.
  Node* const parent =
      options_.dirs ? GetOrCreateDirNode(parent_path) : local_root;
  assert(parent);
  assert(parent->IsDir());

  Node::Ptr node(new Node{
      .mtime = {.tv_sec = now_},
      .atime = {.tv_sec = now_},
      .ctime = {.tv_sec = now_},
      .index_within_archive = i,
      .descriptor = r.descriptor,
      .name = std::string(name),
      .uid = uid_,
      .gid = gid_,
      .mode = static_cast<mode_t>(static_cast<mode_t>(ft) |
                                  (0666 & ~options_.fmask)),
  });

  if (archive_entry_mtime_is_set(e)) {
    node->mtime = {.tv_sec = archive_entry_mtime(e),
                   .tv_nsec = archive_entry_mtime_nsec(e)};
  }
  if (archive_entry_atime_is_set(e)) {
    node->atime = {.tv_sec = archive_entry_atime(e),
                   .tv_nsec = archive_entry_atime_nsec(e)};
  }
  if (archive_entry_ctime_is_set(e)) {
    node->ctime = {.tv_sec = archive_entry_ctime(e),
                   .tv_nsec = archive_entry_ctime_nsec(e)};
  }

  inode_count_ += 1;
  block_count_ += 1;

  if (options_.default_permissions) {
    node->uid = archive_entry_uid(e);
    node->gid = archive_entry_gid(e);
    mode_t const pbits = 07777;
    node->mode &= ~pbits;
    node->mode |= mode & pbits & ~options_.fmask;
  } else if (mode_t const xbits = 0111; (mode & xbits) != 0) {
    // Adjust the access bits if the file is executable.
    node->mode |= xbits & ~options_.fmask;
  }

  Node* const n = node.get();
  parent->AddChild(n);
  n->ComputePathHash();
  RenameIfCollision(std::move(node));

  // Block or Char Device.
  if (ft == FileType::BlockDevice || ft == FileType::CharDevice) {
    n->dev = archive_entry_rdev(e);
    LOG(DEBUG) << "Created " << *n;
    return;
  }

  // Symbolic link.
  if (ft == FileType::Symlink) {
    if (const char* const s =
            archive_entry_symlink_utf8(e) ?: archive_entry_symlink(e)) {
      n->symlink = s;
      n->size = n->symlink.size();
      block_count_ += n->GetBlockCount();
    }
    LOG(DEBUG) << "Created " << *n;
    return;
  }

  // File or Special file.
  if (ft != FileType::File) {
    LOG(DEBUG) << "Created " << *n;
    return;
  }

  // Regular file.
  if (options_.cache == Cache::Full) {
    // Cache file data.
    n->size = archive_entry_size(e);
    i64 const offset = cache_size_;
    cache_size_ = r.CacheEntryData(cache_fd_, cache_size_, n);
    // Now that CacheEntryData has succeeded without throwing an exception, we
    // can mark this file as cached.
    n->cache_offset = offset;
    n->cached_size = n->size = cache_size_ - offset;
    n->last_hole_start = cache_size_;
  } else {
    n->size = r.GetEntrySize();
  }

  // Extract extended attributes.
  if (options_.xattrs) {
    if (int const n_xattrs = archive_entry_xattr_reset(e)) {
      n->attributes.reserve(n_xattrs);
      const char* key;
      const void* value;
      size_t size;
      while (archive_entry_xattr_next(e, &key, &value, &size) == ARCHIVE_OK) {
        n->attributes.push_back({
            .key = GetOrCreateUnique(key),
            .value = std::string(static_cast<const char*>(value), size),
        });
      }
    }
  }

  r.CheckPassword();
  block_count_ += n->GetBlockCount();

  LOG(DEBUG) << "Created " << *n;
}

void Tree::Load(std::span<const std::string> const archives) {
  assert(archives_.empty());

  archives_.reserve(archives.size());
  for (const std::string& archive_path : archives) {
    if (archive_path.empty()) {
      LOG(ERROR) << "Empty archive file name";
      throw ExitCode::GENERIC_FAILURE;
    }

    archives_.push_back({.path = archive_path});
  }

  // Check the archives before starting.
  for (ArchiveDescriptor& archive : archives_) {
    try {
      if (archive.fd = FileDescriptor(open(archive.path.c_str(), O_RDONLY));
          !archive.fd.IsValid()) {
        PLOG(ERROR) << "Cannot open " << Path(archive.path);
        throw ExitCode::CANNOT_OPEN_ARCHIVE;
      }

      if (Stat z; fstat(archive.fd, &z) != 0) {
        PLOG(ERROR) << "Cannot access " << Path(archive.path);
        throw ExitCode::CANNOT_OPEN_ARCHIVE;
      } else if (FileType const ft = GetFileType(z.st_mode);
                 ft != FileType::File) {
        LOG(ERROR) << "Archive " << Path(archive.path)
                   << " is not a regular file: It is a " << ft;
        throw ExitCode::CANNOT_OPEN_ARCHIVE;
      } else {
        archive.size = z.st_size;
        LOG(DEBUG) << "File size of " << Path(archive.path) << " is "
                   << archive.size << " bytes";
      }
    } catch (ExitCode const error) {
      archive.fd.Close();
      if (!options_.force) {
        throw;
      }
      LOG(DEBUG) << "Suppressed error " << error << " because of -o force";
    }
  }

  // Create the root directory.
  assert(!root_);
  {
    Node::Ptr root(new Node{
        .mtime = {.tv_sec = now_},
        .atime = {.tv_sec = now_},
        .ctime = {.tv_sec = now_},
        .name = "/",
        .uid = uid_,
        .gid = gid_,
        .mode = static_cast<mode_t>(S_IFDIR | (0777 & ~options_.dmask)),
        .nlink = 2,
    });
    root->ComputePathHash();
    root_ = RenameIfCollision(std::move(root));
  }

  std::string path;
  for (ArchiveDescriptor& archive : archives_) {
    if (!archive.fd.IsValid()) {
      continue;
    }

    LOG(DEBUG) << "Loading " << Path(archive.path) << "...";

    try {
      std::unique_ptr<Reader> r = std::make_unique<Reader>(&archive, *this);
      r->should_print_progress = LOG_IS_ON(INFO) && archive.size > 0;

      if (options_.cache == Cache::Full && archive.is_seekable_format) {
        // ZIP format should be opened in seekable mode, which requires knowing
        // the decompressed size upfront. Caching the whole ZIP file into the
        // cache file accomplishes this.
        if (!r->NextEntry()) {
          LOG(ERROR) << "Reached EOF while expecting a unique entry";
          throw ExitCode::INVALID_ARCHIVE_HEADER;
        }

        FileDescriptor fd = CreateCacheFile();
        CheckCacheFile(fd);
        i64 const size = r->CacheEntryData(fd, 0);

        r.reset();
        std::string const name = std::move(archive.name_without_extension);
        archive = ArchiveDescriptor{
            .path = name,
            .name_without_extension = name,
            .fd = std::move(fd),
            .size = size,
            .format = archive.format,
            .filter_count = archive.filter_count,
            .is_seekable_format = false,
        };
        r = std::make_unique<Reader>(&archive, *this);
        r->should_print_progress = LOG_IS_ON(INFO) && archive.size > 0;
      }

      path = "/";
      Node* local_root = root_;
      if (!options_.merge) {
        // Create a directory node for this archive.
        Node::Ptr archive_node(new Node{
            .mtime = {.tv_sec = now_},
            .atime = {.tv_sec = now_},
            .ctime = {.tv_sec = now_},
            .name = archive.name_without_extension,
            .uid = uid_,
            .gid = gid_,
            .mode = static_cast<mode_t>(S_IFDIR | (0777 & ~options_.dmask)),
            .nlink = 2,
        });

        inode_count_ += 1;
        block_count_ += 1;
        root_->AddChild(archive_node.get());
        archive_node->ComputePathHash();
        local_root = RenameIfCollision(std::move(archive_node));

        path += local_root->name;
        assert(local_root->GetPath() == path);
        LOG(DEBUG) << "Created " << *local_root;
      }

      size_t const original_path_size = path.size();
      while (r->NextEntry()) {
        CheckRawArchive(*r);

        try {
          path.resize(original_path_size);
          ProcessEntry(*r, path, local_root);
        } catch (ExitCode const error) {
          if (!options_.force) {
            throw;
          }
          LOG(DEBUG) << "Suppressed error " << error << " because of -o force";
        }
      }

      ResolveHardlinks();

      if (g_latest_log_is_ephemeral) {
        LOG(INFO) << "Loading " << Path(r->descriptor->path) << "... "
                  << ProgressMessage(100);
      }
    } catch (ExitCode const error) {
      if (!options_.force) {
        throw;
      }
      LOG(DEBUG) << "Suppressed error " << error << " because of -o force";
    }

    if (options_.cache == Cache::Full) {
      // Archive file is not needed anymore since everything has been cached.
      archive.fd.Close();
    }
  }

  // Trim the top level if necessary.
  if (options_.trim) {
    if (options_.merge) {
      Trim(*root_);
    } else {
      for (Node& c : root_->children) {
        Trim(c);
      }
    }
  }
}

void Tree::Deindex(Node& node) {
  for (Node& c : node.children) {
    Deindex(c);
  }

  nodes_by_path_.erase(nodes_by_path_.iterator_to(node));
}

void Tree::Reindex(Node& node) {
  node.ComputePathHash();

  [[maybe_unused]] bool const ok = nodes_by_path_.insert(node).second;
  assert(ok);

  for (Node& c : node.children) {
    Reindex(c);
  }
}

// Collapses directory |a| into its only child if that child is also a
// directory. Recurses if possible.
void Tree::Trim(Node& a) {
  Node* p = a.GetUniqueChildDirectory();
  if (!p) {
    return;
  }

  Deindex(*p);
  a.children.clear();

  while (Node* const q = p->GetUniqueChildDirectory()) {
    p->children.clear();
    p = q;
  }

  LOG(DEBUG) << "Collapsing " << *p << " into " << a;

  assert(a.IsDir());
  assert(p->IsDir());
  a.ino = p->ino;
  a.uid = p->uid;
  a.gid = p->gid;
  a.mode = p->mode;
  a.size = p->size;
  a.atime = p->atime;
  a.mtime = p->mtime;
  a.ctime = p->ctime;
  a.nlink = p->nlink;
  assert(!a.hardlink_target);
  assert(!p->hardlink_target);
  a.children = std::move(p->children);
  assert(p->children.empty());

  for (Node& c : a.children) {
    assert(c.parent == p);
    c.parent = &a;
    Reindex(c);
  }

  LOG(INFO) << "Collapsed " << *p << " into " << a;
  LOG(INFO) << "Use `-o notrim` if you want to keep these intermediate "
               "directories";

  while (p != &a) {
    block_count_ -= 1;
    inode_count_ -= 1;
    Node* const q = p->parent;
    delete p;
    p = q;
  }
}

Reader::Ptr Tree::GetReader(ArchiveDescriptor* const descriptor,
                            i64 const want_index_within_archive,
                            i64 const want_offset_within_entry) {
  assert(want_index_within_archive > 0);
  assert(want_offset_within_entry >= 0);

  // Find the closest warm Reader that is below or at the requested position.
  Reader* best = nullptr;
  for (Reader& r : recycled_readers_) {
    if (r.descriptor == descriptor &&
        (r.descriptor->filter_count > 0 ||
         r.index_within_archive == want_index_within_archive) &&
        std::pair(r.index_within_archive, r.GetBufferOffset()) <=
            std::pair(want_index_within_archive, want_offset_within_entry) &&
        (!best ||
         std::pair(best->index_within_archive, best->offset_within_entry) <
             std::pair(r.index_within_archive, r.offset_within_entry))) {
      best = &r;
    }
  }

  Reader::Ptr r;
  if (best) {
    r.reset(best);
    recycled_readers_.erase(recycled_readers_.iterator_to(*best));
    LOG(DEBUG) << "Reusing " << *r << " currently at offset "
               << r->offset_within_entry << " of entry "
               << r->index_within_archive;
  } else {
    r.reset(new Reader(descriptor, *this));
  }

  assert(r);
  r->AdvanceIndex(want_index_within_archive);
  r->AdvanceOffset(want_offset_within_entry);

  return r;
}

void Tree::CacheUpTo(Node& node, i64 const want_cached_size) {
  if (want_cached_size <= node.cached_size) {
    return;
  }

  assert(want_cached_size <= node.size);
  LOG(DEBUG) << "Caching " << node << " from " << node.cached_size << " to "
             << want_cached_size;

  Timer const timer;
  if (node.cache_offset < 0) {
    // No data in cache for this file yet.
    // Reserve a range of bytes in the cache file.
    assert(node.cached_size == 0);
    node.cache_offset = cache_size_;
    assert(node.last_hole_start < 0);
    node.last_hole_start = node.cache_offset;
    cache_size_ += node.size;
    cache_fd_.Truncate(cache_size_);

    LOG(DEBUG) << "Increased cache file size by " << node.size << " bytes to "
               << cache_size_ << " bytes";
  }

  assert(node.cache_offset >= 0);

  if (!node.reader) {
    node.reader =
        GetReader(node.descriptor, node.index_within_archive, node.cached_size);
  }

  assert(node.reader);
  assert(node.reader->descriptor == node.descriptor);
  assert(node.reader->index_within_archive == node.index_within_archive);

  i64 const old_cached_size = node.cached_size;
  block_count_ -= node.GetBlockCount();

  FileDescriptor::HoleCallback on_hole;
  if (options_.holes) {
    on_hole = [&node](i64 from, i64 to) {
      from -= node.cache_offset;
      to -= node.cache_offset;
      node.saved_blocks +=
          node.holes.emplace_back(from, to).GetSavedBlocks(node.size);
    };
  }

  while (node.cached_size < want_cached_size) {
    char buff[64 * 1024];

    ssize_t const n = node.reader->Read(node.cached_size, buff);
    assert(n >= 0);
    if (n == 0) {
      LOG(ERROR) << "Unexpected EOF while caching " << node;
      break;
    }

    node.last_hole_start = cache_fd_.WriteBytesAndSkipHoles(
        std::string_view(buff, n), node.cache_offset + node.cached_size,
        node.last_hole_start, on_hole);
    node.cached_size += n;
    assert(node.reader->offset_within_entry == node.cached_size);
  }

  if (node.cached_size == node.size) {
    i64 const file_end = node.cache_offset + node.size;
    if (node.last_hole_start < file_end) {
      if (on_hole) {
        on_hole(node.last_hole_start, file_end);
      }
      node.last_hole_start = file_end;
    }
  }

  block_count_ += node.GetBlockCount();

  LOG(DEBUG) << "Cached " << node.cached_size - old_cached_size << " bytes of "
             << node << " up to " << node.cached_size << " in " << timer;
}

void Tree::SetCacheFd(FileDescriptor fd) {
  assert(!cache_fd_.IsValid());
  assert(cache_size_ == 0);
  cache_fd_ = std::move(fd);
  assert(cache_fd_.IsValid());
  CheckCacheFile(cache_fd_);
}

}  // namespace fuse_archive
