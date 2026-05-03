// Copyright 2026 The Fuse-Archive Authors.
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

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "lib/file_descriptor.h"
#include "lib/hashed_string.h"
#include "lib/node.h"
#include "lib/path.h"
#include "lib/reader.h"
#include "lib/tree.h"
#include "lib/util.h"

namespace fuse_archive {

class NodeTest : public ::testing::Test {
 protected:
  Node node_;
};

TEST_F(NodeTest, GetBlockCountEmpty) {
  node_.size = 0;
  EXPECT_EQ(node_.GetBlockCount(), 0);
}

TEST_F(NodeTest, GetBlockCountDense) {
  node_.size = 1000;
  // (1000 + 511) / 512 = 2 blocks
  EXPECT_EQ(node_.GetBlockCount(), 2);

  node_.size = 512;
  EXPECT_EQ(node_.GetBlockCount(), 1);
}

TEST_F(NodeTest, GetBlockCountSparse) {
  node_.size = 2000;
  node_.saved_blocks = 1;
  // (2000 + 511) / 512 = 4 blocks. 4 - 1 = 3.
  EXPECT_EQ(node_.GetBlockCount(), 3);
}

TEST_F(NodeTest, GetBlockCountTerminalHole) {
  node_.size = 2000;
  node_.cached_size = 2000;  // Fully cached
  node_.cache_offset = 0;
  node_.last_hole_start = 1000;  // Terminal hole starts at 1000
  node_.saved_blocks = 0;        // Internal holes

  // GetSizeToLastHole() should return last_hole_start - cache_offset = 1000.
  // (1000 + 511) / 512 = 2 blocks.
  EXPECT_EQ(node_.GetBlockCount(), 2);
}

class FileDescriptorTest : public ::testing::Test {
 protected:
  FileDescriptor fd_;

  void SetUp() override {
    fd_ = CreateCacheFile(/*memcache=*/true);
    ASSERT_TRUE(fd_.IsValid());
  }
};

TEST_F(FileDescriptorTest, WriteAndTruncate) {
  std::string_view const data = "hello world";
  i64 const pos = fd_.Write(data, 0);
  EXPECT_EQ(pos, data.size());

  fd_.Truncate(5);
  EXPECT_EQ(lseek(fd_, 0, SEEK_END), 5);
}

TEST_F(FileDescriptorTest, WriteBytesAndSkipHoles) {
  std::vector<Hole> holes;
  auto on_hole = [&](i64 from, i64 to) { holes.emplace_back(from, to); };

  // Data < 1024 bytes (min_hole_size).
  std::string const small_nuls(500, '\0');
  std::string const data = "abc" + small_nuls + "def";
  i64 pos = fd_.WriteBytesAndSkipHoles(data, 0, 0, on_hole);

  EXPECT_EQ(pos, data.size());
  EXPECT_TRUE(holes.empty());

  // Data > 1024 bytes.
  std::string const large_nuls(2000, '\0');
  std::string const data2 = "ghj" + large_nuls + "klm";
  holes.clear();
  i64 const start_pos = pos;
  pos = fd_.WriteBytesAndSkipHoles(data2, start_pos, start_pos, on_hole);

  EXPECT_EQ(pos, start_pos + data2.size());
  ASSERT_EQ(holes.size(), 1);
  EXPECT_EQ(holes[0].from, start_pos + 3);
  EXPECT_EQ(holes[0].to, start_pos + 2003);
}

// TreeTest fixture provides access to private Tree members for testing.
class TreeTest : public ::testing::Test {
 protected:
  Tree tree_;

  void SetUp() override {
    Options options;
    options.dirs = true;
    options.hardlinks = true;
    options.cache = Cache::None;
    tree_.SetOptions(options);
    tree_.Load(std::vector<std::string>{});  // Initializes root_
  }

  // Wrapper methods to access private Tree members.
  Node* GetOrCreateDirNode(std::string_view path) {
    return tree_.GetOrCreateDirNode(path);
  }

  Node* RenameIfCollision(Node::Ptr node) {
    return tree_.RenameIfCollision(std::move(node));
  }

  void Trim(Node& node) { tree_.Trim(node); }

  void AddHardlink(i64 index, std::string source, std::string target) {
    tree_.hardlinks_.push_back({index, source, target});
  }

  void ResolveHardlinks() { tree_.ResolveHardlinks(); }

  static ArchiveDescriptor* GetArchive(Tree& tree, size_t i) {
    return &tree.archives_[i];
  }

  static size_t GetRecycledReaderCount(const Tree& tree) {
    return tree.recycled_readers_.size();
  }

  static Reader* GetFirstRecycledReader(Tree& tree) {
    return &tree.recycled_readers_.front();
  }
};

TEST_F(TreeTest, GetOrCreateDirNode) {
  Node* n1 = GetOrCreateDirNode("/foo/bar");
  ASSERT_NE(n1, nullptr);
  EXPECT_EQ(n1->name, "bar");
  EXPECT_TRUE(n1->IsDir());
  EXPECT_EQ(n1->GetPath(), "/foo/bar");

  Node* n2 = tree_.FindNode("/foo");
  ASSERT_NE(n2, nullptr);
  EXPECT_TRUE(n2->IsDir());
  EXPECT_EQ(n2->name, "foo");

  Node* n3 = GetOrCreateDirNode("/foo");
  EXPECT_EQ(n1->parent, n3);
  EXPECT_EQ(n2, n3);
}

TEST_F(TreeTest, RenameIfCollision) {
  Node::Ptr n1(new Node);
  n1->name = "file.txt";
  n1->mode = S_IFREG | 0644;
  n1->parent = tree_.FindNode("/");
  n1->ComputePathHash();

  Node* p1 = RenameIfCollision(std::move(n1));
  ASSERT_NE(p1, nullptr);
  EXPECT_EQ(p1->name, "file.txt");

  Node::Ptr n2(new Node);
  n2->name = "file.txt";
  n2->mode = S_IFREG | 0644;
  n2->parent = tree_.FindNode("/");
  n2->ComputePathHash();

  Node* p2 = RenameIfCollision(std::move(n2));
  ASSERT_NE(p2, nullptr);
  EXPECT_EQ(p2->name, "file (1).txt");
}

TEST_F(TreeTest, Trim) {
  // Create /a/b/c/file.txt
  Node* a = GetOrCreateDirNode("/a");
  Node* b = GetOrCreateDirNode("/a/b");
  Node* c = GetOrCreateDirNode("/a/b/c");

  Node::Ptr file(new Node);
  file->name = "file.txt";
  file->mode = S_IFREG | 0644;

  Node* f = file.get();
  c->AddChild(f);
  f->ComputePathHash();
  RenameIfCollision(std::move(file));

  // Before trim: a -> b -> c -> file.txt
  ASSERT_EQ(a->children.size(), 1);
  EXPECT_EQ(&*a->children.begin(), b);
  ASSERT_EQ(b->children.size(), 1);
  EXPECT_EQ(&*b->children.begin(), c);
  ASSERT_EQ(c->children.size(), 1);
  EXPECT_EQ(&*c->children.begin(), f);

  // Trim 'a'. It should collapse b and c into a.
  Trim(*a);

  ASSERT_EQ(a->children.size(), 1);
  Node* child = &*a->children.begin();
  EXPECT_EQ(child, f);
  EXPECT_EQ(f->parent, a);
  EXPECT_EQ(f->GetPath(), "/a/file.txt");
}

TEST_F(TreeTest, ResolveHardlinks) {
  // 1. Create a target node.
  Node* root = tree_.FindNode("/");
  Node::Ptr file(new Node{
      .ino = 100,
      .size = 1234,
      .name = "target",
      .uid = 1000,
      .gid = 1000,
      .mode = S_IFREG | 0644,
  });
  Node* t = file.get();
  root->AddChild(t);
  t->ComputePathHash();
  RenameIfCollision(std::move(file));

  // 2. Add a hardlink entry.
  AddHardlink(1, "/hl", "/target");

  // 3. Resolve.
  ResolveHardlinks();

  // 4. Verify.
  Node* hl = tree_.FindNode("/hl");
  ASSERT_NE(hl, nullptr);
  EXPECT_EQ(hl->hardlink_target, t);
  EXPECT_EQ(t->nlink, 2);
  EXPECT_EQ(hl->ino, t->ino);
  EXPECT_EQ(hl->size, t->size);
}

TEST_F(TreeTest, ReaderRecycling) {
  // Use a separate Tree to avoid collision with SetUp's Load.
  Tree local_tree;
  Options options;
  options.cache = Cache::None;
  local_tree.SetOptions(options);

  std::string const archive_path = "test/data/archive.tar";
  const std::string archives[] = {archive_path};
  local_tree.Load(archives);
  ArchiveDescriptor* desc = GetArchive(local_tree, 0);

  void* raw_ptr = nullptr;
  {
    Reader::Ptr r1 = local_tree.GetReader(desc, 1, 0);
    raw_ptr = r1.get();
    ASSERT_NE(raw_ptr, nullptr);
    EXPECT_EQ(GetRecycledReaderCount(local_tree), 0);
  }
  // r1 recycled.
  EXPECT_EQ(GetRecycledReaderCount(local_tree), 1);
  EXPECT_EQ(GetFirstRecycledReader(local_tree), raw_ptr);

  {
    Reader::Ptr r2 = local_tree.GetReader(desc, 1, 0);
    EXPECT_EQ(r2.get(), raw_ptr);
    EXPECT_EQ(GetRecycledReaderCount(local_tree), 0);
  }
}

TEST_F(TreeTest, ReaderBestMatch) {
  Tree local_tree;
  Options options;
  options.cache = Cache::None;
  local_tree.SetOptions(options);

  std::string const archive_path = "test/data/archive.tar";
  const std::string archives[] = {archive_path};
  local_tree.Load(archives);
  ArchiveDescriptor* desc = GetArchive(local_tree, 0);

  // 1. Create two readers at different positions in entry 2 (has data).
  Reader::Ptr r1 = local_tree.GetReader(desc, 2, 0);
  r1->AdvanceOffset(100);
  void* ptr1 = r1.get();

  Reader::Ptr r2 = local_tree.GetReader(desc, 2, 0);
  r2->AdvanceOffset(200);
  void* ptr2 = r2.get();

  // 2. Recycle them.
  r1.reset();
  r2.reset();
  ASSERT_EQ(GetRecycledReaderCount(local_tree), 2);

  // 3. Request reader for entry 2, offset 150.
  // Best match should be ptr2 (at 200), because it can serve 150 from its
  // rolling buffer and it is further ahead than ptr1 (at 100).
  // We keep 'best1' alive to keep ptr2 out of the pool.
  Reader::Ptr best1 = local_tree.GetReader(desc, 2, 150);
  EXPECT_EQ(best1.get(), ptr2);

  // 4. Request reader for entry 2, offset 250.
  // Best match should be ptr1 (at 100) now, because ptr2 is in use.
  {
    Reader::Ptr best2 = local_tree.GetReader(desc, 2, 250);
    EXPECT_EQ(best2.get(), ptr1);
  }
}

namespace {

TEST(Path, Normalized) {
  EXPECT_EQ(Path("").Normalized(), "/?");
  EXPECT_EQ(Path("/").Normalized(), "/");
  EXPECT_EQ(Path("///").Normalized(), "/");
  EXPECT_EQ(Path("foo").Normalized(), "/foo");
  EXPECT_EQ(Path("/foo").Normalized(), "/foo");
  EXPECT_EQ(Path("foo/").Normalized(), "/foo");
  EXPECT_EQ(Path("/foo/").Normalized(), "/foo");
  EXPECT_EQ(Path("foo//bar").Normalized(), "/foo/bar");
  EXPECT_EQ(Path("foo/./bar").Normalized(), "/foo/?/bar");
  EXPECT_EQ(Path("foo/../bar").Normalized(), "/foo/?/bar");
  EXPECT_EQ(Path("/foo/../bar").Normalized(), "/foo/?/bar");
  EXPECT_EQ(Path("../foo").Normalized(), "/foo");
  EXPECT_EQ(Path("./foo").Normalized(), "/foo");
  EXPECT_EQ(Path("foo/..").Normalized(), "/foo/?");
}

TEST(Path, ExtensionPosition) {
  EXPECT_EQ(Path("foo.tar.gz").ExtensionPosition(), 3);
  EXPECT_EQ(Path("foo.tar.bz2").ExtensionPosition(), 3);
  EXPECT_EQ(Path("foo.tar.xz").ExtensionPosition(), 3);
  EXPECT_EQ(Path("foo.zip").ExtensionPosition(), 3);
  EXPECT_EQ(Path("foo.1.tar.gz").ExtensionPosition(), 5);
  EXPECT_EQ(Path("foo").ExtensionPosition(), 3);
  EXPECT_EQ(Path("foo.").ExtensionPosition(), 4);
  EXPECT_EQ(Path(".foo").ExtensionPosition(), 4);
}

TEST(Path, Split) {
  auto [parent, base] = Path("/foo/bar").Split();
  EXPECT_EQ(parent, "/foo");
  EXPECT_EQ(base, "bar");

  std::tie(parent, base) = Path("foo").Split();
  EXPECT_EQ(parent, "");
  EXPECT_EQ(base, "foo");

  std::tie(parent, base) = Path("/").Split();
  EXPECT_EQ(parent, "/");
  EXPECT_EQ(base, "");
}

TEST(Path, Append) {
  std::string p = "/foo";
  Path::Append(&p, "bar");
  EXPECT_EQ(p, "/foo/bar");

  p = "/foo/";
  Path::Append(&p, "bar");
  EXPECT_EQ(p, "/foo/bar");

  p = "/foo";
  Path::Append(&p, "/bar");
  EXPECT_EQ(p, "/bar");
}

TEST(HashedString, Basic) {
  HashedStringView hsv("test");
  EXPECT_EQ(hsv.string, "test");
  EXPECT_EQ(hsv.hash, ComputeStringHash("test"));

  HashedString hs(hsv);
  EXPECT_EQ(hs.string, "test");
  EXPECT_EQ(hs.hash, hsv.hash);

  IsEqual eq;
  EXPECT_TRUE(eq(hs, hsv));
  EXPECT_TRUE(eq(hsv, hs));
  EXPECT_FALSE(eq(hs, HashedStringView("other")));
}

TEST(Util, ToLower) {
  EXPECT_EQ(ToLower("ABC"), "abc");
  EXPECT_EQ(ToLower("abc"), "abc");
  EXPECT_EQ(ToLower("123!"), "123!");
}

TEST(Util, SafeAdd) {
  EXPECT_EQ(SafeAdd(10, 20), 30);
  EXPECT_EQ(SafeAdd(0, 0), 0);
  EXPECT_THROW(SafeAdd(INT64_MAX, 1), ExitCode);
}

TEST(Util, HoleSavedBlocks) {
  // block_size is 512
  EXPECT_EQ(Hole(0, 512).GetSavedBlocks(), 1);
  EXPECT_EQ(Hole(0, 1024).GetSavedBlocks(), 2);
  EXPECT_EQ(Hole(1, 511).GetSavedBlocks(), 0);
  EXPECT_EQ(Hole(511, 513).GetSavedBlocks(), 0);
  EXPECT_EQ(Hole(0, 511).GetSavedBlocks(), 0);
  EXPECT_EQ(Hole(512, 1024).GetSavedBlocks(), 1);
}

}  // namespace
}  // namespace fuse_archive
