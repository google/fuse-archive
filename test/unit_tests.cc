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

#include <fcntl.h>
#include <gtest/gtest.h>

#include <iostream>
#include <string>
#include <vector>

#include "lib/common.h"
#include "lib/file_descriptor.h"
#include "lib/hashed_string.h"
#include "lib/node.h"
#include "lib/path.h"
#include "lib/reader.h"
#include "lib/tree.h"
#include "lib/util.h"

#include "lib/fuse_ops.h"

#ifndef ENOATTR
#define ENOATTR ENODATA
#endif

namespace fuse_archive {

TEST(HashedStringTest, All) {
  // Should hit return nullptr if !g_unique_strings
  EXPECT_EQ(GetUniqueOrNull("uninitialized"), nullptr);

  GetOrCreateUnique("initialized");
  // Should hit return nullptr if it == g_unique_strings->cend()
  EXPECT_EQ(GetUniqueOrNull("missing"), nullptr);
  EXPECT_NE(GetUniqueOrNull("initialized"), nullptr);
}

class NodeTest : public ::testing::Test {
 protected:
  Node node_;
};

TEST_F(NodeTest, GetBlockCount) {
  node_.size = 0;
  EXPECT_EQ(node_.GetBlockCount(), 0);
  node_.size = 1000;
  EXPECT_EQ(node_.GetBlockCount(), 2);
  node_.saved_blocks = 1;
  EXPECT_EQ(node_.GetBlockCount(), 1);
  node_.size = 2000;
  node_.cached_size = 2000;
  node_.cache_offset = 0;
  node_.last_hole_start = 1000;
  node_.saved_blocks = 0;
  EXPECT_EQ(node_.GetBlockCount(), 2);
}

TEST_F(NodeTest, SparseSeek) {
  node_.size = 10000;
  node_.cache_offset = 0;
  node_.cached_size = 10000;
  node_.holes.emplace_back(2000, 4000);
  node_.last_hole_start = 8000;

  // Negative offset
  EXPECT_EQ(node_.SparseSeek(-1, SEEK_DATA), -EINVAL);
  EXPECT_EQ(node_.SparseSeek(-1, SEEK_HOLE), -EINVAL);

  EXPECT_EQ(node_.SparseSeek(0, SEEK_DATA), 0);
  EXPECT_EQ(node_.SparseSeek(2000, SEEK_DATA), 4000);
  EXPECT_EQ(node_.SparseSeek(8000, SEEK_DATA), -ENXIO);
  EXPECT_EQ(node_.SparseSeek(0, SEEK_HOLE), 2000);
  EXPECT_EQ(node_.SparseSeek(4000, SEEK_HOLE), 8000);
  EXPECT_EQ(node_.SparseSeek(8000, SEEK_HOLE), 8000);
  EXPECT_EQ(node_.SparseSeek(10000, SEEK_HOLE), -ENXIO);
  EXPECT_EQ(node_.SparseSeek(0, 999), -EINVAL);
}

TEST_F(NodeTest, Misc) {
  // HasPath coverage
  Node root;
  root.name = "/";
  Node dir;
  dir.name = "dir";
  dir.parent = &root;
  node_.name = "file";
  node_.parent = &dir;

  EXPECT_TRUE(node_.HasPath("/dir/file"));
  EXPECT_FALSE(node_.HasPath("/dir_file"));  // Missing / between components
  EXPECT_FALSE(node_.HasPath("/wrong/file"));
  EXPECT_FALSE(node_.HasPath("dir/file"));  // No leading slash

  // GetUniqueChildDirectory coverage
  node_.mode = S_IFREG | 0644;
  EXPECT_EQ(node_.GetUniqueChildDirectory(), nullptr);  // Not a directory
}

class TreeTest : public ::testing::Test {
 protected:
  Tree tree_;

  void SetUp() override {
    Options options;
    options.dirs = true;
    options.hardlinks = true;
    options.cache = Cache::None;
    tree_.SetOptions(options);
    tree_.Load(std::vector<std::string>{});
  }

  Node* RenameIfCollision(Node::Ptr node) {
    return tree_.RenameIfCollision(std::move(node));
  }
  bool ShouldSkip(FileType ft) { return tree_.ShouldSkip(ft); }
};

TEST_F(TreeTest, RenameIfCollision) {
  Node* root = tree_.FindNode("/");
  auto create_node = [&](const std::string& name) {
    Node::Ptr n(new Node);
    n->name = name;
    n->mode = S_IFREG | 0644;
    n->parent = root;
    n->ComputePathHash();
    return n;
  };
  Node* p1 = RenameIfCollision(create_node("file.txt"));
  EXPECT_EQ(p1->name, "file.txt");
  Node* p2 = RenameIfCollision(create_node("file.txt"));
  EXPECT_EQ(p2->name, "file (1).txt");
}

TEST_F(TreeTest, ShouldSkip) {
  Options options;
  options.specials = false;
  tree_.SetOptions(options);
  EXPECT_TRUE(ShouldSkip(FileType::BlockDevice));
  EXPECT_FALSE(ShouldSkip(FileType::File));
}

class ReaderTest : public ::testing::Test {
 protected:
  Tree tree_;

  void SetUp() override {
    try {
      Options options;
      options.cache = Cache::None;
      tree_.SetOptions(options);
      tree_.Load(std::vector<std::string>{"test/data/archive.tar"});
    } catch (ExitCode const& e) {
      std::cerr << "ReaderTest::SetUp failed with ExitCode: "
                << static_cast<int>(e) << std::endl;
      throw;
    }
  }

  ArchiveDescriptor* GetArchive(size_t i) { return &tree_.archives_[i]; }
};

TEST_F(ReaderTest, Advance) {
  ArchiveDescriptor* desc = GetArchive(0);
  Reader::Ptr r = tree_.GetReader(desc, 1, 0);

  // AdvanceIndex
  r->AdvanceIndex(7);
  EXPECT_EQ(r->index_within_archive, 7);

  // AdvanceOffset
  r->AdvanceOffset(100);
  EXPECT_EQ(r->offset_within_entry, 100);

  // Read from advanced offset
  std::vector<char> buf(100);
  EXPECT_EQ(r->Read(buf.data(), 100), 100);
  EXPECT_EQ(r->offset_within_entry, 200);
}

TEST_F(ReaderTest, RollingBuffer) {
  ArchiveDescriptor* desc = GetArchive(0);
  Reader::Ptr r = tree_.GetReader(desc, 7, 0);  // romeo.txt
  std::vector<char> b1(100), b2(100), b3(100);
  EXPECT_EQ(r->Read(b1.data(), 100), 100);
  EXPECT_EQ(r->Read(b2.data(), 100), 100);
  EXPECT_EQ(r->Read(50, b3), 100);
  EXPECT_TRUE(std::equal(b1.begin() + 50, b1.end(), b3.begin()));
  EXPECT_TRUE(std::equal(b2.begin(), b2.begin() + 50, b3.begin() + 50));
}

TEST_F(ReaderTest, SetFormat) {
  struct Case {
    std::string path;
    bool seekable;
    std::string name;
  };
  std::vector<Case> cases = {
      {"test.tar.gz", false, "test"},  {"test.tgz", false, "test"},
      {"test.tar.bz2", false, "test"}, {"test.zip.gz", true, "test.zip"},
      {"test.7z.gz", true, "test.7z"}, {"test.tar", false, "test"},
      {"test.xxx", false, "test"}  // bidding
  };
  for (const auto& c : cases) {
    ArchiveDescriptor ad;
    ad.path = c.path;
    ad.fd = FileDescriptor(open("/dev/null", O_RDONLY));
    try {
      Reader r(&ad, tree_);
    } catch (ExitCode const&) {
    }
    EXPECT_EQ(ad.is_seekable_format, c.seekable) << c.path;
    EXPECT_EQ(ad.name_without_extension, c.name) << c.path;
  }
}

// Mock fuse_get_context
static fuse_context g_fuse_context;
extern "C" fuse_context* fuse_get_context() {
  return &g_fuse_context;
}

class FUSETest : public ::testing::Test {
 protected:
  fuse_operations ops_ = GetFuseOperations();
  Tree tree_;

  void SetUp() override {
    g_fuse_context.private_data = &tree_;
    Options options;
    options.cache = Cache::None;
    tree_.SetOptions(options);
  }
};

TEST_F(FUSETest, GetAttrByPath) {
  tree_.Load(std::vector<std::string>{"test/data/archive.tar"});
  Stat z;
#if FUSE_USE_VERSION >= 30
  EXPECT_EQ(ops_.getattr("/romeo.txt", &z, nullptr), 0);
#else
  EXPECT_EQ(ops_.getattr("/romeo.txt", &z), 0);
#endif
  EXPECT_GT(z.st_size, 0);

#if FUSE_USE_VERSION >= 30
  EXPECT_EQ(ops_.getattr("/nonexistent", &z, nullptr), -ENOENT);
#else
  EXPECT_EQ(ops_.getattr("/nonexistent", &z), -ENOENT);
#endif
}

TEST_F(FUSETest, GetAttrByFi) {
  tree_.Load(std::vector<std::string>{"test/data/archive.tar"});
  fuse_file_info fi;
  std::memset(&fi, 0, sizeof(fi));
  EXPECT_EQ(ops_.open("/romeo.txt", &fi), 0);
  EXPECT_NE(fi.fh, 0);

  Stat z;
#if FUSE_USE_VERSION >= 30
  EXPECT_EQ(ops_.getattr(nullptr, &z, &fi), 0);
#else
  EXPECT_EQ(ops_.getattr("/romeo.txt", &z), 0);
#endif
  EXPECT_GT(z.st_size, 0);

  ops_.release("/romeo.txt", &fi);
}

TEST_F(FUSETest, Xattr) {
  tree_.Load(std::vector<std::string>{"test/data/many-xattrs.tar"});
  char buf[1024];

  // Success
  int res = ops_.getxattr("/file.txt", "user.attr_0001", buf, sizeof(buf));
  EXPECT_GT(res, 0);

  // Buffer too small
  EXPECT_EQ(ops_.getxattr("/file.txt", "user.attr_0001", buf, 1), -ERANGE);

  // Missing attribute
  EXPECT_EQ(ops_.getxattr("/file.txt", "user.nonexistent", buf, sizeof(buf)),
            -ENOATTR);

  // Attribute exists on another node (file.txt) but not on the root directory
  EXPECT_EQ(ops_.getxattr("/", "user.attr_0001", buf, sizeof(buf)), -ENOATTR);

  // Missing file
  EXPECT_EQ(ops_.getxattr("/nonexistent", "user.test", buf, sizeof(buf)),
            -ENOENT);

  // List xattrs
  res = ops_.listxattr("/file.txt", buf, sizeof(buf));
  EXPECT_GT(res, 0);

  // List xattrs size query
  res = ops_.listxattr("/file.txt", nullptr, 0);
  EXPECT_GT(res, 0);

  // List xattrs buffer too small
  EXPECT_EQ(ops_.listxattr("/file.txt", buf, 1), -ERANGE);

  // List xattrs missing file
  EXPECT_EQ(ops_.listxattr("/nonexistent", buf, sizeof(buf)), -ENOENT);
}

TEST_F(FUSETest, ReadLink) {
  tree_.Load(std::vector<std::string>{"test/data/specials.tar"});
  char buf[1024];

  // Success
  EXPECT_EQ(ops_.readlink("/symlink", buf, sizeof(buf)), 0);
  EXPECT_STREQ(buf, "regular");

  // Not a symlink
  EXPECT_EQ(ops_.readlink("/regular", buf, sizeof(buf)), -EINVAL);

  // Missing item
  EXPECT_EQ(ops_.readlink("/nonexistent", buf, sizeof(buf)), -ENOENT);
}

TEST_F(FUSETest, OpenRelease) {
  tree_.Load(std::vector<std::string>{"test/data/archive.tar"});
  fuse_file_info fi;
  std::memset(&fi, 0, sizeof(fi));

  // Success
  EXPECT_EQ(ops_.open("/romeo.txt", &fi), 0);
  EXPECT_NE(fi.fh, 0);

  // Release
  EXPECT_EQ(ops_.release("/romeo.txt", &fi), 0);

  // Open directory as file (failure)
  EXPECT_EQ(ops_.open("/non-ascii", &fi), -EISDIR);

  // Open nonexistent
  EXPECT_EQ(ops_.open("/nonexistent", &fi), -ENOENT);
}

#if FUSE_USE_VERSION >= 30
TEST_F(FUSETest, Seek) {
  tree_.Load(std::vector<std::string>{"test/data/archive.tar"});
  fuse_file_info fi;
  std::memset(&fi, 0, sizeof(fi));
  ops_.open("/romeo.txt", &fi);

  // Success (data)
  EXPECT_EQ(ops_.lseek("/romeo.txt", 0, SEEK_DATA, &fi), 0);

  // Success (hole - none in archive.tar regular file usually)
  // Actually archive.tar entries are not sparse by default.
  // But let's check past end.
  EXPECT_EQ(ops_.lseek("/romeo.txt", 1000000, SEEK_DATA, &fi), -ENXIO);

  ops_.release("/romeo.txt", &fi);
}
#endif

TEST_F(FUSETest, OpenDir) {
  tree_.Load(std::vector<std::string>{"test/data/archive.tar"});
  fuse_file_info fi;
  std::memset(&fi, 0, sizeof(fi));

  // Success
  EXPECT_EQ(ops_.opendir("/", &fi), 0);
  EXPECT_NE(fi.fh, 0);

  // Non-existent path
  EXPECT_EQ(ops_.opendir("/nonexistent", &fi), -ENOENT);

  // Not a directory (romeo.txt is a file)
  EXPECT_EQ(ops_.opendir("/romeo.txt", &fi), -ENOTDIR);
}

TEST_F(FUSETest, ReadDir) {
  tree_.Load(std::vector<std::string>{"test/data/archive.tar"});
  fuse_file_info fi;
  std::memset(&fi, 0, sizeof(fi));
  ops_.opendir("/", &fi);

  struct Data {
    std::vector<std::string> names;
  } data;

  auto filler = [](void* buf, const char* name, const struct stat*, off_t,
#if FUSE_USE_VERSION >= 30
                   enum fuse_fill_dir_flags
#endif
                ) {
    static_cast<Data*>(buf)->names.push_back(name);
    return 0;
  };

#if FUSE_USE_VERSION >= 30
  EXPECT_EQ(ops_.readdir("/", &data, filler, 0, &fi, (fuse_readdir_flags)0), 0);
#else
  EXPECT_EQ(ops_.readdir("/", &data, filler, 0, &fi), 0);
#endif

  EXPECT_FALSE(data.names.empty());
  EXPECT_TRUE(std::find(data.names.begin(), data.names.end(), "romeo.txt") !=
              data.names.end());
}

TEST_F(FUSETest, StatFs) {
  tree_.Load(std::vector<std::string>{"test/data/archive.tar"});
  StatVfs z;
  std::memset(&z, 0, sizeof(z));
  EXPECT_EQ(ops_.statfs("/", &z), 0);
  EXPECT_GT(z.f_blocks, 0);
  EXPECT_GT(z.f_files, 0);
}

namespace {

class GlobalEnvironment : public ::testing::Environment {
 public:
  void SetUp() override { SetLogLevel(LogLevel::DEBUG); }
};

::testing::Environment* const global_env =
    ::testing::AddGlobalTestEnvironment(new GlobalEnvironment);

TEST(Path, Normalized) {
  EXPECT_EQ(Path("").Normalized(), "/?");
  EXPECT_EQ(Path("foo/../bar").Normalized(), "/foo/?/bar");
  EXPECT_EQ(Path(".").Normalized(), "/");
  EXPECT_EQ(Path("///foo//bar///").Normalized(), "/foo/bar");
  EXPECT_EQ(Path("././foo").Normalized(), "/foo");
  EXPECT_EQ(Path("../foo").Normalized(), "/foo");
  EXPECT_EQ(Path("foo/..").Normalized(), "/foo/?");
  EXPECT_EQ(Path("foo/.").Normalized(), "/foo/?");

  std::string long_name(NAME_MAX + 10, 'a');
  EXPECT_LT(Path(long_name).Normalized().size(), long_name.size() + 2);

  std::string deep_path = "a";
  for (int i = 0; i < 5000; ++i) {
    deep_path += "/a";
  }
  EXPECT_TRUE(Path(deep_path).Normalized().find("Too Deep") !=
              std::string::npos);
}

TEST(Path, Extension) {
  EXPECT_EQ(Path("foo.tar.gz").ExtensionPosition(), 3);
  EXPECT_EQ(Path("foo.tar.lz4").ExtensionPosition(), 3);
  EXPECT_EQ(Path("foo.verylongext").FinalExtensionPosition(), 15);
  EXPECT_EQ(Path("foo.tar.zst").ExtensionPosition(), 3);
  EXPECT_EQ(Path("foo .zip").ExtensionPosition(), 4);
  EXPECT_EQ(Path("/foo.bar/baz").ExtensionPosition(), 12);
}

TEST(Path, Truncation) {
  EXPECT_EQ(Path("abc").TruncationPosition(2), 2);
  EXPECT_EQ(Path("αβ").TruncationPosition(1), 0);
  EXPECT_EQ(Path("abc").TruncationPosition(0), 0);
  EXPECT_EQ(Path("abc").TruncationPosition(10), 3);

  std::string zwj = "a\u200Db";
  EXPECT_EQ(Path(zwj).TruncationPosition(2), 0);

  EXPECT_EQ(Path("a\u200D b").TruncationPosition(4), 0);
}

TEST(Path, Stringify) {
  EXPECT_EQ(StrCat(Path("a'b\1\\")), "'a\\'b\\x01\\\\'");
  g_redact = true;
  EXPECT_EQ(StrCat(Path("foo")), "(redacted)");
  g_redact = false;
}

TEST(Path, Misc) {
  EXPECT_EQ(Path("/foo//").WithoutTrailingSeparator(), "/foo");
  Path p("foo/bar");
  EXPECT_TRUE(p.Consume('f'));
  EXPECT_EQ(p, "oo/bar");

  // Coverage for Path::Append
  std::string s = "head";
  Path::Append(&s, "");
  EXPECT_EQ(s, "head");

  s = "";
  Path::Append(&s, "tail");
  EXPECT_EQ(s, "tail");

  s = "head";
  Path::Append(&s, "/tail");
  EXPECT_EQ(s, "/tail");

  s = "head/";
  Path::Append(&s, "tail");
  EXPECT_EQ(s, "head/tail");

  s = "head";
  Path::Append(&s, "tail");
  EXPECT_EQ(s, "head/tail");
}

TEST(Util, All) {
  // Coverage for HashedString GetUniqueOrNull
  EXPECT_EQ(GetUniqueOrNull("this string definitely does not exist"), nullptr);

  EXPECT_EQ(ToLower("ABC"), "abc");
  EXPECT_EQ(SafeAdd(10, 20), 30);
  EXPECT_THROW(SafeAdd(INT64_MAX, 1), ExitCode);

  EXPECT_EQ(StrCat(ExitCode::GENERIC_FAILURE), "GENERIC_FAILURE (1)");
#define CHECK_EXIT_CODE(s)       \
  EXPECT_EQ(StrCat(ExitCode::s), \
            #s " (" + std::to_string(int(ExitCode::s)) + ")");
  CHECK_EXIT_CODE(CANNOT_CREATE_MOUNT_POINT)
  CHECK_EXIT_CODE(CANNOT_OPEN_ARCHIVE)
  CHECK_EXIT_CODE(CANNOT_CREATE_CACHE)
  CHECK_EXIT_CODE(CANNOT_WRITE_CACHE)
  CHECK_EXIT_CODE(PASSPHRASE_REQUIRED)
  CHECK_EXIT_CODE(PASSPHRASE_INCORRECT)
  CHECK_EXIT_CODE(PASSPHRASE_NOT_SUPPORTED)
  CHECK_EXIT_CODE(UNKNOWN_ARCHIVE_FORMAT)
  CHECK_EXIT_CODE(INVALID_ARCHIVE_HEADER)
  CHECK_EXIT_CODE(INVALID_ARCHIVE_CONTENTS)
#undef CHECK_EXIT_CODE
  EXPECT_EQ(StrCat(static_cast<ExitCode>(999)), "Exit Code 999");

  EXPECT_EQ(StrCat(static_cast<Whence>(SEEK_SET)), "SEEK_SET");
  EXPECT_EQ(StrCat(static_cast<Whence>(SEEK_CUR)), "SEEK_CUR");
  EXPECT_EQ(StrCat(static_cast<Whence>(SEEK_END)), "SEEK_END");
  EXPECT_EQ(StrCat(static_cast<Whence>(SEEK_DATA)), "SEEK_DATA");
  EXPECT_EQ(StrCat(static_cast<Whence>(SEEK_HOLE)), "SEEK_HOLE");
  EXPECT_EQ(StrCat(static_cast<Whence>(999)), "SEEK_999");

  EXPECT_FALSE(GetCacheDir().empty());

  FileDescriptor fd = CreateCacheFile(true);
  EXPECT_TRUE(fd.IsValid());
  CheckCacheFile(fd);

  // Failure: Not empty
  {
    char const c = 'x';
    EXPECT_EQ(write(fd, &c, 1), 1);
    EXPECT_THROW(CheckCacheFile(fd), ExitCode);
  }

  // Failure: Invalid FD
  {
    FileDescriptor invalid_fd;
    EXPECT_THROW(CheckCacheFile(invalid_fd), ExitCode);
  }

  // Coverage for ~FileDescriptor with failing close
  {
    FileDescriptor bad_fd(9999);
    // Destructor will run here and PLOG(ERROR)
  }

  EXPECT_THROW(ThrowExitCode("Incorrect passphrase"), ExitCode);
  EXPECT_THROW(ThrowExitCode("Passphrase required"), ExitCode);
  for (const char* const s : {
           "Crypto codec not supported",
           "Decryption is unsupported",
           "Encrypted file is unsupported",
           "Encryption is not supported",
           "RAR encryption support unavailable",
           "The archive header is encrypted, but currently not supported",
           "The file content is encrypted, but currently not supported",
           "Unsupported encryption format",
       }) {
    EXPECT_THROW(ThrowExitCode(s), ExitCode);
  }
  EXPECT_NO_THROW(ThrowExitCode("Unknown error"));
}

TEST(Common, All) {
  EXPECT_EQ(GetFileType(S_IFREG), FileType::File);
  EXPECT_EQ(GetFileType(0), FileType::File);
  EXPECT_EQ(StrCat(FileType::BlockDevice), "Block Device");
  EXPECT_EQ(StrCat(FileType::CharDevice), "Character Device");
  EXPECT_EQ(StrCat(FileType::Directory), "Directory");
  EXPECT_EQ(StrCat(FileType::Fifo), "FIFO");
  EXPECT_EQ(StrCat(FileType::File), "File");
  EXPECT_EQ(StrCat(FileType::Socket), "Socket");
  EXPECT_EQ(StrCat(FileType::Symlink), "Symlink");
  EXPECT_EQ(StrCat(static_cast<FileType>(0)), "Unknown");

  EXPECT_EQ(StrCat(ArchiveFormat::NONE), "NONE");
#define CHECK_FORMAT(s) \
  EXPECT_EQ(StrCat(static_cast<ArchiveFormat>(ARCHIVE_FORMAT_##s)), #s);
  CHECK_FORMAT(CPIO)
  CHECK_FORMAT(CPIO_POSIX)
  CHECK_FORMAT(CPIO_BIN_LE)
  CHECK_FORMAT(CPIO_BIN_BE)
  CHECK_FORMAT(CPIO_SVR4_NOCRC)
  CHECK_FORMAT(CPIO_SVR4_CRC)
  CHECK_FORMAT(CPIO_AFIO_LARGE)
  CHECK_FORMAT(CPIO_PWB)
  CHECK_FORMAT(SHAR)
  CHECK_FORMAT(SHAR_BASE)
  CHECK_FORMAT(SHAR_DUMP)
  CHECK_FORMAT(TAR)
  CHECK_FORMAT(TAR_USTAR)
  CHECK_FORMAT(TAR_PAX_INTERCHANGE)
  CHECK_FORMAT(TAR_PAX_RESTRICTED)
  CHECK_FORMAT(TAR_GNUTAR)
  CHECK_FORMAT(ISO9660)
  CHECK_FORMAT(ISO9660_ROCKRIDGE)
  CHECK_FORMAT(ZIP)
  CHECK_FORMAT(EMPTY)
  CHECK_FORMAT(AR)
  CHECK_FORMAT(AR_GNU)
  CHECK_FORMAT(AR_BSD)
  CHECK_FORMAT(MTREE)
  CHECK_FORMAT(RAW)
  CHECK_FORMAT(XAR)
  CHECK_FORMAT(LHA)
  CHECK_FORMAT(CAB)
  CHECK_FORMAT(RAR)
  CHECK_FORMAT(7ZIP)
  CHECK_FORMAT(WARC)
  CHECK_FORMAT(RAR_V5)
#undef CHECK_FORMAT
  EXPECT_EQ(StrCat(static_cast<ArchiveFormat>(999)), "999");
}

}  // namespace
}  // namespace fuse_archive
