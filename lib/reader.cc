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

#include "reader.h"

#include <archive.h>
#include <archive_entry.h>
#include <termios.h>
#include <unistd.h>

#include <algorithm>
#include <cassert>
#include <iostream>
#include <memory>
#include <span>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include "node.h"
#include "tree.h"

#include "common.h"
#include "path.h"
#include "util.h"

namespace fuse_archive {

int Reader::count = 0;

namespace {

// Temporarily suppresses the echo on the terminal.
// Used when waiting for password to be typed.
class SuppressEcho {
 public:
  explicit SuppressEcho() {
    if (tcgetattr(STDIN_FILENO, &tattr_) < 0) {
      return;
    }

    struct termios tattr = tattr_;
    tattr.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &tattr);
    reset_ = true;
  }

  ~SuppressEcho() {
    if (reset_) {
      tcsetattr(STDIN_FILENO, TCSAFLUSH, &tattr_);
    }
  }

  explicit operator bool() const { return reset_; }

 private:
  struct termios tattr_;
  bool reset_ = false;
};

}  // namespace

// Read a password from the standard input if necessary.
const char* Reader::ReadPassword(Archive*, void* client_data) {
  assert(client_data);
  Tree& tree = *static_cast<Tree*>(client_data);

  if (tree.password_count_++) {
    return nullptr;
  }

  SuppressEcho const guard;
  if (guard) {
    std::cout << "The archive is encrypted.\n"
                 "What is the passphrase that unlocks this archive?\n"
                 "> "
              << std::flush;
  }

  std::string& password = tree.password_;

  // Read password from standard input.
  if (!std::getline(std::cin, password)) {
    password.clear();
  }

  if (guard) {
    std::cout << "Got it!" << std::endl;
  }

  // Remove newline at the end of password.
  while (password.ends_with('\n')) {
    password.pop_back();
  }

  if (password.empty()) {
    LOG(DEBUG) << "Got an empty password";
    return nullptr;
  }

  LOG(DEBUG) << "Got a password of " << password.size() << " bytes";
  return password.c_str();
}

Reader::~Reader() {
  LOG(DEBUG) << "Deleted " << *this;
}

Reader::Reader(ArchiveDescriptor* descriptor, Tree& tree)
    : descriptor(descriptor), tree(tree) {
  if (!archive) {
    LOG(ERROR) << "Out of memory";
    throw std::bad_alloc();
  }

  const std::string& password = tree.password_;

  if (password.empty()) {
    Check(archive_read_set_passphrase_callback(archive.get(), &tree,
                                               &Reader::ReadPassword));
  } else {
    Check(archive_read_add_passphrase(archive.get(), password.c_str()));
  }

  SetFormat();

  // Set callbacks to read the archive file itself.
  Check(archive_read_set_callback_data(archive.get(), this));
  Check(archive_read_set_read_callback(archive.get(), ReadRaw));
  Check(archive_read_set_seek_callback(archive.get(), SeekRaw));
  Check(archive_read_set_skip_callback(archive.get(), SkipRaw));

  // Open the archive.
  Check(archive_read_open1(archive.get()));

  LOG(DEBUG) << "Created " << *this;
}

std::ostream& operator<<(std::ostream& out, const Reader& r) {
  return out << "Reader #" << r.id;
}

Entry* Reader::NextEntry() {
  offset_within_entry = 0;
  index_within_archive++;
  while (true) {
    switch (archive_read_next_header(archive.get(), &entry)) {
      case ARCHIVE_RETRY:
        continue;

      case ARCHIVE_WARN:
        LOG(WARNING) << GetErrorString(archive.get());
        [[fallthrough]];

      case ARCHIVE_OK:
        assert(entry);
        descriptor->format =
            static_cast<ArchiveFormat>(archive_format(archive.get()));
        descriptor->filter_count = 0;
        for (int i = archive_filter_count(archive.get()); i > 0;) {
          if (archive_filter_code(archive.get(), --i) != ARCHIVE_FILTER_NONE) {
            descriptor->filter_count++;
          }
        }
        return entry;

      case ARCHIVE_EOF:
        entry = nullptr;
        return nullptr;

      case ARCHIVE_FAILED:
      case ARCHIVE_FATAL:
        std::string_view const error = GetErrorString(archive.get());
        LOG(ERROR) << "Cannot advance to entry " << index_within_archive << ": "
                   << error;
        ThrowExitCode(error);
        throw ExitCode::INVALID_ARCHIVE_CONTENTS;
    }
  }
}

void Reader::AdvanceIndex(i64 const want) {
  if (index_within_archive == want) {
    return;
  }

  assert(index_within_archive < want);
  Timer const timer;

  do {
    if (!NextEntry()) {
      LOG(ERROR) << "Reached EOF while advancing to entry "
                 << index_within_archive;
      throw ExitCode::INVALID_ARCHIVE_HEADER;
    }
  } while (index_within_archive < want);

  assert(index_within_archive == want);
  LOG(DEBUG) << "Advanced " << *this << " to entry " << want << " in " << timer;
}

void Reader::AdvanceOffset(i64 const want) {
  if (offset_within_entry >= want) {
    assert(GetBufferOffset() <= want);
    // We already are where we want to be.
    return;
  }

  assert(offset_within_entry < want);

  Timer const timer;

  // We are behind where we want to be. Advance (decompressing from the
  // archive entry into a rolling buffer) until we get there.
  Read(nullptr, want - offset_within_entry);

  assert(offset_within_entry == want);
  LOG(DEBUG) << "Advanced " << *this << " to offset " << offset_within_entry
             << " in " << timer;
}

i64 Reader::GetEntrySize() {
  if (archive_entry_size_is_set(entry)) {
    return archive_entry_size(entry);
  }

  // Consume the entry's data.
  off_t offset = offset_within_entry;
  while (true) {
    const void* buff = nullptr;
    size_t len = 0;

    switch (archive_read_data_block(archive.get(), &buff, &len, &offset)) {
      case ARCHIVE_RETRY:
        continue;

      case ARCHIVE_WARN:
        LOG(WARNING) << GetErrorString(archive.get());
        [[fallthrough]];

      case ARCHIVE_OK:
        offset += len;
        offset_within_entry = offset;
        continue;

      case ARCHIVE_EOF:
        assert(len == 0);
        assert(offset >= 0);
        assert(offset_within_entry <= offset);

        if (offset_within_entry < offset) {
          offset_within_entry = offset;
        }

        if (archive_entry_is_encrypted(entry)) {
          tree.password_checked_ = true;
        }

        return offset_within_entry;

      case ARCHIVE_FAILED:
      case ARCHIVE_FATAL:
        std::string_view const error = GetErrorString(archive.get());
        LOG(ERROR) << "Cannot read data from archive: " << error;
        ThrowExitCode(error);
        throw ExitCode::INVALID_ARCHIVE_CONTENTS;
    }
  }
}

void Reader::CheckPassword() {
  if (tree.password_checked_ || !archive_entry_is_encrypted(entry)) {
    return;
  }

  // Reading the first bytes of the first encrypted entry will reveal whether
  // we also need a passphrase.
  tree.password_checked_ = Read(nullptr, 16) > 0;
}

i64 Reader::Read(char* dst_ptr, i64 dst_len) {
  assert(dst_len >= 0);
  i64 total = 0;
  while (dst_len > 0) {
    std::span<char> b(rolling_buffer);
    assert(b.size() == rolling_buffer_size);
    ssize_t const i =
        static_cast<ssize_t>(offset_within_entry & rolling_buffer_mask);
    assert(i >= 0);
    assert(i < b.size());
    b = b.subspan(i);
    if (dst_len < b.size()) {
      b = b.first(static_cast<ssize_t>(dst_len));
    }
    ssize_t const n = archive_read_data(archive.get(), b.data(), b.size());
    if (n == 0) {
      break;
    }

    if (n < 0) {
      if (n == ARCHIVE_RETRY) {
        continue;
      }

      std::string_view const error = GetErrorString(archive.get());
      LOG(ERROR) << "Cannot read data from archive: " << error;
      ThrowExitCode(error);
      throw ExitCode::INVALID_ARCHIVE_CONTENTS;
    }

    assert(n > 0);
    assert(n <= b.size());
    b = b.first(n);
    dst_len -= n;
    if (dst_ptr) {
      dst_ptr = std::ranges::copy(b, dst_ptr).out;
    }
    offset_within_entry += n;
    total += n;
  }

  return total;
}

ssize_t Reader::Read(std::span<char> const dst) {
  return static_cast<ssize_t>(Read(dst.data(), dst.size()));
}

ssize_t Reader::Read(i64 from_offset, std::span<char> dst) {
  assert(!dst.empty());
  assert(from_offset >= GetBufferOffset());
  ssize_t total = 0;

  if (from_offset < offset_within_entry) {
    ssize_t const j =
        static_cast<ssize_t>(offset_within_entry & rolling_buffer_mask);
    assert(j >= 0);
    assert(j < rolling_buffer_size);

    // Copy from rolling buffer.
    do {
      assert(from_offset >= GetBufferOffset());
      std::span<char> b(rolling_buffer);
      assert(b.size() == rolling_buffer_size);
      ssize_t const i = static_cast<ssize_t>(from_offset & rolling_buffer_mask);
      assert(i >= 0);
      assert(i < rolling_buffer_size);
      b = b.subspan(i);
      if (i < j) {
        b = b.first(j - i);
      }

      if (dst.size() < b.size()) {
        b = b.first(dst.size());
      }

      std::ranges::copy(b, dst.begin());
      from_offset += b.size();
      dst = dst.subspan(b.size());
      total += b.size();

      if (dst.empty()) {
        return total;
      }
    } while (from_offset < offset_within_entry);
  } else {
    AdvanceOffset(from_offset);
  }

  assert(from_offset == offset_within_entry);
  total += Read(dst);
  return total;
}

void Reader::Recycler::operator()(Reader* const r) const {
  auto& recycled = r->tree.recycled_readers_;
  LOG(DEBUG) << "Putting aside " << *r << " currently at offset "
             << r->offset_within_entry << " of entry "
             << r->index_within_archive;
  recycled.push_front(*r);
  constexpr int max_saved_readers = 8;
  if (recycled.size() > max_saved_readers) {
    Reader& to_delete = recycled.back();
    recycled.pop_back();
    delete &to_delete;
  }
}

i64 Reader::CacheEntryData(const FileDescriptor& dest_fd,
                           i64 const file_start_offset,
                           Node* const node) try {
  Archive* const a = archive.get();
  assert(a);
  assert(file_start_offset >= 0);
  i64 dest_offset = file_start_offset;
  i64 last_hole_start = file_start_offset;

  FileDescriptor::HoleCallback on_hole;
  if (node && tree.options_.holes) {
    assert(node->holes.empty());
    assert(node->saved_blocks == 0);
    on_hole = [node, file_start_offset](i64 from, i64 to) {
      from -= file_start_offset;
      to -= file_start_offset;
      node->saved_blocks += node->holes.emplace_back(from, to).GetSavedBlocks();
    };
  }

  while (true) {
    const void* buff = nullptr;
    size_t len = 0;
    off_t offset = dest_offset - file_start_offset;

    switch (archive_read_data_block(a, &buff, &len, &offset)) {
      case ARCHIVE_RETRY:
        continue;

      case ARCHIVE_WARN:
        LOG(WARNING) << GetErrorString(a);
        [[fallthrough]];

      case ARCHIVE_OK:
        assert(offset >= 0);
        assert(dest_offset <= SafeAdd(file_start_offset, offset));
        dest_offset = SafeAdd(file_start_offset, offset);

        last_hole_start = dest_fd.WriteBytesAndSkipHoles(
            std::string_view(static_cast<const char*>(buff), len), dest_offset,
            last_hole_start, on_hole);

        dest_offset = SafeAdd(dest_offset, len);
        continue;

      case ARCHIVE_EOF:
        assert(len == 0);
        assert(offset >= 0);
        assert(dest_offset <= SafeAdd(file_start_offset, offset));
        dest_offset = SafeAdd(file_start_offset, offset);

        if (last_hole_start < dest_offset) {
          dest_fd.Truncate(dest_offset);
        }

        if (node) {
          // Mark this file as fully cached.
          node->cache_offset = file_start_offset;
          node->cached_size = offset;
          node->size = offset;
          node->last_hole_start =
              tree.options_.holes ? last_hole_start : dest_offset;
          assert(node->IsFullyCached());
        }

        return dest_offset;
    }

    LOG(ERROR) << "Cannot read archive entry data: " << GetErrorString(a);
    ThrowExitCode(GetErrorString(a));
    throw ExitCode::INVALID_ARCHIVE_CONTENTS;
  }
} catch (...) {
  // In case of error, erase the data of the partially cached file.
  if (node) {
    node->holes.clear();
    node->saved_blocks = 0;
  }

  dest_fd.Truncate(file_start_offset);
  throw;
}

void Reader::Check(int const status) const {
  Archive* const a = archive.get();

  switch (status) {
    case ARCHIVE_OK:
      return;

    case ARCHIVE_WARN:
      LOG(WARNING) << GetErrorString(a);
      return;

    default:
      std::string_view const error = GetErrorString(a);
      LOG(ERROR) << "Cannot open " << Path(descriptor->path) << ": " << error;
      ThrowExitCode(error);
      throw ExitCode::UNKNOWN_ARCHIVE_FORMAT;
  }
}

void Reader::SetTarFormat() {
  Archive* const a = archive.get();
  Check(archive_read_support_format_empty(a));
  Check(archive_read_support_format_tar(a));
}

void Reader::SetRarFormat() {
  Archive* const a = archive.get();
  Check(archive_read_support_format_rar(a));
  Check(archive_read_support_format_rar5(a));
}

void Reader::SetRpmFormat() {
  Archive* const a = archive.get();
  Check(archive_read_support_filter_rpm(a));
  Check(archive_read_support_filter_gzip(a));
  Check(archive_read_support_filter_lzip(a));
  Check(archive_read_support_filter_lzma(a));
  Check(archive_read_support_filter_xz(a));
  Check(archive_read_support_filter_zstd(a));
  Check(archive_read_support_format_cpio(a));
  Check(archive_read_support_format_xar(a));
}

#define SET_FILTER(s)                                           \
  [](Reader& r) {                                               \
    Archive* const a = r.archive.get();                         \
    r.Check(archive_read_append_filter(a, ARCHIVE_FILTER_##s)); \
  }

#define SET_FILTER_COMMAND(s)                                 \
  [](Reader& r) {                                             \
    Archive* const a = r.archive.get();                       \
    r.Check(archive_read_append_filter_program(a, #s " -d")); \
  }

#define WORK_AROUND_ISSUE_2513 ARCHIVE_VERSION_NUMBER < 3'008'007
#define WORK_AROUND_ISSUE_2514 ARCHIVE_VERSION_NUMBER < 3'009'000

bool Reader::SetFilter(std::string_view const ext) {
  static std::unordered_map<std::string_view, void (*)(Reader&)> const
      ext_to_filter = {
          {"asc", SET_FILTER_COMMAND(gpg)},
          {"gpg", SET_FILTER_COMMAND(gpg)},
          {"pgp", SET_FILTER_COMMAND(gpg)},
          {"b64", SET_FILTER_COMMAND(base64)},
          {"base64", SET_FILTER_COMMAND(base64)},
          {"br", SET_FILTER_COMMAND(brotli)},
          {"brotli", SET_FILTER_COMMAND(brotli)},
          {"bz", SET_FILTER(BZIP2)},
          {"bz2", SET_FILTER(BZIP2)},
          {"bzip2", SET_FILTER(BZIP2)},
#if WORK_AROUND_ISSUE_2513
          // Work around https://github.com/libarchive/libarchive/issues/2513
          {"grz", SET_FILTER_COMMAND(grzip)},
          {"grzip", SET_FILTER_COMMAND(grzip)},
#else
          {"grz", SET_FILTER(GRZIP)},
          {"grzip", SET_FILTER(GRZIP)},
#endif
          {"gz", SET_FILTER(GZIP)},
          {"gzip", SET_FILTER(GZIP)},
          {"lrz", SET_FILTER(LRZIP)},
          {"lrzip", SET_FILTER(LRZIP)},
          {"lz", SET_FILTER(LZIP)},
          {"lzip", SET_FILTER(LZIP)},
          {"lz4", SET_FILTER(LZ4)},
          {"lzma", SET_FILTER(LZMA)},
#if WORK_AROUND_ISSUE_2513
          // Work around https://github.com/libarchive/libarchive/issues/2513
          {"lzo", SET_FILTER_COMMAND(lzop)},
          {"lzop", SET_FILTER_COMMAND(lzop)},
#else
          {"lzo", SET_FILTER(LZOP)},
          {"lzop", SET_FILTER(LZOP)},
#endif
          {"uu", SET_FILTER(UU)},
          {"xz", SET_FILTER(XZ)},
#if WORK_AROUND_ISSUE_2514
          // Work around https://github.com/libarchive/libarchive/issues/2514
          {"z", SET_FILTER_COMMAND(compress)},
#else
          {"z", SET_FILTER(COMPRESS)},
#endif
          {"zst", SET_FILTER(ZSTD)},
          {"zstd", SET_FILTER(ZSTD)},
      };

  const auto it = ext_to_filter.find(ext);
  if (it == ext_to_filter.end()) {
    return false;
  }

  it->second(*this);
  return true;
}

bool Reader::SetCompressedTarFormat(std::string_view const ext) {
  static std::unordered_map<std::string_view, void (*)(Reader&)> const
      ext_to_filter = {
#if WORK_AROUND_ISSUE_2514
          // Work around https://github.com/libarchive/libarchive/issues/2514
          {"taz", SET_FILTER_COMMAND(compress)},
          {"tz", SET_FILTER_COMMAND(compress)},
#else
          {"taz", SET_FILTER(COMPRESS)},
          {"tz", SET_FILTER(COMPRESS)},
#endif
          {"tbr", SET_FILTER_COMMAND(brotli)},
          {"tb2", SET_FILTER(BZIP2)},
          {"tbz", SET_FILTER(BZIP2)},
          {"tbz2", SET_FILTER(BZIP2)},
          {"tgz", SET_FILTER(GZIP)},
          {"tlz",
           [](Reader& r) {
             // .tlz could mean any TAR with LZ-based compression.
             Archive* const a = r.archive.get();
             archive_read_support_filter_lzma(a);
             archive_read_support_filter_lzip(a);
             archive_read_support_filter_lzop(a);
             archive_read_support_filter_lz4(a);
           }},
          {"tlz4", SET_FILTER(LZ4)},
          {"tlzip", SET_FILTER(LZIP)},
          {"tlzma", SET_FILTER(LZMA)},
          {"tlrz", SET_FILTER(LRZIP)},
#if WORK_AROUND_ISSUE_2513
          {"tlzo", SET_FILTER_COMMAND(lzop)},
          {"tlzop", SET_FILTER_COMMAND(lzop)},
#else
          {"tlzo", SET_FILTER(LZOP)},
          {"tlzop", SET_FILTER(LZOP)},
#endif
          {"txz", SET_FILTER(XZ)},
          {"tz2", SET_FILTER(BZIP2)},
          {"tzs", SET_FILTER(ZSTD)},
          {"tzst", SET_FILTER(ZSTD)},
          {"tzstd", SET_FILTER(ZSTD)},
          {"tar",
           [](Reader& r) {
             // Some `.tar` archives are actually compressed TARs, even though
             // they don't have the compression extension. So, as a special
             // case for `.tar`, automatically recognize the possible
             // compression filters.
             Archive* const a = r.archive.get();
             r.Check(archive_read_support_filter_all(a));
           }},
      };

  const auto it = ext_to_filter.find(ext);
  if (it == ext_to_filter.end()) {
    return false;
  }

  it->second(*this);
  SetTarFormat();
  return true;
}

#define SET_FORMAT(s)                            \
  [](Reader& r) {                                \
    Archive* const a = r.archive.get();          \
    r.Check(archive_read_support_format_##s(a)); \
  }

bool Reader::SetFormatBeforeExtraFilter(std::string_view const ext) {
  static std::unordered_map<std::string_view, void (*)(Reader&)> const
      ext_to_format = {
          {"7z", SET_FORMAT(7zip)},
          {"7zip", SET_FORMAT(7zip)},
          {"a", SET_FORMAT(ar)},
          {"aab", SET_FORMAT(zip_seekable)},
          {"apk", SET_FORMAT(zip_seekable)},
          {"ar", SET_FORMAT(ar)},
          {"cab", SET_FORMAT(cab)},
          {"cbr", [](Reader& r) { r.SetRarFormat(); }},
          {"cbz", SET_FORMAT(zip_seekable)},
          {"cpio", SET_FORMAT(cpio)},
          {"crx", SET_FORMAT(zip_seekable)},
          {"deb", SET_FORMAT(ar)},
          {"docx", SET_FORMAT(zip_seekable)},
          {"ear", SET_FORMAT(zip_seekable)},
          {"epub", SET_FORMAT(zip_seekable)},
          {"ipa", SET_FORMAT(zip_seekable)},
          {"iso", SET_FORMAT(iso9660)},
          {"iso9660", SET_FORMAT(iso9660)},
          {"jar", SET_FORMAT(zip_seekable)},
          {"lha", SET_FORMAT(lha)},
          {"lzh", SET_FORMAT(lha)},
          {"mtree", SET_FORMAT(mtree)},
          {"odf", SET_FORMAT(zip_seekable)},
          {"odg", SET_FORMAT(zip_seekable)},
          {"odp", SET_FORMAT(zip_seekable)},
          {"ods", SET_FORMAT(zip_seekable)},
          {"odt", SET_FORMAT(zip_seekable)},
          {"ppsx", SET_FORMAT(zip_seekable)},
          {"pptx", SET_FORMAT(zip_seekable)},
          {"rar", [](Reader& r) { r.SetRarFormat(); }},
          {"rpm", [](Reader& r) { r.SetRpmFormat(); }},
          {"spm", [](Reader& r) { r.SetRpmFormat(); }},
          {"tar", [](Reader& r) { r.SetTarFormat(); }},
          {"war", SET_FORMAT(zip_seekable)},
          {"warc", SET_FORMAT(warc)},
          {"whl", SET_FORMAT(zip_seekable)},
          {"xar", SET_FORMAT(xar)},
          {"xlsx", SET_FORMAT(zip_seekable)},
          {"xpi", SET_FORMAT(zip_seekable)},
          {"zip", SET_FORMAT(zip_seekable)},
          {"zipx", SET_FORMAT(zip_seekable)},
      };

  const auto it = ext_to_format.find(ext);
  if (it == ext_to_format.end()) {
    return false;
  }

  it->second(*this);
  return true;
}

bool Reader::SetFormatAfterExtraFilter(std::string_view const ext) {
  static std::unordered_map<std::string_view, void (*)(Reader&)> const
      ext_to_format = {
          {"a", SET_FORMAT(ar)},
          {"ar", SET_FORMAT(ar)},
          {"cab", SET_FORMAT(cab)},
          {"cpio", SET_FORMAT(cpio)},
          {"deb", SET_FORMAT(ar)},
          {"iso", SET_FORMAT(iso9660)},
          {"iso9660", SET_FORMAT(iso9660)},
          {"lha", SET_FORMAT(lha)},
          {"lzh", SET_FORMAT(lha)},
          {"mtree", SET_FORMAT(mtree)},
          {"rar", [](Reader& r) { r.SetRarFormat(); }},
          {"tar", [](Reader& r) { r.SetTarFormat(); }},
          {"warc", SET_FORMAT(warc)},
          {"xar", SET_FORMAT(xar)},
      };

  const auto it = ext_to_format.find(ext);
  if (it == ext_to_format.end()) {
    return false;
  }

  it->second(*this);
  return true;
}

void Reader::SetFormat() {
  Path p = Path(descriptor->path).Split().second;

  // Get the final filename extension in lower case and without the dot.
  // Eg "gz", "tar"...
  size_t i = p.FinalExtensionPosition();
  std::string ext = ToLower(p.substr(std::min(i + 1, p.size())));

  const bool first_time = descriptor->name_without_extension.empty();
  // Does this extension signal a recognized archive format?
  if ((tree.options_.max_filter_count > 0 && SetCompressedTarFormat(ext)) ||
      SetFormatBeforeExtraFilter(ext)) {
    p = p.substr(0, i);
    if (first_time) {
      LOG(DEBUG) << "Recognized format extension '" << ext << "'";
      descriptor->name_without_extension = p;
    }

    return;
  }

  // Does this extension signal a filter?
  if (tree.options_.max_filter_count > 0 && SetFilter(ext)) {
    // There is a compression filter. Only specific formats are recognized
    // after a compression filter.
    p = p.substr(0, i);
    if (first_time) {
      LOG(DEBUG) << "Recognized filter extension '" << ext << "'";
      descriptor->name_without_extension = p;
    }

    i = p.FinalExtensionPosition();
    ext = ToLower(p.substr(std::min(i + 1, p.size())));

    int filter_count = 1;
    while (filter_count < tree.options_.max_filter_count && SetFilter(ext)) {
      filter_count++;
      // There are several filters.
      p = p.substr(0, i);
      if (first_time) {
        LOG(DEBUG) << "Recognized filter extension '" << ext << "'";
        descriptor->name_without_extension = p;
      }

      i = p.FinalExtensionPosition();
      ext = ToLower(p.substr(std::min(i + 1, p.size())));
    }

    if (filter_count > 1 && first_time &&
        archive_version_number() < 3'008'002) {
      LOG(WARNING) << "Simultaneous use of two or more filters with "
                   << archive_version_string()
                   << " can result in blockage due to libarchive issue 2520";
      LOG(WARNING)
          << "See https://github.com/libarchive/libarchive/issues/2520";
    }

    // Only specific formats are recognized after a compression filter.
    if (SetFormatAfterExtraFilter(ext)) {
      p = p.substr(0, i);
      if (first_time) {
        LOG(DEBUG) << "Recognized format extension '" << ext << "'";
        descriptor->name_without_extension = p;
      }
    } else {
      Check(archive_read_support_format_raw(archive.get()));
      static const std::unordered_set<std::string_view> seekable_exts = {
          "7z", "7zip", "ear", "jar", "war", "zip", "zipx"};
      descriptor->is_seekable_format = seekable_exts.contains(ext);
    }

    return;
  }

  if (!tree.options_.bidding) {
    LOG(ERROR) << "Cannot determine the archive format from its filename "
                  "extension '"
               << ext << "'";
    throw ExitCode::UNKNOWN_ARCHIVE_FORMAT;
  }

  p = p.substr(0, i);
  if (first_time) {
    LOG(WARNING) << "Cannot determine the archive format from its filename "
                    "extension '"
                 << ext << "'";
    LOG(WARNING) << "Trying to guess the format using the file contents...";
    descriptor->name_without_extension = p;
  }

  // Not a recognized extension. So we'll activate most of the possible
  // formats, and let libarchive's bidding system do its job.
  if (tree.options_.max_filter_count > 0) {
    Check(archive_read_support_filter_all(archive.get()));
  }

  // Prepare the handlers for the recognized archive formats. We first install
  // handlers whose heuristic format identification tests are the fastest and
  // least invasive. If one of them emits a high enough score, then the
  // subsequent testers will do nothing.
  Check(archive_read_support_format_tar(archive.get()));

  // The following archive formats are supported by libarchive, but some of
  // them haven't been tested by fuse-archive's authors.
  Check(archive_read_support_format_ar(archive.get()));
  Check(archive_read_support_format_cpio(archive.get()));
  Check(archive_read_support_format_lha(archive.get()));
  Check(archive_read_support_format_xar(archive.get()));
  Check(archive_read_support_format_warc(archive.get()));

  // More expensive bidders, all supported by libarchive and tested by
  // fuse-archive's authors.
  Check(archive_read_support_format_7zip(archive.get()));
  Check(archive_read_support_format_cab(archive.get()));
  Check(archive_read_support_format_rar(archive.get()));
  Check(archive_read_support_format_rar5(archive.get()));
  Check(archive_read_support_format_iso9660(archive.get()));

  // We don't want to handle ZIP archives in streamable mode.
  // We only handle ZIP archives in seekable mode.
  // See https://github.com/libarchive/libarchive/issues/1764.
  // See https://github.com/libarchive/libarchive/issues/2502.
  Check(archive_read_support_format_zip_seekable(archive.get()));

  // We use the "raw" archive format to read simple compressed files such as
  // "romeo.txt.gz".
  Check(archive_read_support_format_raw(archive.get()));
}

ssize_t Reader::ReadRaw(Archive* const a,
                        void* const p,
                        const void** const out) {
  assert(p);
  Reader& r = *static_cast<Reader*>(p);
  assert(r.descriptor);
  assert(r.descriptor->fd.IsValid());
  while (true) {
    ssize_t const n =
        pread(r.descriptor->fd, r.raw_bytes, sizeof(r.raw_bytes), r.raw_pos);
    if (n >= 0) {
      r.raw_pos += n;
      r.PrintProgress();
      *out = r.raw_bytes;
      return n;
    }

    if (errno == EINTR) {
      continue;
    }

    archive_set_error(a, errno, "Cannot read archive file: %s",
                      strerror(errno));
    return ARCHIVE_FATAL;
  }
}

i64 Reader::SeekRaw(Archive*,
                    void* const p,
                    i64 const offset,
                    int const whence) {
  assert(p);
  Reader& r = *static_cast<Reader*>(p);
  assert(r.descriptor);
  switch (whence) {
    case SEEK_SET:
      r.raw_pos = offset;
      return r.raw_pos;
    case SEEK_CUR:
      r.raw_pos += offset;
      return r.raw_pos;
    case SEEK_END:
      r.raw_pos = r.descriptor->size + offset;
      return r.raw_pos;
  }

  LOG(ERROR) << "Unexpected: whence = " << Whence(whence);
  return ARCHIVE_FATAL;
}

i64 Reader::SkipRaw(Archive*, void* const p, i64 const delta) {
  assert(p);
  Reader& r = *static_cast<Reader*>(p);
  r.raw_pos += delta;
  return delta;
}

void Reader::PrintProgress() const {
  if (should_print_progress && const_cast<Beat&>(g_progress_beat).Keep()) {
    assert(descriptor->size > 0);
    LOG(INFO) << "Loading " << Path(descriptor->path) << "... "
              << ProgressMessage(100 *
                                 std::min<i64>(raw_pos, descriptor->size) /
                                 descriptor->size);
  }
}

}  // namespace fuse_archive
