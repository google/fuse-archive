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

#ifndef LIB_READER_H
#define LIB_READER_H

#include <archive.h>
#include <archive_entry.h>

#include <memory>
#include <span>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

#include <boost/intrusive/list.hpp>

#include "common.h"
#include "util.h"

namespace fuse_archive {

namespace bi = boost::intrusive;

struct Node;
struct Tree;

#ifdef NDEBUG
using LinkMode = bi::link_mode<bi::normal_link>;
#else
using LinkMode = bi::link_mode<bi::safe_link>;
#endif

// A Reader bundles libarchive concepts (an archive and an archive entry) and
// other state to point to a particular offset (in decompressed space) of a
// particular archive entry (identified by its index) in an archive.
//
// A Reader is backed by its own archive_read_open call so each can be
// positioned independently.
struct Reader : bi::list_base_hook<LinkMode> {
  // Global count of Reader instances created.
  static int count;

  // Unique identifier for this Reader instance.
  int const id = ++count;

  // The descriptor of the archive this reader is operating on.
  ArchiveDescriptor* const descriptor;

  // The virtual file system tree this reader belongs to.
  Tree& tree;

  // libarchive handle for reading the archive.
  ArchivePtr archive = ArchivePtr(archive_read_new());

  // Current entry being processed by libarchive.
  Entry* entry = nullptr;

  // Index of the current entry within the archive (1-based).
  i64 index_within_archive = 0;

  // Current offset within the decompressed entry content.
  i64 offset_within_entry = 0;

  // Whether to log loading progress for this archive.
  bool should_print_progress = false;

  // Current position within the raw compressed archive file.
  i64 raw_pos = 0;

  // Buffer for reading raw data from the archive file.
  char raw_bytes[16 * 1024];

  // Rolling buffer of uncompressed bytes to handle out-of-order kernel reads.
  //
  // See (https://crbug.com/1245925#c18).
  //
  // Even when libfuse is single-threaded, we have seen kernel readahead
  // causing the offset arguments in a sequence of read calls to sometimes
  // arrive out-of-order, where conceptually consecutive reads are swapped. With
  // a rolling buffer, we can serve the second-to-arrive request by a cheap
  // memcpy instead of an expensive "re-do decompression from the start".
  static ssize_t const rolling_buffer_size = 256 * 1024;
  static ssize_t const rolling_buffer_mask = rolling_buffer_size - 1;
  char rolling_buffer[rolling_buffer_size];

  // Destroys the reader and its internal libarchive state.
  ~Reader();

  // Initializes a reader for the given archive and tree.
  Reader(ArchiveDescriptor* descriptor, Tree& tree);

  // Formats the reader for logging (e.g. "Reader #5").
  friend std::ostream& operator<<(std::ostream& out, const Reader& r);

  // Advances to the next entry in the archive. Returns the entry or nullptr if
  // EOF.
  Entry* NextEntry();

  // Gets the offset within the current entry of the beginning of the rolling
  // buffer.
  i64 GetBufferOffset() const {
    return std::max<i64>(offset_within_entry - rolling_buffer_size, 0);
  }

  // Advances the reader to the specified entry index within the archive.
  void AdvanceIndex(i64 want);

  // Advances the reader to the specified decompressed offset within the current
  // entry.
  void AdvanceOffset(i64 want);

  // Returns the total decompressed size of the current entry.
  // May perform full decompression if the archive header does not provide it.
  i64 GetEntrySize();

  // Checks if the archive requires a password and prompts the user if
  // necessary.
  void CheckPassword();

  // Reads decompressed data from the current entry into the provided buffer.
  // Updates offset_within_entry and the rolling buffer.
  i64 Read(char* dst_ptr, i64 dst_len);

  // Reads decompressed data into a span.
  ssize_t Read(std::span<char> dst);

  // Reads decompressed data from a specific offset into a span.
  // Precondition: offset >= GetBufferOffset() and offset <=
  // offset_within_entry.
  ssize_t Read(i64 from_offset, std::span<char> dst);

  // Reads data from the current entry of archive |a| and writes it into
  // |dest_fd| starting at offset |file_start_offset|. Returns the new total
  // size of the cache file.
  //
  // If |node| is non null, it also discovers and remembers "holes" (sparse
  // regions) in the file and updates the node's block count.
  //
  // Preconditions:
  // - |a| must point to a valid entry.
  //
  // Throws ExitCode::CANNOT_WRITE_CACHE in case of an I/O error.
  // Throws ExitCode::INVALID_ARCHIVE_CONTENTS in case of integer overflow or
  // unexpected data format.
  i64 CacheEntryData(const FileDescriptor& dest_fd,
                     i64 file_start_offset,
                     Node* node = nullptr);

  // Deleter for unique_ptr that puts the reader into the recycle bin instead of
  // deleting it.
  struct Recycler {
    void operator()(Reader* r) const;
  };

  using Ptr = std::unique_ptr<Reader, Recycler>;

 private:
  friend struct Tree;

  // Read a password from the standard input if necessary.
  static const char* ReadPassword(Archive* a, void* client_data);

  // Internal helper to check libarchive status codes and throw on failure.
  void Check(int status) const;

  // Configures libarchive to handle TAR formats.
  void SetTarFormat();

  // Configures libarchive to handle RAR formats.
  void SetRarFormat();

  // Configures libarchive to handle RPM formats.
  void SetRpmFormat();

  // Configures filters based on filename extension.
  bool SetFilter(std::string_view ext);

  // Configures compressed TAR formats (e.g. .tar.gz).
  bool SetCompressedTarFormat(std::string_view ext);

  // Format configuration helpers used during filename-based detection.
  bool SetFormatBeforeExtraFilter(std::string_view ext);
  bool SetFormatAfterExtraFilter(std::string_view ext);

  // High-level method to detect and set the archive format based on its
  // filename.
  void SetFormat();

  // libarchive callbacks for reading from the underlying ArchiveDescriptor's
  // file descriptor.
  static ssize_t ReadRaw(Archive* a, void* p, const void** out);
  static i64 SeekRaw(Archive*, void* p, i64 offset, int whence);
  static i64 SkipRaw(Archive*, void* p, i64 delta);

  // Throttler for loading progress log messages.
  Beat g_progress_beat;

  // Logs the current loading progress (0-100%).
  void PrintProgress() const;
};

}  // namespace fuse_archive

#endif  // LIB_READER_H
