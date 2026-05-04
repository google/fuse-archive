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

#ifndef LIB_FILE_DESCRIPTOR_H
#define LIB_FILE_DESCRIPTOR_H

#include <unistd.h>

#include <functional>
#include <string_view>
#include <utility>

#include "util.h"

namespace fuse_archive {

// A scoped file descriptor.
class FileDescriptor {
 public:
  // Closes the underlying file descriptor if it is currently valid.
  ~FileDescriptor() {
    if (IsValid() && close(fd_) < 0) {
      PLOG(ERROR) << "Cannot close file";
    }
  }

  // Initializes an empty (invalid) FileDescriptor.
  FileDescriptor() noexcept : fd_(-1) {}

  // Takes ownership of the provided raw file descriptor.
  explicit FileDescriptor(int fd) noexcept : fd_(fd) {}

  // Move-constructs a FileDescriptor, taking ownership from the other instance.
  FileDescriptor(FileDescriptor&& other) noexcept
      : fd_(std::exchange(other.fd_, -1)) {}

  // Atomically swaps the underlying file descriptors between two instances.
  void SwapWith(FileDescriptor& other) noexcept { std::swap(fd_, other.fd_); }

  // Explicitly closes the underlying file descriptor and marks this instance as
  // invalid.
  void Close() noexcept {
    FileDescriptor other;
    SwapWith(other);
  }

  // Assigns ownership from another instance.
  FileDescriptor& operator=(FileDescriptor other) noexcept {
    SwapWith(other);
    return *this;
  }

  // Returns true if the instance holds a valid, non-negative file descriptor.
  bool IsValid() const noexcept { return fd_ >= 0; }

  // Gets the underlying raw file descriptor.
  operator int() const noexcept { return fd_; }

  // Resizes the underlying file to the specified size.
  //
  // Preconditions: IsValid() is true; new_size >= 0.
  //
  // Throws ExitCode::CANNOT_WRITE_CACHE on failure.
  void Truncate(i64 const new_size) const;

  // Writes the data in 'b' into the file at the specified absolute position.
  // Returns the offset immediately following the written data.
  //
  // Preconditions: IsValid() is true; pos >= 0.
  //
  // Throws ExitCode::CANNOT_WRITE_CACHE on failure.
  i64 Write(std::string_view b, i64 pos) const;

  // Function signature for reporting discovered sparse holes.
  using HoleCallback = std::function<void(i64, i64)>;

  // Writes the data in 'b' to the file at 'pos' while detecting and skipping
  // large NUL sequences. This creates a sparse file to save disk space.
  // 'last_hole_start' tracks the start of the current potentially sparse
  // region. 'on_hole' is called whenever a new hole is finalized.
  //
  // Returns the position immediately following the last written bytes,
  // or `last_hole_start` if nothing was written.
  //
  // Preconditions: IsValid() is true; pos >= 0.
  //
  // Throws ExitCode::CANNOT_WRITE_CACHE on failure.
  i64 WriteBytesAndSkipHoles(std::string_view b,
                             i64 pos,
                             i64 last_hole_start,
                             const HoleCallback& on_hole = nullptr) const;

 private:
  friend class FileDescriptorTest;

  // Raw file descriptor.
  int fd_;
};

}  // namespace fuse_archive

#endif  // LIB_FILE_DESCRIPTOR_H
