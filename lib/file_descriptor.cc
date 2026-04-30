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

#include "file_descriptor.h"

#include <unistd.h>

#include <cassert>
#include <cerrno>
#include <string_view>

#include "util.h"

namespace fuse_archive {

void FileDescriptor::Truncate(i64 const new_size) const {
  assert(IsValid());
  assert(new_size >= 0);

  while (ftruncate(fd_, new_size) < 0) {
    if (errno != EINTR) {
      PLOG(ERROR) << "Cannot resize file to " << new_size << " bytes";
      throw ExitCode::CANNOT_WRITE_CACHE;
    }
  }
}

i64 FileDescriptor::Write(std::string_view b, i64 pos) const {
  assert(IsValid());
  assert(pos >= 0);

  while (!b.empty()) {
    ssize_t const r = pwrite(fd_, b.data(), b.size(), pos);
    if (r < 0) {
      if (errno == EINTR) {
        continue;
      }

      PLOG(ERROR) << "Cannot write to cache";
      throw ExitCode::CANNOT_WRITE_CACHE;
    }

    assert(r <= b.size());
    b.remove_prefix(r);
    pos = SafeAdd(pos, r);
  }

  return pos;
}

i64 FileDescriptor::WriteBytesAndSkipHoles(std::string_view b,
                                           i64 pos,
                                           i64 last_hole_start,
                                           const HoleCallback& on_hole) const {
  constexpr size_t npos = std::string_view::npos;
  constexpr size_t min_hole_size = 1024;

  size_t i = b.find_first_not_of('\0');
  if (i == npos) {
    return last_hole_start;
  }

  while (true) {
    assert(i < b.size());
    b.remove_prefix(i);
    pos += i;
    i = 0;

    if (on_hole && pos - last_hole_start >= min_hole_size) {
      on_hole(last_hole_start, pos);
    }

    size_t j;
    do {
      assert(!b.empty());
      assert(!b.starts_with('\0'));

      j = b.find_first_of('\0', i);
      if (j == npos) {
        return Write(b, pos);
      }

      assert(i < j && j < b.size());

      i = b.find_first_not_of('\0', j);
      if (i == npos) {
        return Write(b.substr(0, j), pos);
      }

      assert(j < i && i < b.size());
    } while (i - j < min_hole_size);

    // Found a sequence of NUL bytes long enough to be considered a "hole".
    last_hole_start = Write(b.substr(0, j), pos);
  }
}

}  // namespace fuse_archive
