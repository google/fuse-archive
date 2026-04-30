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

#include "path.h"

#include <cassert>
#include <climits>
#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>

#include "common.h"
#include "util.h"

namespace fuse_archive {

Path Path::WithoutTrailingSeparator() const {
  Path path = *this;

  // Don't remove the first character, even if it is a '/'.
  while (path.size() > 1 && path.back() == '/') {
    path.remove_suffix(1);
  }

  return path;
}

size_t Path::FinalExtensionPosition() const {
  size_type const last_dot = find_last_of("/. ");
  if (last_dot == npos || at(last_dot) != '.' || last_dot == 0 ||
      last_dot == size() - 1 || size() - last_dot > 8) {
    return size();
  }

  if (size_type const i = find_last_not_of('.', last_dot - 1);
      i == npos || at(i) == '/') {
    return size();
  }

  return last_dot;
}

size_t Path::ExtensionPosition() const {
  size_type const last_dot = FinalExtensionPosition();
  if (last_dot >= size()) {
    return last_dot;
  }

  // Extract extension without dot and in ASCII lowercase.
  assert(at(last_dot) == '.');
  const std::string ext = ToLower(substr(last_dot + 1));

  // Is it a special extension?
  static std::unordered_set<std::string_view> const special_exts = {
      "asc",   "b64", "base64", "br",    "brotli", "bz",   "bz2",
      "bzip2", "gpg", "grz",    "grzip", "gz",     "gzip", "lrz",
      "lrzip", "lz",  "lzip",   "lz4",   "lzma",   "lzo",  "lzop",
      "pgp",   "uu",  "xz",     "z",     "zst",    "zstd"};

  if (special_exts.contains(ext)) {
    return Path(substr(0, last_dot)).FinalExtensionPosition();
  }

  return last_dot;
}

size_t Path::TruncationPosition(size_type i) const {
  if (i >= size()) {
    return size();
  }

  while (true) {
    // Avoid truncating at a UTF-8 trailing byte.
    while (i > 0 && (at(i) & 0b1100'0000) == 0b1000'0000) {
      --i;
    }

    if (i == 0) {
      return i;
    }

    std::string_view const zero_width_joiner = "\u200D";

    // Avoid truncating at a zero-width joiner.
    if (substr(i).starts_with(zero_width_joiner)) {
      --i;
      continue;
    }

    // Avoid truncating just after a zero-width joiner.
    if (substr(0, i).ends_with(zero_width_joiner)) {
      i -= zero_width_joiner.size();
      if (i > 0) {
        --i;
        continue;
      }
    }

    return i;
  }
}

std::pair<Path, Path> Path::Split() const {
  std::string_view::size_type const i = find_last_of('/') + 1;
  return {Path(substr(0, i)).WithoutTrailingSeparator(), substr(i)};
}

void Path::Append(std::string* const head, std::string_view const tail) {
  assert(head);

  if (tail.empty()) {
    return;
  }

  if (head->empty() || tail.starts_with('/')) {
    *head = tail;
    return;
  }

  assert(!head->empty());
  assert(!tail.empty());

  if (!head->ends_with('/')) {
    *head += '/';
  }

  *head += tail;
}

bool Path::Consume(std::string_view const prefix) {
  bool const ok = starts_with(prefix);
  if (ok) {
    remove_prefix(prefix.size());
  }
  return ok;
}

bool Path::Consume(char const prefix) {
  bool const ok = starts_with(prefix);
  if (ok) {
    remove_prefix(1);
  }
  return ok;
}

std::string Path::Normalized(std::string prefix) const {
  NormalizeAppend(&prefix);
  return prefix;
}

void Path::NormalizeAppend(std::string* const to) const {
  assert(to);
  std::string& result = *to;

  Path in = *this;
  if (in.empty()) {
    Append(&result, "?");
    return;
  }

  if (in == ".") {
    return;
  }

  do {
    while (in.Consume('/')) {
    }
  } while (in.Consume("./") || in.Consume("../"));

  const size_t initial_size = result.size();

  // Extract part after part
  while (true) {
    size_type i = in.find_first_not_of('/');
    if (i == npos) {
      break;
    }

    in.remove_prefix(i);
    assert(!in.empty());

    i = in.find_first_of('/');
    std::string_view part = in.substr(0, i);
    assert(!part.empty());
    in.remove_prefix(part.size());

    std::string_view extension;
    if (i == npos) {
      const size_type last_dot = Path(part).ExtensionPosition();
      extension = part.substr(last_dot);
      part.remove_suffix(extension.size());
    }

    part = part.substr(
        0, Path(part).TruncationPosition(NAME_MAX - extension.size()));

    if (part.empty() || part == "." || part == "..") {
      part = "?";
    }

    if (extension.empty()) {
      Append(&result, part);
    } else {
      Append(&result, StrCat(part, extension));
    }
  }

  if (result.size() > PATH_MAX) {
    std::string last_part(Path(result).Split().second);
    result.resize(initial_size);
    Append(&result, "Too Deep");
    Append(&result, last_part);
  }
}

std::ostream& operator<<(std::ostream& out, Path const path) {
  if (g_redact) {
    return out << "(redacted)";
  }

  out.put('\'');
  for (char const c : path) {
    switch (c) {
      case '\\':
      case '\'':
        out.put('\\');
        out.put(c);
        break;
      default:
        int const i = static_cast<unsigned char>(c);
        if (std::iscntrl(i)) {
          out << "\\x" << std::hex << std::setw(2) << std::setfill('0') << i
              << std::dec;
        } else {
          out.put(c);
        }
    }
  }

  out.put('\'');
  return out;
}

}  // namespace fuse_archive
