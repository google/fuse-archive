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

#ifndef LIB_PATH_H
#define LIB_PATH_H

#include <iostream>
#include <string>
#include <string_view>
#include <utility>

namespace fuse_archive {

// Path manipulations.
class Path : public std::string_view {
 public:
  Path() = default;
  Path(const char* const path) : std::string_view(path) {}
  Path(std::string_view const path) : std::string_view(path) {}

  // Returns a new Path with trailing '/' separators removed.
  Path WithoutTrailingSeparator() const;

  // Returns the position of the last dot that starts a valid filename
  // extension, or `size()` if no extension is found. Handles various edge cases
  // like trailing slashes, trailing dots, and multi-dot hidden files (e.g.
  // "...foo").
  //
  // If the path ends with a slash, then it does not have an extension:
  // * "/" -> no extension
  // * "foo/" -> no extension
  // * "a.b/" -> no extension
  //
  // If the path ends with a dot, then it does not have an extension:
  // * "." -> no extension
  // * ".." -> no extension
  // * "..." -> no extension
  // * "foo." -> no extension
  // * "foo..." -> no extension
  //
  // If the filename starts with a dot or a sequence of dots, but does not have
  // any other dot after that, then it does not have an extension:
  // ".foo" -> no extension
  // "...foo" -> no extension
  // "a.b/...foo" -> no extension
  //
  // An extension cannot contain a space:
  // * "foo. " -> no extension
  // * "foo.a b" -> no extension
  // * "foo. (1)" -> no extension
  //
  // An extension cannot be longer than 8 bytes, including the leading dot:
  // * "foo.tool" -> ".tool"
  // * "foo.toolongforanextension" -> no extension
  size_type FinalExtensionPosition() const;

  // Returns the position of the dot that starts the filename extension,
  // accounting for common double extensions like ".tar.gz" or ".tar.bz2".
  size_type ExtensionPosition() const;

  // Returns a new Path with the extension removed (if any).
  Path WithoutExtension() const { return substr(0, ExtensionPosition()); }

  // Returns a safe character position `x` where `0 <= x <= i` that does not
  // split a multi-byte UTF-8 character. Used for safe filename truncation.
  size_type TruncationPosition(size_type i) const;

  // Splits the path into a pair containing the parent directory and the
  // basename.
  std::pair<Path, Path> Split() const;

  // Appends a relative or absolute 'tail' to the 'head' string.
  // If 'tail' is absolute, 'head' is replaced. Otherwise, 'tail' is joined
  // with a '/' separator if needed.
  static void Append(std::string* head, std::string_view tail);

  // If the path starts with 'prefix', removes it and returns true.
  bool Consume(std::string_view prefix);

  // If the path starts with the character 'prefix', removes it and returns
  // true.
  bool Consume(char prefix);

  // Returns a normalized version of the path, collapsing redundant dots and
  // slashes. An optional 'prefix' (default "/") can be prepended.
  std::string Normalized(std::string prefix = "/") const;

  // Normalizes the path and appends it to the 'to' string.
  void NormalizeAppend(std::string* to) const;

  // Formats the Path for logging output.
  friend std::ostream& operator<<(std::ostream& out, Path path);
};

}  // namespace fuse_archive

#endif  // LIB_PATH_H
