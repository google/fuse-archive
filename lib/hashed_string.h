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

#ifndef LIB_HASHED_STRING_H
#define LIB_HASHED_STRING_H

#include "util.h"

#include <string>
#include <string_view>
#include <unordered_set>

namespace fuse_archive {

// A string view paired with its pre-computed hash for fast lookups.
struct HashedStringView {
  std::string_view string;
  size_t hash;

  // Constructs a view and computes the hash of the given string.
  HashedStringView(std::string_view s)
      : string(s), hash(ComputeStringHash(s)) {}

  // Constructs a view with a manually provided hash.
  HashedStringView(std::string_view s, size_t h) : string(s), hash(h) {}
};

// A managed string and its pre-computed hash, used for deduplication.
struct HashedString {
  std::string string;
  size_t hash;

  // Promotes a HashedStringView to a managed HashedString.
  HashedString(const HashedStringView& x) : string(x.string), hash(x.hash) {}
};

// Equality comparator for heterogeneous lookups (HashedString vs
// HashedStringView).
struct IsEqual {
  using is_transparent = std::true_type;

  // Returns true if both objects have the same hash and identical string
  // content.
  bool operator()(const auto& a, const auto& b) const {
    return a.hash == b.hash && a.string == b.string;
  }
};

// Hash accessor for heterogeneous lookups.
struct Hash {
  using is_transparent = std::true_type;

  // Returns the pre-computed hash of the given object.
  size_t operator()(const auto& x) const { return x.hash; }
};

// Set of unique (deduplicated) strings used to save memory for repeated
// names/attributes.
using HashedStrings = std::unordered_set<HashedString, Hash, IsEqual>;

extern HashedStrings* g_unique_strings;

// Returns a pointer to the unique string instance if it already exists, or
// nullptr.
const HashedString* GetUniqueOrNull(std::string_view s);

// Returns a pointer to the unique string instance, creating it if it doesn't
// exist.
const HashedString* GetOrCreateUnique(std::string_view s);

}  // namespace fuse_archive

#endif  // LIB_HASHED_STRING_H
