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

#include "hashed_string.h"

#include <cassert>
#include <string_view>
#include <unordered_set>

#include "util.h"

namespace fuse_archive {

HashedStrings* g_unique_strings = nullptr;

const HashedString* GetUniqueOrNull(std::string_view const s) {
  if (!g_unique_strings) {
    return nullptr;
  }

  HashedStrings::const_iterator const it =
      g_unique_strings->find(HashedStringView(s));
  if (it == g_unique_strings->cend()) {
    return nullptr;
  }

  assert(it->string == s);
  return &*it;
}

const HashedString* GetOrCreateUnique(std::string_view const s) {
  if (!g_unique_strings) {
    g_unique_strings = new HashedStrings();
  }

  assert(g_unique_strings);
  HashedStrings::const_iterator const it =
      g_unique_strings->insert(HashedStringView(s)).first;
  assert(it != g_unique_strings->cend());
  assert(it->string == s);
  return &*it;
}

}  // namespace fuse_archive
