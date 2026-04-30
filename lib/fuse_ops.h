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

#ifndef LIB_FUSE_OPS_H
#define LIB_FUSE_OPS_H

#include <fuse.h>

namespace fuse_archive {

// Returns a populated fuse_operations struct containing all the callback
// functions required for the FUSE filesystem behavior.
fuse_operations GetFuseOperations();

}  // namespace fuse_archive

#endif  // LIB_FUSE_OPS_H
