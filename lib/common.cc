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

#include "common.h"

#include <archive.h>
#include <sys/stat.h>

#include <iostream>
#include <vector>

namespace fuse_archive {

std::ostream& operator<<(std::ostream& out, ArchiveFormat const f) {
  switch (static_cast<int>(f)) {
    case 0:
      return out << "NONE";
#define PRINT(s)           \
  case ARCHIVE_FORMAT_##s: \
    return out << #s;
      PRINT(CPIO)
      PRINT(CPIO_POSIX)
      PRINT(CPIO_BIN_LE)
      PRINT(CPIO_BIN_BE)
      PRINT(CPIO_SVR4_NOCRC)
      PRINT(CPIO_SVR4_CRC)
      PRINT(CPIO_AFIO_LARGE)
      PRINT(CPIO_PWB)
      PRINT(SHAR)
      PRINT(SHAR_BASE)
      PRINT(SHAR_DUMP)
      PRINT(TAR)
      PRINT(TAR_USTAR)
      PRINT(TAR_PAX_INTERCHANGE)
      PRINT(TAR_PAX_RESTRICTED)
      PRINT(TAR_GNUTAR)
      PRINT(ISO9660)
      PRINT(ISO9660_ROCKRIDGE)
      PRINT(ZIP)
      PRINT(EMPTY)
      PRINT(AR)
      PRINT(AR_GNU)
      PRINT(AR_BSD)
      PRINT(MTREE)
      PRINT(RAW)
      PRINT(XAR)
      PRINT(LHA)
      PRINT(CAB)
      PRINT(RAR)
      PRINT(7ZIP)
      PRINT(WARC)
      PRINT(RAR_V5)
#undef PRINT
  }
  return out << static_cast<int>(f);
}

FileType GetFileType(mode_t const mode) {
  // Consider an unknown file type as a regular file.
  // https://github.com/google/fuse-archive/issues/47
  const mode_t ft = mode & S_IFMT;
  return ft ? FileType(ft) : FileType::File;
}

std::ostream& operator<<(std::ostream& out, FileType const t) {
  switch (t) {
    case FileType::BlockDevice:
      return out << "Block Device";
    case FileType::CharDevice:
      return out << "Character Device";
    case FileType::Directory:
      return out << "Directory";
    case FileType::Fifo:
      return out << "FIFO";
    case FileType::File:
      return out << "File";
    case FileType::Socket:
      return out << "Socket";
    case FileType::Symlink:
      return out << "Symlink";
  }

  return out << "Unknown";
}

}  // namespace fuse_archive
