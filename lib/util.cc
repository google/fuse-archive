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

#include "util.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <iostream>

#include <archive.h>
#include <archive_entry.h>

#include "common.h"
#include "path.h"

namespace fuse_archive {

i64 Hole::GetSavedBlocks() const {
  const i64 blocks_to = to / block_size;
  const i64 blocks_from = (from + block_size - 1) / block_size;
  return std::max<i64>(0, blocks_to - blocks_from);
}

std::ostream& operator<<(std::ostream& out, const Hole& h) {
  return out << "Hole from " << h.from << " to " << h.to;
}

LogLevel g_log_level = LogLevel::INFO;
bool g_latest_log_is_ephemeral = false;
bool g_redact = false;

void SetLogLevel(LogLevel level) {
  g_log_level = level;
  setlogmask(LOG_UPTO(static_cast<int>(level)));
}

std::string ToLower(std::string_view const s) {
  std::string r(s);
  for (char& c : r) {
    if ('A' <= c && c <= 'Z') {
      c += 'a' - 'A';
    }
  }

  return r;
}

size_t ComputeStringHash(std::string_view const s) {
  size_t h = 0;

  for (char const c : s) {
    boost::hash_combine(h, c);
  }

  return h;
}

Logger::~Logger() {
  if (err_ >= 0) {
    if (LOG_IS_ON(DEBUG)) {
      oss_ << ": Error " << err_;
    }
    oss_ << ": " << strerror(err_);
  }

  if (g_latest_log_is_ephemeral && isatty(STDERR_FILENO)) {
    std::string_view const s = "\033[F\033[K";
    std::ignore = write(STDERR_FILENO, s.data(), s.size());
  }

  syslog(static_cast<int>(level_), "%s", std::move(oss_).str().c_str());
  g_latest_log_is_ephemeral = ephemeral_;
}

std::ostream& operator<<(std::ostream& out, ExitCode const e) {
  switch (e) {
#define PRINT(s)    \
  case ExitCode::s: \
    return out << #s << " (" << int(ExitCode::s) << ")";
    PRINT(GENERIC_FAILURE)
    PRINT(CANNOT_CREATE_MOUNT_POINT)
    PRINT(CANNOT_OPEN_ARCHIVE)
    PRINT(CANNOT_CREATE_CACHE)
    PRINT(CANNOT_WRITE_CACHE)
    PRINT(PASSPHRASE_REQUIRED)
    PRINT(PASSPHRASE_INCORRECT)
    PRINT(PASSPHRASE_NOT_SUPPORTED)
    PRINT(UNKNOWN_ARCHIVE_FORMAT)
    PRINT(INVALID_ARCHIVE_HEADER)
    PRINT(INVALID_ARCHIVE_CONTENTS)
#undef PRINT
  }

  return out << "Exit Code " << int(e);
}

std::string_view GetErrorString(struct archive* const a) {
  // Work around bug https://github.com/libarchive/libarchive/issues/2495.
  return archive_error_string(a) ?: "Unspecified error";
}

void ThrowExitCode(std::string_view const e) {
  if (e.starts_with("Incorrect passphrase")) {
    throw ExitCode::PASSPHRASE_INCORRECT;
  }

  if (e.starts_with("Passphrase required")) {
    throw ExitCode::PASSPHRASE_REQUIRED;
  }

  std::string_view const not_supported_prefixes[] = {
      "Crypto codec not supported",
      "Decryption is unsupported",
      "Encrypted file is unsupported",
      "Encryption is not supported",
      "RAR encryption support unavailable",
      "The archive header is encrypted, but currently not supported",
      "The file content is encrypted, but currently not supported",
      "Unsupported encryption format",
  };

  for (std::string_view const prefix : not_supported_prefixes) {
    if (e.starts_with(prefix)) {
      throw ExitCode::PASSPHRASE_NOT_SUPPORTED;
    }
  }
}

i64 SafeAdd(i64 const a, i64 const b) {
  i64 r;
  if (__builtin_add_overflow(a, b, &r)) {
    LOG(ERROR) << "Integer overflow with " << a << " + " << b;
    throw ExitCode::INVALID_ARCHIVE_CONTENTS;
  }

  return r;
}

std::ostream& operator<<(std::ostream& out, Whence const whence) {
  switch (static_cast<int>(whence)) {
#define PRINT(s) \
  case SEEK_##s: \
    return out << "SEEK_" << #s;
    PRINT(SET)
    PRINT(CUR)
    PRINT(END)
    PRINT(DATA)
    PRINT(HOLE)
#undef PRINT
  }

  return out << "SEEK_" << static_cast<int>(whence);
}

std::string GetCacheDir() {
  const char* const val = std::getenv("TMPDIR");
  return val && *val ? val : "/tmp";
}

FileDescriptor CreateCacheFile(bool memcache) {
  FileDescriptor fd;

  if (memcache) {
#if defined(__linux__)
    fd = FileDescriptor(memfd_create("fuse-archive", MFD_CLOEXEC));
    if (fd.IsValid()) {
      LOG(DEBUG) << "Created memory-backed cache file";
      return fd;
    }

    PLOG(ERROR) << "Cannot create memory-backed cache file";
    throw ExitCode::CANNOT_CREATE_CACHE;
#else
    LOG(ERROR) << "Memory-backed cache file is only supported on Linux";
    throw ExitCode::CANNOT_CREATE_CACHE;
#endif
  }

  std::string const cache_dir = GetCacheDir();

#if !defined(__FreeBSD__) && !defined(__OpenBSD__) && !defined(__APPLE__)
  fd = FileDescriptor(open(cache_dir.c_str(), O_TMPFILE | O_RDWR | O_EXCL, 0));
  if (fd.IsValid()) {
    LOG(DEBUG) << "Created anonymous cache file in " << Path(cache_dir);
    return fd;
  }

  if (errno != ENOTSUP) {
    PLOG(ERROR) << "Cannot create anonymous cache file in " << Path(cache_dir);
    throw ExitCode::CANNOT_CREATE_CACHE;
  }

  // Some filesystems, such as overlayfs, do not support the creation of temp
  // files with O_TMPFILE. Unfortunately, these filesystems are sometimes used
  // for the /tmp directory. In that case, create a named temp file, and unlink
  // it immediately.
  assert(errno == ENOTSUP);
  LOG(DEBUG) << "The filesystem of " << Path(cache_dir)
             << " does not support O_TMPFILE";
#endif

  std::string path = cache_dir;
  Path::Append(&path, "XXXXXX");
  fd = FileDescriptor(mkstemp(path.data()));

  if (!fd.IsValid()) {
    PLOG(ERROR) << "Cannot create named cache file in " << Path(cache_dir);
    throw ExitCode::CANNOT_CREATE_CACHE;
  }

  LOG(DEBUG) << "Created cache file " << Path(path);

  if (unlink(path.c_str()) < 0) {
    PLOG(ERROR) << "Cannot unlink cache file " << Path(path);
    throw ExitCode::CANNOT_CREATE_CACHE;
  }

  return fd;
}

void CheckCacheFile(const FileDescriptor& fd) {
  Stat z;
  if (fstat(fd, &z) != 0) {
    PLOG(ERROR) << "Cannot stat cache file";
    throw ExitCode::CANNOT_CREATE_CACHE;
  }

  if (z.st_size != 0) {
    LOG(ERROR) << "Cache file is not empty: It contains " << z.st_size
               << " bytes";
    throw ExitCode::CANNOT_CREATE_CACHE;
  }
}

}  // namespace fuse_archive
