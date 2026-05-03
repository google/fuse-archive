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

#ifndef LIB_UTIL_H
#define LIB_UTIL_H

#include <archive.h>
#include <archive_entry.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syslog.h>
#include <syslog.h>
#include <unistd.h>

#include <cassert>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <memory>
#include <ostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include <boost/functional/hash.hpp>

namespace fuse_archive {

class FileDescriptor;

// Type aliases for shorter code.
using i64 = std::int64_t;
using Stat = struct stat;
using StatVfs = struct statvfs;
using SteadyClock = std::chrono::steady_clock;
using SystemClock = std::chrono::system_clock;

// Concatenates multiple arguments into a single string.
template <typename... Args>
std::string StrCat(Args&&... args) {
  std::ostringstream out;
  (out << ... << std::forward<Args>(args));
  return std::move(out).str();
}

// Simple timer for measuring elapsed time in debug logs.
struct Timer {
  // The time point when the timer was started or reset.
  SteadyClock::time_point start = SteadyClock::now();

  // Resets the timer's start time to the current moment.
  void Reset() { start = SteadyClock::now(); }

  // Returns the elapsed time in milliseconds since the last start or reset.
  auto Milliseconds() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               SteadyClock::now() - start)
        .count();
  }

  // Formats the timer for logging output (e.g. "150 ms").
  friend std::ostream& operator<<(std::ostream& out, const Timer& timer) {
    return out << timer.Milliseconds() << " ms";
  }
};

// Throttles log messages to prevent flooding (e.g. progress updates).
class Beat {
 public:
  // Initializes a beat with the specified minimum period between successful
  // Keep() calls.
  explicit Beat(std::chrono::milliseconds period = std::chrono::seconds(1))
      : period_(period), next_(SteadyClock::now() + period) {}

  // Returns true if enough time has passed since the last successful Keep()
  // call.
  bool Keep() const {
    auto const now = SteadyClock::now();
    if (now < next_) {
      return false;
    }

    count_ += 1;
    next_ = now + period_;
    return true;
  }

  // Returns the total number of successful Keep() calls made.
  int Count() const { return count_; }

 private:
  std::chrono::milliseconds const period_;
  mutable int count_ = 0;
  mutable SteadyClock::time_point next_;
};

// Log levels following the syslog standard.
enum class LogLevel {
  DEBUG = LOG_DEBUG,
  INFO = LOG_INFO,
  WARNING = LOG_WARNING,
  ERROR = LOG_ERR,
};

extern LogLevel g_log_level;

// Sets the global minimum log level for the application.
void SetLogLevel(LogLevel level);

#define LOG_IS_ON(level) \
  (::fuse_archive::LogLevel::level <= ::fuse_archive::g_log_level)

extern bool g_latest_log_is_ephemeral;
extern bool g_redact;

enum class ProgressMessage : int;

// Internal logger class that accumulates messages into a stream and flushes
// them to syslog/stderr on destruction.
class Logger {
 public:
  // Creates a logger for the given level, optionally including a system error
  // code (errno).
  explicit Logger(LogLevel const level, int const err = -1)
      : level_(level), err_(err) {}

  Logger(const Logger&) = delete;

  // Flushes the accumulated log message.
  ~Logger();

  // Streams a value into the log message.
  Logger&& operator<<(const auto& a) && {
    oss_ << a;
    return std::move(*this);
  }

  // Specialized stream operator for progress messages that marks the log as
  // ephemeral.
  Logger&& operator<<(ProgressMessage const a) && {
    oss_ << static_cast<int>(a) << "%";
    ephemeral_ = true;
    return std::move(*this);
  }

 private:
  LogLevel const level_;
  int const err_;
  std::ostringstream oss_;
  bool ephemeral_ = false;
};

#define LOG(level)                                                    \
  if (::fuse_archive::LogLevel::level <= ::fuse_archive::g_log_level) \
  ::fuse_archive::Logger(::fuse_archive::LogLevel::level)

#define PLOG(level)                                                   \
  if (::fuse_archive::LogLevel::level <= ::fuse_archive::g_log_level) \
  ::fuse_archive::Logger(::fuse_archive::LogLevel::level, errno)

// ---- Exit Codes

// Standard exit codes for the application, mapping logic failures to shell
// status codes.
enum class ExitCode {
  GENERIC_FAILURE = 1,
  CANNOT_CREATE_MOUNT_POINT = 10,
  CANNOT_OPEN_ARCHIVE = 11,
  CANNOT_CREATE_CACHE = 12,
  CANNOT_WRITE_CACHE = 13,
  PASSPHRASE_REQUIRED = 20,
  PASSPHRASE_INCORRECT = 21,
  PASSPHRASE_NOT_SUPPORTED = 22,
  UNKNOWN_ARCHIVE_FORMAT = 30,
  INVALID_ARCHIVE_HEADER = 31,
  INVALID_ARCHIVE_CONTENTS = 32,
};

// Formats an ExitCode for logging.
std::ostream& operator<<(std::ostream& out, ExitCode e);

// Returns a string representation of the current libarchive error.
std::string_view GetErrorString(struct archive* a);

// Parses a libarchive error message and throws the corresponding ExitCode.
void ThrowExitCode(std::string_view e);

// Returns a + b.
// Throws ExitCode::INVALID_ARCHIVE_CONTENTS in case of integer overflow.
i64 SafeAdd(i64 a, i64 b);

// Default block size used for statvfs and block count calculations.
constexpr blksize_t block_size = 512;

// Represents a sparse region (hole) in a file.
struct Hole {
  i64 from, to;

  // Creates a hole from the specified starting offset to the end offset
  // (exclusive).
  Hole(i64 const from, i64 const to) : from(from), to(to) {
    assert(0 <= from && from < to);
  }

  // Calculates the number of filesystem blocks saved by this hole.
  i64 GetSavedBlocks() const;

  // Formats a Hole for logging (e.g. "Hole [1024, 2048)").
  friend std::ostream& operator<<(std::ostream& out, const Hole& h);
};

// A sorted collection of holes representing a sparse file's structure.
using Holes = std::vector<Hole>;

enum class Whence : int;

// Formats a seek 'whence' value (SEEK_SET, etc.) for logging.
std::ostream& operator<<(std::ostream& out, Whence whence);

// Computes a non-cryptographic hash of the given string.
size_t ComputeStringHash(std::string_view s);

// Returns a lower-case version of the given string.
std::string ToLower(std::string_view s);

// Returns the path to a directory suitable for temporary cache files.
std::string GetCacheDir();

// Creates and opens a hidden temporary file for uncompressed data caching.
FileDescriptor CreateCacheFile(bool memcache = false);

// Validates that a cache file descriptor is valid and points to an empty file.
void CheckCacheFile(const FileDescriptor& fd);

}  // namespace fuse_archive

#endif  // LIB_UTIL_H
