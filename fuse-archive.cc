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

// fuse-archive mounts an archive or compressed file (e.g. foo.tar, foo.tar.gz,
// foo.xz, foo.zip) as a read-only FUSE file system
// (https://en.wikipedia.org/wiki/Filesystem_in_Userspace).

#include <archive.h>
#include <archive_entry.h>
#include <fcntl.h>
#include <fuse.h>
#include <langinfo.h>
#include <locale.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <sys/types.h>
#include <syslog.h>
#include <termios.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cassert>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <functional>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <limits>
#include <locale>
#include <memory>
#include <new>
#include <ostream>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <boost/functional/hash.hpp>
#include <boost/intrusive/list.hpp>
#include <boost/intrusive/slist.hpp>
#include <boost/intrusive/unordered_set.hpp>

// ---- Compile-time Configuration

#define PROGRAM_NAME "fuse-archive"

// Even minor versions (e.g. 1.0 or 1.2) are stable versions.
// Odd minor versions (e.g. 1.1 or 1.3) are development versions.
#define PROGRAM_VERSION "1.19"

namespace {

// Type alias for shorter code.
using i64 = std::int64_t;

template <typename... Args>
std::string StrCat(Args&&... args) {
  std::ostringstream out;
  (out << ... << std::forward<Args>(args));
  return std::move(out).str();
}

// Timer for debug logs.
struct Timer {
  using Clock = std::chrono::steady_clock;

  // Start time.
  Clock::time_point const start = Clock::now();

  // Elapsed time in milliseconds.
  auto Milliseconds() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() -
                                                                 start)
        .count();
  }

  friend std::ostream& operator<<(std::ostream& out, const Timer& timer) {
    return out << timer.Milliseconds() << " ms";
  }
};

enum class LogLevel {
  DEBUG = LOG_DEBUG,
  INFO = LOG_INFO,
  WARNING = LOG_WARNING,
  ERROR = LOG_ERR,
};

LogLevel g_log_level = LogLevel::INFO;

void SetLogLevel(LogLevel const level) {
  g_log_level = level;
  setlogmask(LOG_UPTO(static_cast<int>(level)));
}

#define LOG_IS_ON(level) (LogLevel::level <= g_log_level)

bool g_latest_log_is_ephemeral = false;

enum class ProgressMessage : int;

// Accumulates a log message and logs it.
class Logger {
 public:
  explicit Logger(LogLevel const level, int err = -1)
      : level_(level), err_(err) {}

  Logger(const Logger&) = delete;

  ~Logger() {
    if (err_ >= 0) {
      if (LOG_IS_ON(DEBUG)) {
        oss_ << ": Error " << err_;
      }
      oss_ << ": " << strerror(err_);
    }

    if (g_latest_log_is_ephemeral && isatty(STDERR_FILENO)) {
      std::string_view const s = "\e[F\e[K";
      std::ignore = write(STDERR_FILENO, s.data(), s.size());
    }

    syslog(static_cast<int>(level_), "%s", std::move(oss_).str().c_str());
    g_latest_log_is_ephemeral = ephemeral_;
  }

  Logger&& operator<<(const auto& a) && {
    oss_ << a;
    return std::move(*this);
  }

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

#define LOG(level)                    \
  if (LogLevel::level <= g_log_level) \
  Logger(LogLevel::level)

#define PLOG(level)                   \
  if (LogLevel::level <= g_log_level) \
  Logger(LogLevel::level, errno)

// ---- Exit Codes

// These are values passed to the exit function, or returned by main. These are
// (Linux or Linux-like) application exit codes, not library error codes.
//
// Note that, unless the -f command line option was passed for foreground
// operation, the parent process may very well ignore the exit code value after
// daemonization succeeds.

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

std::string_view GetErrorString(archive* const a) {
  // Work around bug https://github.com/libarchive/libarchive/issues/2495.
  return archive_error_string(a) ?: "Unspecified error";
}

constexpr blksize_t block_size = 512;

// A hole in a sparse file.
struct Hole {
  i64 from, to;

  Hole(i64 const from, i64 const to) : from(from), to(to) {
    assert(0 <= from && from < to);
  }

  // Returns the number of blocks saved by this hole in a file of the given
  // size.
  i64 GetSavedBlocks(i64 const file_size) const {
    constexpr i64 bsm1 = block_size - 1;
    i64 const effective_to = (to < file_size) ? to : file_size + bsm1;
    i64 const saved = effective_to / block_size - (from + bsm1) / block_size;
    return std::max<i64>(0, saved);
  }

  friend std::ostream& operator<<(std::ostream& out, const Hole& h) {
    return out << "Hole from " << h.from << " to " << h.to;
  }
};

// A sorted list of holes in a sparse file.
using Holes = std::vector<Hole>;

// A scoped file descriptor.
class ScopedFile {
 public:
  // Closes this file descriptor if it is valid.
  ~ScopedFile() {
    if (IsValid() && close(fd_) < 0) {
      PLOG(ERROR) << "Cannot close file";
    }
  }

  // Creates an invalid file descriptor.
  ScopedFile() noexcept : fd_(-1) {}

  // Takes ownership of the given file descriptor, if it is valid.
  explicit ScopedFile(int fd) noexcept : fd_(fd) {}

  // Move constructor.
  ScopedFile(ScopedFile&& other) noexcept : fd_(std::exchange(other.fd_, -1)) {}

  // Swaps this file descriptor with the other one.
  void SwapWith(ScopedFile& other) noexcept { std::swap(fd_, other.fd_); }

  // Closes this file descriptor if it is valid.
  void Close() noexcept {
    ScopedFile other;
    SwapWith(other);
  }

  // Universal assignment operator.
  ScopedFile& operator=(ScopedFile other) noexcept {
    SwapWith(other);
    return *this;
  }

  // Is this file descriptor valid?
  bool IsValid() const noexcept { return fd_ >= 0; }

  // Gets the underlying raw file descriptor.
  operator int() const noexcept { return fd_; }

  // Resizes this file by either truncating it or extending it with NUL bytes.
  //
  // Preconditions:
  // - `this` must be a valid, writable file descriptor.
  // - `new_size >= 0`.
  //
  // Throws ExitCode::CANNOT_WRITE_CACHE in case of an I/O error.
  void Truncate(i64 const new_size) const {
    assert(IsValid());
    assert(new_size >= 0);

    while (ftruncate(fd_, new_size) < 0) {
      if (errno != EINTR) {
        PLOG(ERROR) << "Cannot resize file to " << new_size << " bytes";
        throw ExitCode::CANNOT_WRITE_CACHE;
      }
    }
  }

  // Writes the given bytes into this file at the given position.
  // Returns `pos + b.size()`, which is the position immediately following the
  // written bytes.
  //
  // Preconditions:
  // - `this` must be a valid, writable file descriptor.
  // - `pos >= 0`.
  //
  // Postconditions:
  // - The data in `b` is fully written to the file at `pos`.
  //
  // Throws ExitCode::CANNOT_WRITE_CACHE in case of an I/O error.
  i64 Write(std::string_view b, i64 pos) const {
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
      pos += r;
    }

    return pos;
  }

  // Callback called when a hole is discovered.
  using HoleCallback = std::function<void(i64, i64)>;

  // Writes the given bytes into this file at the given position.
  // While doing so, it detects and skips "holes" (sparse regions).
  // A "hole" is defined as a sequence of 1024 or more consecutive NUL bytes.
  //
  // Returns the position immediately following the last written bytes,
  // or `last_hole_start` if nothing was written.
  //
  // Preconditions:
  // - `this` must be a valid, writable file descriptor.
  // - `pos >= 0`.
  //
  // Postconditions:
  // - The data in `b` is written to the file at `pos`, except for holes.
  // - If `on_hole` is not null, any skipped holes are passed to it.
  //
  // Throws ExitCode::CANNOT_WRITE_CACHE in case of an I/O error.
  i64 WriteBytesAndSkipHoles(std::string_view b,
                             i64 pos,
                             i64 last_hole_start,
                             const HoleCallback& on_hole = nullptr) const {
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

 private:
  // Raw file descriptor.
  int fd_;
};

// ---- Globals

enum {
  KEY_HELP,
  KEY_VERSION,
  KEY_QUIET,
  KEY_VERBOSE,
  KEY_REDACT,
  KEY_FORCE,
  KEY_LAZY_CACHE,
  KEY_NO_CACHE,
  KEY_NO_MERGE,
  KEY_NO_TRIM,
  KEY_NO_DIRS,
  KEY_NO_SPECIALS,
  KEY_NO_SYMLINKS,
  KEY_NO_HARDLINKS,
  KEY_NO_XATTRS,
  KEY_DEFAULT_PERMISSIONS,
#if FUSE_USE_VERSION >= 30
  KEY_DIRECT_IO,
#endif
};

struct Options {
  unsigned int dmask = 0022;
  unsigned int fmask = 0022;
  int max_filter_count = 1;
};

Options g_options;

fuse_opt const g_fuse_opts[] = {
    FUSE_OPT_KEY("--help", KEY_HELP),
    FUSE_OPT_KEY("-h", KEY_HELP),
    FUSE_OPT_KEY("--version", KEY_VERSION),
    FUSE_OPT_KEY("-V", KEY_VERSION),
    FUSE_OPT_KEY("--quiet", KEY_QUIET),
    FUSE_OPT_KEY("quiet", KEY_QUIET),
    FUSE_OPT_KEY("-q", KEY_QUIET),
    FUSE_OPT_KEY("--verbose", KEY_VERBOSE),
    FUSE_OPT_KEY("verbose", KEY_VERBOSE),
    FUSE_OPT_KEY("-v", KEY_VERBOSE),
    FUSE_OPT_KEY("--redact", KEY_REDACT),
    FUSE_OPT_KEY("redact", KEY_REDACT),
    FUSE_OPT_KEY("force", KEY_FORCE),
    FUSE_OPT_KEY("lazycache", KEY_LAZY_CACHE),
    FUSE_OPT_KEY("nocache", KEY_NO_CACHE),
    FUSE_OPT_KEY("nomerge", KEY_NO_MERGE),
    FUSE_OPT_KEY("notrim", KEY_NO_TRIM),
    FUSE_OPT_KEY("nodirs", KEY_NO_DIRS),
    FUSE_OPT_KEY("nospecials", KEY_NO_SPECIALS),
    FUSE_OPT_KEY("nosymlinks", KEY_NO_SYMLINKS),
    FUSE_OPT_KEY("nohardlinks", KEY_NO_HARDLINKS),
    FUSE_OPT_KEY("noxattrs", KEY_NO_XATTRS),
    FUSE_OPT_KEY("default_permissions", KEY_DEFAULT_PERMISSIONS),
#if FUSE_USE_VERSION >= 30
    FUSE_OPT_KEY("direct_io", KEY_DIRECT_IO),
#endif
    {"dmask=%o", offsetof(Options, dmask)},
    {"fmask=%o", offsetof(Options, fmask)},
    {"maxfilters=%d", offsetof(Options, max_filter_count)},
    FUSE_OPT_END,
};

// Command line options.
bool g_help = false;
bool g_version = false;
bool g_redact = false;
bool g_force = false;
bool g_merge = true;
bool g_trim = true;
bool g_dirs = true;
bool g_specials = true;
bool g_symlinks = true;
bool g_hardlinks = true;
bool g_xattrs = true;
bool g_default_permissions = false;
#if FUSE_USE_VERSION >= 30
bool g_direct_io = false;
#endif

// Path of the mount point.
std::string g_mount_point;

// Possible caching strategies.
enum class Cache {
  None,  // No caching.
  Lazy,  // Incremental caching.
  Full,  // Full caching.
};

// Caching strategy.
Cache g_cache = Cache::Full;

// File descriptor of the cache file.
ScopedFile g_cache_fd;

// Size of the cache file.
i64 g_cache_size = 0;

// Decryption password.
std::string g_password;

// Number of times the decryption password has been requested.
int g_password_count = 0;

// Has the password been actually checked yet?
bool g_password_checked = false;

// We support 'cooked' archive files (e.g. foo.tar.gz or foo.zip) but also what
// libarchive calls 'raw' files (e.g. foo.gz), which are compressed but not
// explicitly an archive (a collection of files). libarchive can still present
// it as an implicit archive containing 1 file.
enum class ArchiveFormat : int {
  NONE = 0,
  RAW = ARCHIVE_FORMAT_RAW,
};

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

// g_uid and g_gid are the user/group IDs for the files we serve. They're the
// same as the current uid/gid.
//
// libfuse will override GetAttr's use of these variables if the "-o uid=N" or
// "-o gid=N" command line options are set.
uid_t const g_uid = getuid();
gid_t const g_gid = getgid();

using Clock = std::chrono::system_clock;
time_t const g_now = Clock::to_time_t(Clock::now());

size_t hash(std::string_view const s) {
  size_t h = 0;

  for (char const c : s) {
    boost::hash_combine(h, c);
  }

  return h;
}

// A string view and its hashed value.
struct HashedStringView {
  std::string_view string;
  size_t string_hash = hash(string);
};

// A string and its hashed value.
struct HashedString {
  std::string string;
  size_t string_hash;
  HashedString(const HashedStringView& x)
      : string(x.string), string_hash(x.string_hash) {}
};

// Function object that compares HashedStringView and HashedString objects for
// equality.
struct IsEqual {
  using is_transparent = std::true_type;
  bool operator()(const auto& a, const auto& b) const {
    return a.string_hash == b.string_hash && a.string == b.string;
  }
};

// Function object that gets the hashed value of HashedStringView and
// HashedString objects.
struct Hash {
  using is_transparent = std::true_type;
  size_t operator()(const auto& x) const { return x.string_hash; }
};

// Set of unique (i.e. deduplicated) strings. Lazily constructed and populated.
// Never destructed.
using HashedStrings = std::unordered_set<HashedString, Hash, IsEqual>;
HashedStrings* g_unique_strings = nullptr;

// Gets a pointer to the unique registered string matching the given string, or
// null if no such string has been registered.
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
  assert(it->string.data() != s.data());
  return &*it;
}

// Gets a non-null pointer to the unique registered string matching the given
// string, creating and registering it if necessary.
const HashedString* GetOrCreateUnique(std::string_view const s) {
  if (!g_unique_strings) {
    g_unique_strings = new HashedStrings();
  }

  HashedStrings::const_iterator const it =
      g_unique_strings->insert(HashedStringView(s)).first;
  assert(it != g_unique_strings->cend());
  assert(it->string == s);
  assert(it->string.data() != s.data());
  return &*it;
}

// Converts a string to ASCII lower case.
std::string ToLower(std::string_view const s) {
  std::string r(s);
  for (char& c : r) {
    if ('A' <= c && c <= 'Z') {
      c += 'a' - 'A';
    }
  }

  return r;
}

// Path manipulations.
class Path : public std::string_view {
 public:
  Path() = default;
  Path(const char* const path) : std::string_view(path) {}
  Path(std::string_view const path) : std::string_view(path) {}

  // Removes trailing separators.
  Path WithoutTrailingSeparator() const {
    Path path = *this;

    // Don't remove the first character, even if it is a '/'.
    while (path.size() > 1 && path.back() == '/') {
      path.remove_suffix(1);
    }

    return path;
  }

  // Gets the position of the dot where the filename extension starts, or
  // `size()` if there is no extension.
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
  size_type FinalExtensionPosition() const {
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

  // Same as FinalExtensionPosition, but also takes in account some double
  // extensions such as ".tar.gz".
  size_type ExtensionPosition() const {
    size_type const last_dot = FinalExtensionPosition();
    if (last_dot >= size()) {
      return last_dot;
    }

    // Extract extension without dot and in ASCII lowercase.
    assert(at(last_dot) == '.');
    const std::string ext = ToLower(substr(last_dot + 1));

    // Is it a special extension?
    static std::unordered_set<std::string_view> const special_exts = {
        "asc", "b64",  "base64", "br",   "brotli", "bz2",  "bzip2",
        "gpg", "grz",  "grzip",  "gz",   "gzip",   "lrz",  "lrzip",
        "lz",  "lzip", "lz4",    "lzma", "lzo",    "lzop", "pgp",
        "uu",  "xz",   "z",      "zst",  "zstd"};

    if (special_exts.contains(ext)) {
      return Path(substr(0, last_dot)).FinalExtensionPosition();
    }

    return last_dot;
  }

  // Removes the extension, if any.
  Path WithoutExtension() const { return substr(0, ExtensionPosition()); }

  // Gets a safe truncation position `x` such that `0 <= x && x <= i`. Avoids
  // truncating in the middle of a multi-byte UTF-8 sequence. Returns `size()`
  // if `i >= size()`.
  size_type TruncationPosition(size_type i) const {
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

  // Splits path between parent path and basename.
  std::pair<Path, Path> Split() const {
    std::string_view::size_type const i = find_last_of('/') + 1;
    return {Path(substr(0, i)).WithoutTrailingSeparator(), substr(i)};
  }

  // Appends the |tail| path to |*head|. If |tail| is an absolute path, then
  // |*head| takes the value of |tail|. If |tail| is a relative path, then it is
  // appended to |*head|. A '/' separator is added if |*head| doesn't already
  // end with one.
  static void Append(std::string* const head, std::string_view const tail) {
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

  bool Consume(std::string_view const prefix) {
    bool const ok = starts_with(prefix);
    if (ok) {
      remove_prefix(prefix.size());
    }
    return ok;
  }

  bool Consume(char const prefix) {
    bool const ok = starts_with(prefix);
    if (ok) {
      remove_prefix(1);
    }
    return ok;
  }

  // Gets normalized path.
  std::string Normalized(std::string prefix = "/") const {
    NormalizeAppend(&prefix);
    return prefix;
  }

  void NormalizeAppend(std::string* const to) const {
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
};

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

// An open archive file descriptor with other archive metadata.
struct ArchiveDescriptor {
  // Command line argument naming the archive file.
  std::string path;

  // Archive name without its extension.
  std::string name_without_extension;

  // File descriptor of the opened archive file.
  ScopedFile fd;

  // Size of this archive file.
  i64 size = 0;

  // Format of this archive.
  ArchiveFormat format = ArchiveFormat::NONE;

  // Number of decompression or decoding filters (e.g. `gz`, `bz2`, `br`, `uu`,
  // `b64`).
  int filter_count = 0;

  // Is there an archive format that requires caching and random access to the
  // decompressed data?
  bool filtered_zip = false;
};

std::vector<ArchiveDescriptor> g_archives;

enum class FileType : mode_t {
  BlockDevice = S_IFBLK,  // Block-oriented device
  CharDevice = S_IFCHR,   // Character-oriented device
  Directory = S_IFDIR,    // Directory
  Fifo = S_IFIFO,         // FIFO or pipe
  File = S_IFREG,         // Regular file
  Socket = S_IFSOCK,      // Socket
  Symlink = S_IFLNK,      // Symbolic link
};

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

enum class Whence : int;

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
  }

  return out << "SEEK_" << static_cast<int>(whence);
}

// Total number of blocks taken by the tree of nodes.
blkcnt_t g_block_count = 1;

// Total number of original inodes (i.e. not counting hard links) taken by the
// tree of nodes.
fsfilcnt_t g_inode_count = 1;

using Archive = struct archive;
using Entry = struct archive_entry;

struct ArchiveDeleter {
  void operator()(Archive* const a) const { archive_read_free(a); }
};

using ArchivePtr = std::unique_ptr<Archive, ArchiveDeleter>;

const char* ReadPassword(Archive*, void*);

// Converts libarchive errors to fuse-archive exit codes. libarchive doesn't
// have designated passphrase-related error numbers. As for whether a particular
// archive file's encryption is supported, libarchive isn't consistent in
// archive_read_has_encrypted_entries returning
// ARCHIVE_READ_FORMAT_ENCRYPTION_UNSUPPORTED. Instead, we do a string
// comparison on the various possible error messages.
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

namespace bi = boost::intrusive;

#ifdef NDEBUG
using LinkMode = bi::link_mode<bi::normal_link>;
#else
using LinkMode = bi::link_mode<bi::safe_link>;
#endif

// A Reader bundles libarchive concepts (an archive and an archive entry) and
// other state to point to a particular offset (in decompressed space) of a
// particular archive entry (identified by its index) in an archive.
//
// A Reader is backed by its own archive_read_open call so each can be
// positioned independently.
struct Reader : bi::list_base_hook<LinkMode> {
  // Number of Readers created so far.
  static int count;

  int const id = ++count;
  ArchiveDescriptor* const descriptor;
  ArchivePtr archive = ArchivePtr(archive_read_new());
  Entry* entry = nullptr;
  i64 index_within_archive = 0;
  i64 offset_within_entry = 0;
  bool should_print_progress = false;
  i64 raw_pos = 0;
  char raw_bytes[16 * 1024];

  // Rolling buffer of uncompressed bytes. See (https://crbug.com/1245925#c18).
  // Even when libfuse is single-threaded, we have seen kernel readahead
  // causing the offset arguments in a sequence of read calls to sometimes
  // arrive out-of-order, where conceptually consecutive reads are swapped. With
  // a rolling buffer, we can serve the second-to-arrive request by a cheap
  // memcpy instead of an expensive "re-do decompression from the start".
  static ssize_t const rolling_buffer_size = 256 * 1024;
  static ssize_t const rolling_buffer_mask = rolling_buffer_size - 1;
  static_assert((rolling_buffer_size & rolling_buffer_mask) == 0);
  char rolling_buffer[rolling_buffer_size];

  ~Reader() { LOG(DEBUG) << "Deleted " << *this; }

  Reader(ArchiveDescriptor* const descriptor) : descriptor(descriptor) {
    if (!archive) {
      LOG(ERROR) << "Out of memory";
      throw std::bad_alloc();
    }

    if (g_password.empty()) {
      Check(archive_read_set_passphrase_callback(archive.get(), nullptr,
                                                 &ReadPassword));
    } else {
      Check(archive_read_add_passphrase(archive.get(), g_password.c_str()));
    }

    SetFormat();

    // Set callbacks to read the archive file itself.
    Check(archive_read_set_callback_data(archive.get(), this));
    Check(archive_read_set_read_callback(archive.get(), ReadRaw));
    Check(archive_read_set_seek_callback(archive.get(), SeekRaw));
    Check(archive_read_set_skip_callback(archive.get(), SkipRaw));

    // Open the archive.
    Check(archive_read_open1(archive.get()));

    LOG(DEBUG) << "Created " << *this;
  }

  friend std::ostream& operator<<(std::ostream& out, const Reader& r) {
    return out << "Reader #" << r.id;
  }

  Entry* NextEntry() {
    offset_within_entry = 0;
    index_within_archive++;
    while (true) {
      switch (archive_read_next_header(archive.get(), &entry)) {
        case ARCHIVE_RETRY:
          continue;

        case ARCHIVE_WARN:
          LOG(WARNING) << GetErrorString(archive.get());
          [[fallthrough]];

        case ARCHIVE_OK:
          assert(entry);
          return entry;

        case ARCHIVE_EOF:
          entry = nullptr;
          return nullptr;

        case ARCHIVE_FAILED:
        case ARCHIVE_FATAL:
          std::string_view const error = GetErrorString(archive.get());
          LOG(ERROR) << "Cannot advance to entry " << index_within_archive
                     << ": " << error;
          ThrowExitCode(error);
          throw ExitCode::INVALID_ARCHIVE_CONTENTS;
      }
    }
  }

  // Gets the offset within the current entry of the beginning of the rolling
  // buffer.
  i64 GetBufferOffset() const {
    return std::max<i64>(offset_within_entry - rolling_buffer_size, 0);
  }

  // Walks forward until positioned at the want'th index. An index identifies an
  // archive entry. If this Reader wasn't already positioned at that index, it
  // also resets the Reader's offset to zero.
  void AdvanceIndex(i64 const want) {
    if (index_within_archive == want) {
      return;
    }

    assert(index_within_archive < want);
    Timer const timer;

    do {
      if (!NextEntry()) {
        LOG(ERROR) << "Reached EOF while advancing to entry "
                   << index_within_archive;
        throw ExitCode::INVALID_ARCHIVE_HEADER;
      }
    } while (index_within_archive < want);

    assert(index_within_archive == want);
    LOG(DEBUG) << "Advanced " << *this << " to entry " << want << " in "
               << timer;
  }

  // Walks forward until positioned at the want'th offset. An offset identifies
  // a byte position relative to the start of an archive entry's decompressed
  // contents.
  void AdvanceOffset(i64 const want) {
    if (offset_within_entry >= want) {
      assert(GetBufferOffset() <= want);
      // We already are where we want to be.
      return;
    }

    assert(offset_within_entry < want);

    Timer const timer;

    // We are behind where we want to be. Advance (decompressing from the
    // archive entry into a rolling buffer) until we get there.
    Read(nullptr, want - offset_within_entry);

    assert(offset_within_entry == want);
    LOG(DEBUG) << "Advanced " << *this << " to offset " << offset_within_entry
               << " in " << timer;
  }

  // Gets the current entry size. 'Raw' archives don't always explicitly record
  // the decompressed size. We'll have to decompress it to find out. Some
  // 'cooked' archives also don't explicitly record this (at the time
  // archive_read_next_header returns).
  // See https://github.com/libarchive/libarchive/issues/1764.
  i64 GetEntrySize() {
    if (archive_entry_size_is_set(entry)) {
      return archive_entry_size(entry);
    }

    // Consume the entry's data.
    off_t offset = offset_within_entry;
    while (true) {
      const void* buff = nullptr;
      size_t len = 0;

      switch (archive_read_data_block(archive.get(), &buff, &len, &offset)) {
        case ARCHIVE_RETRY:
          continue;

        case ARCHIVE_WARN:
          LOG(WARNING) << GetErrorString(archive.get());
          [[fallthrough]];

        case ARCHIVE_OK:
          offset += len;
          offset_within_entry = offset;
          continue;

        case ARCHIVE_EOF:
          assert(len == 0);
          assert(offset >= 0);
          assert(offset_within_entry <= offset);

          if (offset_within_entry < offset) {
            offset_within_entry = offset;
          }

          if (archive_entry_is_encrypted(entry)) {
            g_password_checked = true;
          }

          return offset_within_entry;

        case ARCHIVE_FAILED:
        case ARCHIVE_FATAL:
          std::string_view const error = GetErrorString(archive.get());
          LOG(ERROR) << "Cannot read data from archive: " << error;
          ThrowExitCode(error);
          throw ExitCode::INVALID_ARCHIVE_CONTENTS;
      }
    }
  }

  void CheckPassword() {
    if (g_password_checked || !archive_entry_is_encrypted(entry)) {
      return;
    }

    // Reading the first bytes of the first encrypted entry will reveal whether
    // we also need a passphrase.
    g_password_checked = Read(nullptr, 16) > 0;
  }

  // Copies from the archive entry's decompressed contents to the destination
  // buffer. It also advances the Reader's offset_within_entry.
  i64 Read(char* dst_ptr, i64 dst_len) {
    assert(dst_len >= 0);
    i64 total = 0;
    while (dst_len > 0) {
      std::span<char> b(rolling_buffer);
      assert(b.size() == rolling_buffer_size);
      ssize_t const i =
          static_cast<ssize_t>(offset_within_entry & rolling_buffer_mask);
      assert(i >= 0);
      assert(i < b.size());
      b = b.subspan(i);
      if (dst_len < b.size()) {
        b = b.first(static_cast<ssize_t>(dst_len));
      }
      ssize_t const n = archive_read_data(archive.get(), b.data(), b.size());
      if (n == 0) {
        break;
      }

      if (n < 0) {
        if (n == ARCHIVE_RETRY) {
          continue;
        }

        std::string_view const error = GetErrorString(archive.get());
        LOG(ERROR) << "Cannot read data from archive: " << error;
        ThrowExitCode(error);
        throw ExitCode::INVALID_ARCHIVE_CONTENTS;
      }

      assert(n > 0);
      assert(n <= b.size());
      b = b.first(n);
      dst_len -= n;
      if (dst_ptr) {
        dst_ptr = std::ranges::copy(b, dst_ptr).out;
      }
      offset_within_entry += n;
      total += n;
    }

    return total;
  }

  ssize_t Read(std::span<char> const dst) {
    return static_cast<ssize_t>(Read(dst.data(), dst.size()));
  }

  ssize_t Read(i64 from_offset, std::span<char> dst) {
    assert(!dst.empty());
    assert(from_offset >= GetBufferOffset());
    ssize_t total = 0;

    if (from_offset < offset_within_entry) {
      ssize_t const j =
          static_cast<ssize_t>(offset_within_entry & rolling_buffer_mask);
      assert(j >= 0);
      assert(j < rolling_buffer_size);

      // Copy from rolling buffer.
      do {
        assert(from_offset >= GetBufferOffset());
        std::span<char> b(rolling_buffer);
        assert(b.size() == rolling_buffer_size);
        ssize_t const i =
            static_cast<ssize_t>(from_offset & rolling_buffer_mask);
        assert(i >= 0);
        assert(i < rolling_buffer_size);
        b = b.subspan(i);
        if (i < j) {
          b = b.first(j - i);
        }

        if (dst.size() < b.size()) {
          b = b.first(dst.size());
        }

        std::ranges::copy(b, dst.begin());
        from_offset += b.size();
        dst = dst.subspan(b.size());
        total += b.size();

        if (dst.empty()) {
          return total;
        }
      } while (from_offset < offset_within_entry);
    } else {
      AdvanceOffset(from_offset);
    }

    assert(from_offset == offset_within_entry);
    total += Read(dst);
    return total;
  }

  // Puts a Reader into the recycle bin.
  struct Recycler {
    void operator()(Reader* const r) const {
      LOG(DEBUG) << "Putting aside " << *r << " currently at offset "
                 << r->offset_within_entry << " of entry "
                 << r->index_within_archive;
      recycled.push_front(*r);
      constexpr int max_saved_readers = 8;
      if (recycled.size() > max_saved_readers) {
        Reader& to_delete = recycled.back();
        recycled.pop_back();
        delete &to_delete;
      }
    }
  };

  using Ptr = std::unique_ptr<Reader, Recycler>;

  // Returns a Reader positioned at the given offset of the given index'th entry
  // of the archive.
  static Ptr ReuseOrCreate(ArchiveDescriptor* const descriptor,
                           i64 const want_index_within_archive,
                           i64 const want_offset_within_entry) {
    assert(want_index_within_archive > 0);
    assert(want_offset_within_entry >= 0);

    // Find the closest warm Reader that is below or at the requested position.
    Reader* best = nullptr;
    for (Reader& r : recycled) {
      if (r.descriptor == descriptor &&
          (r.descriptor->filter_count > 0 ||
           r.index_within_archive == want_index_within_archive) &&
          std::pair(r.index_within_archive, r.GetBufferOffset()) <=
              std::pair(want_index_within_archive, want_offset_within_entry) &&
          (!best ||
           std::pair(best->index_within_archive, best->offset_within_entry) <
               std::pair(r.index_within_archive, r.offset_within_entry))) {
        best = &r;
      }
    }

    Ptr r;
    if (best) {
      r.reset(best);
      recycled.erase(recycled.iterator_to(*best));
      LOG(DEBUG) << "Reusing " << *r << " currently at offset "
                 << r->offset_within_entry << " of entry "
                 << r->index_within_archive;
    } else {
      r.reset(new Reader(descriptor));
    }

    assert(r);
    r->AdvanceIndex(want_index_within_archive);
    r->AdvanceOffset(want_offset_within_entry);

    return r;
  }

 private:
  void Check(int const status) const {
    Archive* const a = archive.get();

    switch (status) {
      case ARCHIVE_OK:
        return;

      case ARCHIVE_WARN:
        LOG(WARNING) << GetErrorString(a);
        return;

      default:
        std::string_view const error = GetErrorString(a);
        LOG(ERROR) << "Cannot open " << Path(descriptor->path) << ": " << error;
        ThrowExitCode(error);
        throw ExitCode::UNKNOWN_ARCHIVE_FORMAT;
    }
  }

  // Special case for .tar files because they can be of two different formats:
  // TAR or EMPTY.
  void SetTarFormat() {
    Archive* const a = archive.get();
    Check(archive_read_support_format_empty(a));
    Check(archive_read_support_format_tar(a));
  }

  // Special case for .rar files because they can be of two different formats:
  // RAR or RAR5.
  void SetRarFormat() {
    Archive* const a = archive.get();
    Check(archive_read_support_format_rar(a));
    Check(archive_read_support_format_rar5(a));
  }

  // Special case for .rpm files.
  // https://en.wikipedia.org/wiki/RPM_Package_Manager#Binary_format
  // https://github.com/google/fuse-archive/issues/50
  void SetRpmFormat() {
    Archive* const a = archive.get();
    Check(archive_read_support_filter_rpm(a));
    Check(archive_read_support_filter_gzip(a));
    Check(archive_read_support_filter_lzip(a));
    Check(archive_read_support_filter_lzma(a));
    Check(archive_read_support_filter_xz(a));
    Check(archive_read_support_filter_zstd(a));
    Check(archive_read_support_format_cpio(a));
    Check(archive_read_support_format_xar(a));
  }

#define SET_FILTER(s)                                           \
  [](Reader& r) {                                               \
    Archive* const a = r.archive.get();                         \
    r.Check(archive_read_append_filter(a, ARCHIVE_FILTER_##s)); \
  }

#define SET_FILTER_COMMAND(s)                                 \
  [](Reader& r) {                                             \
    Archive* const a = r.archive.get();                       \
    r.Check(archive_read_append_filter_program(a, #s " -d")); \
  }

#define WORK_AROUND_ISSUE_2513 ARCHIVE_VERSION_NUMBER < 3009000

  bool SetFilter(std::string_view const ext) {
    static std::unordered_map<std::string_view, void (*)(Reader&)> const
        ext_to_filter = {
            {"asc", SET_FILTER_COMMAND(gpg)},
            {"gpg", SET_FILTER_COMMAND(gpg)},
            {"pgp", SET_FILTER_COMMAND(gpg)},
            {"b64", SET_FILTER_COMMAND(base64)},
            {"base64", SET_FILTER_COMMAND(base64)},
            {"br", SET_FILTER_COMMAND(brotli)},
            {"brotli", SET_FILTER_COMMAND(brotli)},
            {"bz2", SET_FILTER(BZIP2)},
            {"bzip2", SET_FILTER(BZIP2)},
#if WORK_AROUND_ISSUE_2513
            // Work around https://github.com/libarchive/libarchive/issues/2513
            {"grz", SET_FILTER_COMMAND(grzip)},
            {"grzip", SET_FILTER_COMMAND(grzip)},
#else
            {"grz", SET_FILTER(GRZIP)},
            {"grzip", SET_FILTER(GRZIP)},
#endif
            {"gz", SET_FILTER(GZIP)},
            {"gzip", SET_FILTER(GZIP)},
            {"lrz", SET_FILTER(LRZIP)},
            {"lrzip", SET_FILTER(LRZIP)},
            {"lz", SET_FILTER(LZIP)},
            {"lzip", SET_FILTER(LZIP)},
            {"lz4", SET_FILTER(LZ4)},
            {"lzma", SET_FILTER(LZMA)},
#if WORK_AROUND_ISSUE_2513
            // Work around https://github.com/libarchive/libarchive/issues/2513
            {"lzo", SET_FILTER_COMMAND(lzop)},
            {"lzop", SET_FILTER_COMMAND(lzop)},
#else
            {"lzo", SET_FILTER(LZOP)},
            {"lzop", SET_FILTER(LZOP)},
#endif
            {"uu", SET_FILTER(UU)},
            {"xz", SET_FILTER(XZ)},
            // Work around https://github.com/libarchive/libarchive/issues/2514
            // {"z", SET_FILTER(COMPRESS)},
            {"z", SET_FILTER_COMMAND(compress)},
            {"zst", SET_FILTER(ZSTD)},
            {"zstd", SET_FILTER(ZSTD)},
        };

    const auto it = ext_to_filter.find(ext);
    if (it == ext_to_filter.end()) {
      return false;
    }

    it->second(*this);
    return true;
  }

  bool SetCompressedTarFormat(std::string_view const ext) {
    static std::unordered_map<std::string_view, void (*)(Reader&)> const
        ext_to_filter = {
            // Work around https://github.com/libarchive/libarchive/issues/2514
            // {"taz", SET_FILTER(COMPRESS)},
            {"taz", SET_FILTER_COMMAND(compress)},
            {"tbr", SET_FILTER_COMMAND(brotli)},
            {"tb2", SET_FILTER(BZIP2)},
            {"tbz", SET_FILTER(BZIP2)},
            {"tbz2", SET_FILTER(BZIP2)},
            {"tgz", SET_FILTER(GZIP)},
            {"tlz",
             [](Reader& r) {
               // .tlz could mean .tar.lz or .tar.lzma
               Archive* const a = r.archive.get();
               r.Check(archive_read_support_filter_lzip(a));
               r.Check(archive_read_support_filter_lzma(a));
             }},
            {"tlz4", SET_FILTER(LZ4)},
            {"tlzip", SET_FILTER(LZIP)},
            {"tlzma", SET_FILTER(LZMA)},
            {"txz", SET_FILTER(XZ)},
            // Work around https://github.com/libarchive/libarchive/issues/2514
            // {"tz", SET_FILTER(COMPRESS)},
            {"tz", SET_FILTER_COMMAND(compress)},
            {"tz2", SET_FILTER(BZIP2)},
            {"tzs", SET_FILTER(ZSTD)},
            {"tzst", SET_FILTER(ZSTD)},
            {"tzstd", SET_FILTER(ZSTD)},
            {"tar",
             [](Reader& r) {
               // Some `.tar` archives are actually compressed TARs, even though
               // they don't have the compression extension. So, as a special
               // case for `.tar`, automatically recognize the possible
               // compression filters.
               Archive* const a = r.archive.get();
               r.Check(archive_read_support_filter_all(a));
             }},
        };

    const auto it = ext_to_filter.find(ext);
    if (it == ext_to_filter.end()) {
      return false;
    }

    it->second(*this);
    SetTarFormat();
    return true;
  }

#define SET_FORMAT(s)                            \
  [](Reader& r) {                                \
    Archive* const a = r.archive.get();          \
    r.Check(archive_read_support_format_##s(a)); \
  }

  bool SetFormatBeforeExtraFilter(std::string_view const ext) {
    static std::unordered_map<std::string_view, void (*)(Reader&)> const
        ext_to_format = {
            {"7z", SET_FORMAT(7zip)},
            {"7zip", SET_FORMAT(7zip)},
            {"a", SET_FORMAT(ar)},
            {"ar", SET_FORMAT(ar)},
            {"cab", SET_FORMAT(cab)},
            {"cpio", SET_FORMAT(cpio)},
            {"crx", SET_FORMAT(zip_seekable)},
            {"deb", SET_FORMAT(ar)},
            {"docx", SET_FORMAT(zip_seekable)},
            {"iso", SET_FORMAT(iso9660)},
            {"iso9660", SET_FORMAT(iso9660)},
            {"jar", SET_FORMAT(zip_seekable)},
            {"lha", SET_FORMAT(lha)},
            {"mtree", SET_FORMAT(mtree)},
            {"odf", SET_FORMAT(zip_seekable)},
            {"odg", SET_FORMAT(zip_seekable)},
            {"odp", SET_FORMAT(zip_seekable)},
            {"ods", SET_FORMAT(zip_seekable)},
            {"odt", SET_FORMAT(zip_seekable)},
            {"ppsx", SET_FORMAT(zip_seekable)},
            {"pptx", SET_FORMAT(zip_seekable)},
            {"rar", [](Reader& r) { r.SetRarFormat(); }},
            {"rpm", [](Reader& r) { r.SetRpmFormat(); }},
            {"spm", [](Reader& r) { r.SetRpmFormat(); }},
            {"tar", [](Reader& r) { r.SetTarFormat(); }},
            {"war", SET_FORMAT(zip_seekable)},
            {"warc", SET_FORMAT(warc)},
            {"xar", SET_FORMAT(xar)},
            {"xlsx", SET_FORMAT(zip_seekable)},
            {"zip", SET_FORMAT(zip_seekable)},
            {"zipx", SET_FORMAT(zip_seekable)},
        };

    const auto it = ext_to_format.find(ext);
    if (it == ext_to_format.end()) {
      return false;
    }

    it->second(*this);
    return true;
  }

  bool SetFormatAfterExtraFilter(std::string_view const ext) {
    static std::unordered_map<std::string_view, void (*)(Reader&)> const
        ext_to_format = {
            {"a", SET_FORMAT(ar)},
            {"ar", SET_FORMAT(ar)},
            {"cab", SET_FORMAT(cab)},
            {"cpio", SET_FORMAT(cpio)},
            {"deb", SET_FORMAT(ar)},
            {"iso", SET_FORMAT(iso9660)},
            {"iso9660", SET_FORMAT(iso9660)},
            {"lha", SET_FORMAT(lha)},
            {"mtree", SET_FORMAT(mtree)},
            {"rar", [](Reader& r) { r.SetRarFormat(); }},
            {"tar", [](Reader& r) { r.SetTarFormat(); }},
            {"warc", SET_FORMAT(warc)},
            {"xar", SET_FORMAT(xar)},
        };

    const auto it = ext_to_format.find(ext);
    if (it == ext_to_format.end()) {
      return false;
    }

    it->second(*this);
    return true;
  }

  // Determines the archive format from the filename extension.
  void SetFormat() {
    Path p = Path(descriptor->path).Split().second;

    // Get the final filename extension in lower case and without the dot.
    // Eg "gz", "tar"...
    size_t i = p.FinalExtensionPosition();
    std::string ext = ToLower(p.substr(std::min(i + 1, p.size())));

    const bool first_time = descriptor->name_without_extension.empty();
    // Does this extension signal a recognized archive format?
    if ((g_options.max_filter_count > 0 && SetCompressedTarFormat(ext)) ||
        SetFormatBeforeExtraFilter(ext)) {
      p = p.substr(0, i);
      if (first_time) {
        LOG(DEBUG) << "Recognized format extension '" << ext << "'";
        descriptor->name_without_extension = p;
      }

      return;
    }

    // Does this extension signal a filter?
    if (g_options.max_filter_count > 0 && SetFilter(ext)) {
      // There is a compression filter. Only specific formats are recognized
      // after a compression filter.
      p = p.substr(0, i);
      if (first_time) {
        LOG(DEBUG) << "Recognized filter extension '" << ext << "'";
        descriptor->name_without_extension = p;
      }

      i = p.FinalExtensionPosition();
      ext = ToLower(p.substr(std::min(i + 1, p.size())));

      int filter_count = 1;
      while (filter_count < g_options.max_filter_count && SetFilter(ext)) {
        filter_count++;
        // There are several filters.
        p = p.substr(0, i);
        if (first_time) {
          LOG(DEBUG) << "Recognized filter extension '" << ext << "'";
          descriptor->name_without_extension = p;
        }

        i = p.FinalExtensionPosition();
        ext = ToLower(p.substr(std::min(i + 1, p.size())));
      }

      if (filter_count > 1 && first_time &&
          archive_version_number() < 3'008'002) {
        LOG(WARNING) << "Simultaneous use of two or more filters with "
                     << archive_version_string()
                     << " can result in blockage due to libarchive issue 2520";
        LOG(WARNING)
            << "See https://github.com/libarchive/libarchive/issues/2520";
      }

      // Only specific formats are recognized after a compression filter.
      if (SetFormatAfterExtraFilter(ext)) {
        p = p.substr(0, i);
        if (first_time) {
          LOG(DEBUG) << "Recognized format extension '" << ext << "'";
          descriptor->name_without_extension = p;
        }
      } else {
        Check(archive_read_support_format_raw(archive.get()));
        static const std::unordered_set<std::string_view> zip_exts = {
            "7z", "7zip", "zip", "zipx"};
        descriptor->filtered_zip = zip_exts.contains(ext);
      }

      return;
    }

#ifdef NO_ARCHIVE_FORMAT_BIDDING
    LOG(ERROR)
        << "Cannot determine the archive format from its filename extension '"
        << ext << "'";
    throw ExitCode::UNKNOWN_ARCHIVE_FORMAT;
#else
    p = p.substr(0, i);
    if (first_time) {
      LOG(WARNING)
          << "Cannot determine the archive format from its filename extension '"
          << ext << "'";
      LOG(WARNING) << "Trying to guess the format using the file contents...";
      descriptor->name_without_extension = p;
    }

    // Not a recognized extension. So we'll activate most of the possible
    // formats, and let libarchive's bidding system do its job.
    if (g_options.max_filter_count > 0) {
      Check(archive_read_support_filter_all(archive.get()));
    }

    // Prepare the handlers for the recognized archive formats. We first install
    // handlers whose heuristic format identification tests are the fastest and
    // least invasive. If one of them emits a high enough score, then the
    // subsequent testers will do nothing.
    Check(archive_read_support_format_tar(archive.get()));

    // The following archive formats are supported by libarchive, but some of
    // them haven't been tested by fuse-archive's authors.
    Check(archive_read_support_format_ar(archive.get()));
    Check(archive_read_support_format_cpio(archive.get()));
    Check(archive_read_support_format_lha(archive.get()));
    Check(archive_read_support_format_xar(archive.get()));
    Check(archive_read_support_format_warc(archive.get()));

    // More expensive bidders, all supported by libarchive and tested by
    // fuse-archive's authors.
    Check(archive_read_support_format_7zip(archive.get()));
    Check(archive_read_support_format_cab(archive.get()));
    Check(archive_read_support_format_rar(archive.get()));
    Check(archive_read_support_format_rar5(archive.get()));
    Check(archive_read_support_format_iso9660(archive.get()));

    // We don't want to handle ZIP archives in streamable mode.
    // We only handle ZIP archives in seekable mode.
    // See https://github.com/libarchive/libarchive/issues/1764.
    // See https://github.com/libarchive/libarchive/issues/2502.
    Check(archive_read_support_format_zip_seekable(archive.get()));

    // We use the "raw" archive format to read simple compressed files such as
    // "romeo.txt.gz".
    Check(archive_read_support_format_raw(archive.get()));
#endif
  }

  // The following callbacks are used by libarchive to read the uncompressed
  // data from the archive file.
  static ssize_t ReadRaw(Archive* const a,
                         void* const p,
                         const void** const out) {
    assert(p);
    Reader& r = *static_cast<Reader*>(p);
    assert(r.descriptor);
    assert(r.descriptor->fd.IsValid());
    while (true) {
      ssize_t const n =
          pread(r.descriptor->fd, r.raw_bytes, sizeof(r.raw_bytes), r.raw_pos);
      if (n >= 0) {
        r.raw_pos += n;
        r.PrintProgress();
        *out = r.raw_bytes;
        return n;
      }

      if (errno == EINTR) {
        continue;
      }

      archive_set_error(a, errno, "Cannot read archive file: %s",
                        strerror(errno));
      return ARCHIVE_FATAL;
    }
  }

  static i64 SeekRaw(Archive*,
                     void* const p,
                     i64 const offset,
                     int const whence) {
    assert(p);
    Reader& r = *static_cast<Reader*>(p);
    assert(r.descriptor);
    switch (whence) {
      case SEEK_SET:
        r.raw_pos = offset;
        return r.raw_pos;
      case SEEK_CUR:
        r.raw_pos += offset;
        return r.raw_pos;
      case SEEK_END:
        r.raw_pos = r.descriptor->size + offset;
        return r.raw_pos;
    }

    LOG(ERROR) << "Unexpected: whence = " << Whence(whence);
    return ARCHIVE_FATAL;
  }

  static i64 SkipRaw(Archive*, void* const p, i64 const delta) {
    assert(p);
    Reader& r = *static_cast<Reader*>(p);
    r.raw_pos += delta;
    return delta;
  };

  // Print progress if necessary.
  void PrintProgress() const {
    if (!should_print_progress) {
      return;
    }

    constexpr auto period = std::chrono::seconds(1);
    auto const now = std::chrono::steady_clock::now();
    static auto next = now + period;
    if (now < next) {
      return;
    }

    next = now + period;
    assert(descriptor->size > 0);
    LOG(INFO) << "Loading " << Path(descriptor->path) << "... "
              << ProgressMessage(100 *
                                 std::min<i64>(raw_pos, descriptor->size) /
                                 descriptor->size);
  }

  // A cache of warm Readers. Libarchive is designed for streaming access, not
  // random access, and does not support seeking backwards. For example, if some
  // other program reads "/foo", "/bar" and then "/baz" sequentially from an
  // archive (via this program) and those correspond to the 60th, 40th and 50th
  // archive entries in that archive, then:
  //
  //  - A naive implementation (calling archive_read_free when each FUSE file is
  //    closed) would have to start iterating from the first archive entry each
  //    time a FUSE file is opened, for 150 iterations (60 + 40 + 50) in total.
  //  - Saving readers in an LRU (Least Recently Used) cache (calling
  //    release_reader when each FUSE file is closed) allows just 110 iterations
  //    (60 + 40 + 10) in total. The Reader for "/bar" can be re-used for
  //    "/baz".
  //
  // When copying all of the files out of an archive (e.g. "cp -r" from the
  // command line) and the files are accessed in the natural order, caching
  // readers means that the overall time can be linear instead of quadratic.
  //
  // The warmest Reader is at the front of the list, and the coldest Reader is
  // at the back.
  static bi::list<Reader> recycled;
};

int Reader::count = 0;
bi::list<Reader> Reader::recycled;

// A node of the virtual file system: either a directory or a file.
struct Node {
  // Name of this node in the context of its parent. This name should be a valid
  // and non-empty filename, and it shouldn't contain any '/' separator. The
  // only exception is the root directory, which is just named "/".
  std::string name;
  std::string symlink;
  mode_t mode;
  static ino_t count;
  ino_t ino = ++count;

  uid_t uid = g_uid;
  gid_t gid = g_gid;

  // File descriptor of the archive holding the entry represented by this node,
  // or nullptr if it is not directly represented in the archive (like any
  // directory).
  ArchiveDescriptor* const descriptor = nullptr;

  // Index of the entry represented by this node in the archive, or 0 if it is
  // not directly represented in the archive (like any directory).
  i64 const index_within_archive = 0;

  // Number of bytes of this file.
  i64 size = 0;

  // Where does the cached data start in the cache file?
  i64 cache_offset = std::numeric_limits<i64>::min();

  // How many bytes have been cached so far for this file?
  i64 cached_size = 0;

  i64 last_hole_start = 0;

  Reader::Ptr reader;

  time_t mtime = 0;
  dev_t rdev = 0;
  i64 nlink = 1;

  // Sorted list of holes in this file.
  Holes holes;

  // Number of blocks saved by the presence of holes in this file.
  i64 saved_blocks = 0;

  // Extended attributes.
  struct Attribute {
    const HashedString* key;
    std::string value;
  };

  using Attributes = std::vector<Attribute>;
  Attributes attributes;

  // Number of entries whose name have initially collided with this file node.
  int collision_count = 0;

  // Number of open file descriptors that are currently reading this file node.
  std::atomic<int> fd_count = 0;

  // Hard link target.
  Node* hardlink_target = nullptr;

  // Pointer to the parent node. Should be non null. The only exception is the
  // root directory which has a null parent pointer.
  Node* parent = nullptr;

  size_t path_length = 0;
  size_t path_hash = 0;

  // Hook used to index Nodes by parent.
  using ByParent = bi::slist_member_hook<LinkMode>;
  ByParent by_parent;

  // Children of this Node. The children are not sorted and their order is not
  // relevant. This Node doesn't own its children nodes. The `parent` pointer of
  // every child in `children` should point back to this Node.
  using Children = bi::slist<Node,
                             bi::member_hook<Node, ByParent, &Node::by_parent>,
                             bi::constant_time_size<false>,
                             bi::linear<true>,
                             bi::cache_last<true>>;
  Children children;

  // Hooks used to index Nodes by full path.
  using ByPath = bi::unordered_set_member_hook<LinkMode, bi::store_hash<false>>;
  ByPath by_path;

  bool IsRoot() const { return !parent; }

  FileType GetType() const { return GetFileType(mode); }

  bool IsDir() const { return S_ISDIR(mode); }

  void AddChild(Node* const child) {
    assert(child);
    assert(!child->parent);
    assert(IsDir());
    assert(!hardlink_target);
    assert(nlink >= 2);
    // Count one "block" for each directory entry.
    size += block_size;
    g_block_count += 1;
    nlink += child->IsDir();
    child->parent = this;
    children.push_back(*child);
  }

  // Recomputes this Node's path length and hash.
  void ComputePathHash() {
    path_length = 0;
    path_hash = 0;

    if (!IsRoot()) {
      path_length = parent->path_length;
      path_hash = parent->path_hash;
      if (!parent->IsRoot()) {
        ++path_length;
        boost::hash_combine(path_hash, '/');
      }
    }

    path_length += name.size();
    for (char const c : name) {
      boost::hash_combine(path_hash, c);
    }
  }

  // Returns the number of blocks used by this node.
  i64 GetBlockCount() const {
    constexpr i64 bsm1 = block_size - 1;
    i64 const n = (size + bsm1) / block_size - saved_blocks;
    return std::max<i64>(0, n);
  }

  const Node* GetTarget() const { return hardlink_target ?: this; }
  Node* GetTarget() { return hardlink_target ?: this; }

  struct stat GetStat() const {
    struct stat z = {};
    z.st_nlink = GetTarget()->nlink;
    assert(z.st_nlink > 0);
    z.st_ino = ino;
    z.st_mode = mode;
    z.st_uid = uid;
    z.st_gid = gid;
    z.st_size = size;
    z.st_atime = g_now;
    z.st_ctime = g_now;
    z.st_mtime = mtime ?: g_now;
    z.st_blksize = block_size;
    z.st_blocks = GetBlockCount();
    z.st_rdev = rdev;
    return z;
  }

  // Gets the full absolute path of this node.
  std::string GetPath() const {
    if (IsRoot()) {
      assert(name == "/");
      return "/";
    }

    std::vector<const Node*> nodes;
    nodes.reserve(32);

    size_t n = 0;
    const Node* node = this;
    do {
      assert(!node->IsRoot());
      nodes.push_back(node);
      n += node->name.size() + 1;
      node = node->parent;
    } while (!node->IsRoot());

    assert(node);
    assert(node->IsRoot());
    assert(node->name == "/");

    std::string path;
    path.reserve(n);

    do {
      assert(!nodes.empty());
      path += '/';
      path += nodes.back()->name;
      nodes.pop_back();
    } while (!nodes.empty());

    assert(nodes.empty());
    assert(path.size() == n);
    return path;
  }

  bool HasPath(std::string_view path) const {
    const Node* node = this;

    if (!node->IsRoot()) {
      while (true) {
        if (!path.ends_with(node->name)) {
          return false;
        }

        path.remove_suffix(node->name.size());
        node = node->parent;
        if (node->IsRoot()) {
          break;
        }

        if (!path.ends_with('/')) {
          return false;
        }

        path.remove_suffix(1);
      }
    }

    assert(node->IsRoot());
    return path == node->name;
  }

  // If this node is a directory which only has one child which is a directory
  // as well, then this method returns a pointer to this child. Otherwise it
  // returns a null pointer.
  Node* GetUniqueChildDirectory() {
    if (!IsDir()) {
      // LOG(DEBUG) << *this << " is not a dir";
      return nullptr;
    }

    Node::Children::iterator const it = children.begin();
    if (it == children.end()) {
      // LOG(DEBUG) << *this << " has no children";
      return nullptr;
    }

    if (std::next(it) != children.end()) {
      // LOG(DEBUG) << *this << " has more than one child";
      return nullptr;
    }

    if (!it->IsDir()) {
      // LOG(DEBUG) << *it << " is not a dir";
      return nullptr;
    }

    return &*it;
  }

  // Reads and caches data for this file up to `want_cached_size`.
  //
  // Preconditions:
  // - `want_cached_size <= size` (the total decompressed size of the file).
  // - `this` must represent a valid File node within an archive.
  //
  // Postconditions:
  // - The uncompressed data up to `want_cached_size` is available in
  //   `g_cache_fd`.
  // - `cached_size` is updated to reflect the newly cached amount.
  // - `cache_offset` is set and `>= 0`.
  // - `reader` is advanced to `cached_size`.
  //
  // Throws ExitCode::CANNOT_WRITE_CACHE in case of an I/O error.
  void CacheUpTo(i64 const want_cached_size) {
    if (want_cached_size <= cached_size) {
      return;
    }

    assert(want_cached_size <= size);
    LOG(DEBUG) << "Caching " << *this << " from " << cached_size << " to "
               << want_cached_size;

    Timer const timer;
    if (cache_offset < 0) {
      // No data in cache for this file yet.
      // Reserve a range of bytes in the cache file.
      assert(cached_size == 0);
      cache_offset = g_cache_size;
      assert(last_hole_start == 0);
      last_hole_start = cache_offset;
      g_cache_size += size;
      g_cache_fd.Truncate(g_cache_size);

      LOG(DEBUG) << "Increased cache file size by " << size << " bytes to "
                 << g_cache_size << " bytes";
    }

    assert(cache_offset >= 0);

    if (!reader) {
      reader =
          Reader::ReuseOrCreate(descriptor, index_within_archive, cached_size);
    }

    assert(reader);
    assert(reader->descriptor == descriptor);
    assert(reader->index_within_archive == index_within_archive);

    i64 const old_cached_size = cached_size;
    i64 const old_blocks = GetBlockCount();

    ScopedFile::HoleCallback const on_hole = [this](i64 from, i64 to) {
      from -= cache_offset;
      to -= cache_offset;
      saved_blocks += holes.emplace_back(from, to).GetSavedBlocks(size);
    };

    while (cached_size < want_cached_size) {
      char buff[64 * 1024];

      ssize_t const n = reader->Read(cached_size, buff);
      assert(n >= 0);
      if (n == 0) {
        LOG(ERROR) << "Unexpected EOF while caching " << *this;
        break;
      }

      last_hole_start = g_cache_fd.WriteBytesAndSkipHoles(
          std::string_view(buff, n), cache_offset + cached_size,
          last_hole_start, on_hole);
      cached_size += n;
      assert(reader->offset_within_entry == cached_size);
    }

    if (cached_size == size) {
      i64 const file_end = cache_offset + size;
      if (last_hole_start < file_end) {
        on_hole(last_hole_start, file_end);
        last_hole_start = file_end;
      }
    }

    g_block_count -= (old_blocks - GetBlockCount());

    LOG(DEBUG) << "Cached " << cached_size - old_cached_size << " bytes of "
               << *this << " up to " << cached_size << " in " << timer;
  }
};

ino_t Node::count = 0;

std::ostream& operator<<(std::ostream& out, const Node& n) {
  out << n.GetType();
  if (n.index_within_archive > 0) {
    out << " [" << n.index_within_archive << "]";
  }
  return out << " " << Path(n.GetPath());
}

// These global variables are the in-memory directory tree of nodes.
//
// Building the directory tree can take minutes, for archive file formats like
// .tar.gz that are compressed but also do not contain an explicit on-disk
// directory of archive entries.

struct GetHash {
  size_t operator()(const HashedStringView& hsv) const {
    return hsv.string_hash;
  }

  size_t operator()(const Node& n) const { return n.path_hash; }
};

struct HasSamePath {
  bool operator()(const Node& a, const Node& b) const {
    return a.path_hash == b.path_hash && a.parent == b.parent &&
           a.name == b.name;
  }

  bool operator()(const HashedStringView& hsv, const Node& n) const {
    return hsv.string_hash == n.path_hash &&
           hsv.string.size() == n.path_length && n.HasPath(hsv.string);
  }
};

using NodesByPath =
    bi::unordered_set<Node,
                      bi::member_hook<Node, Node::ByPath, &Node::by_path>,
                      bi::constant_time_size<true>,
                      bi::power_2_buckets<true>,
                      bi::compare_hash<false>,
                      bi::equal<HasSamePath>,
                      bi::hash<GetHash>>;

using Bucket = NodesByPath::bucket_type;
using Buckets = std::vector<Bucket>;
Buckets buckets(1 << 4);

NodesByPath g_nodes_by_path({buckets.data(), buckets.size()});

// Root node of the tree.
Node* g_root_node = nullptr;

// Hard link to resolve.
struct Hardlink {
  i64 index_within_archive;
  std::string source_path;
  std::string target_path;
};

// Hard links to resolve.
std::vector<Hardlink> g_hardlinks_to_resolve;

std::string GetCacheDir() {
  const char* const val = std::getenv("TMPDIR");
  return val && *val ? val : "/tmp";
}

// Creates a hidden temp file. Returns a file descriptor to this temp file.
ScopedFile CreateCacheFile() {
  ScopedFile fd;
  std::string const cache_dir = GetCacheDir();

#if !defined(__FreeBSD__) && !defined(__OpenBSD__) && !defined(__APPLE__)
  fd = ScopedFile(open(cache_dir.c_str(), O_TMPFILE | O_RDWR | O_EXCL, 0));
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
  fd = ScopedFile(mkstemp(path.data()));

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

// Checks that the cache file specified by `fd` is open and empty.
void CheckCacheFile(const ScopedFile& fd) {
  struct stat z;
  if (fstat(fd, &z) != 0) {
    PLOG(ERROR) << "Cannot stat cache file";
    throw ExitCode::CANNOT_CREATE_CACHE;
  }

  if (z.st_size != 0) {
    LOG(ERROR) << "Cache file is not empty: It contains " << z.st_size
               << " bytes";
    throw ExitCode::CANNOT_CREATE_CACHE;
  }

  if (z.st_nlink != 0) {
    LOG(ERROR) << "Cache file is not hidden: It has " << z.st_nlink << " links";
    throw ExitCode::CANNOT_CREATE_CACHE;
  }
}

// Temporarily suppresses the echo on the terminal.
// Used when waiting for password to be typed.
class SuppressEcho {
 public:
  explicit SuppressEcho() {
    if (tcgetattr(STDIN_FILENO, &tattr_) < 0) {
      return;
    }

    struct termios tattr = tattr_;
    tattr.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &tattr);
    reset_ = true;
  }

  ~SuppressEcho() {
    if (reset_) {
      tcsetattr(STDIN_FILENO, TCSAFLUSH, &tattr_);
    }
  }

  explicit operator bool() const { return reset_; }

 private:
  struct termios tattr_;
  bool reset_ = false;
};

// Read a password from the standard input if necessary.
const char* ReadPassword(Archive*, void*) {
  if (g_password_count++) {
    return nullptr;
  }

  SuppressEcho const guard;
  if (guard) {
    std::cout << "The archive is encrypted.\n"
                 "What is the passphrase that unlocks this archive?\n"
                 "> "
              << std::flush;
  }

  // Read password from standard input.
  if (!std::getline(std::cin, g_password)) {
    g_password.clear();
  }

  if (guard) {
    std::cout << "Got it!" << std::endl;
  }

  // Remove newline at the end of password.
  while (g_password.ends_with('\n')) {
    g_password.pop_back();
  }

  if (g_password.empty()) {
    LOG(DEBUG) << "Got an empty password";
    return nullptr;
  }

  LOG(DEBUG) << "Got a password of " << g_password.size() << " bytes";
  return g_password.c_str();
}

struct FileHandle {
  Node* const node;
  Reader::Ptr reader;
};

// ---- In-Memory Directory Tree

// Validates and normalizes the current entry's path, and appends it to `*path`.
void GetNormalizedEntryPath(const Reader& r, std::string* const path) {
  Entry* const e = r.entry;
  const char* const s =
      archive_entry_pathname_utf8(e) ?: archive_entry_pathname(e);
  Path name = s && *s ? s : "data";

  // For 'raw' archives, libarchive defaults to "data" when the compression file
  // format doesn't contain the original file's name. For fuse-archive, we use
  // the archive filename's innername instead. Given an archive filename of
  // "/foo/bar.txt.bz2", the sole file within will be served as "bar.txt".
  if (r.descriptor->format == ArchiveFormat::RAW && name == "data") {
    name = Path(r.descriptor->name_without_extension);
  }

  name.NormalizeAppend(path);
}

// Checks if the given character is an ASCII digit.
bool IsAsciiDigit(char const c) {
  return c >= '0' && c <= '9';
}

// Removes the numeric suffix at the end of the given string `s`. Does nothing
// if the string does not end with a numeric suffix. A numeric suffix is a
// decimal number between parentheses and preceded by a space, like:
// * " (1)" or
// * " (142857)".
void RemoveNumericSuffix(std::string& s) {
  size_t i = s.size();

  if (i == 0 || s[--i] != ')') {
    return;
  }

  if (i == 0 || !IsAsciiDigit(s[--i])) {
    return;
  }

  while (i > 0 && IsAsciiDigit(s[i - 1])) {
    --i;
  }

  if (i == 0 || s[--i] != '(') {
    return;
  }

  if (i == 0 || s[--i] != ' ') {
    return;
  }

  s.resize(i);
}

// Finds a node by full path.
Node* FindNode(const HashedStringView& path) {
  auto const it = g_nodes_by_path.find(path, g_nodes_by_path.hash_function(),
                                       g_nodes_by_path.key_eq());
  return it == g_nodes_by_path.end() ? nullptr : &*it;
}

Node* FindNode(std::string_view const path) {
  return FindNode(HashedStringView(Path(path).WithoutTrailingSeparator()));
}

void RehashIfNecessary() {
  if (g_nodes_by_path.size() > buckets.size()) {
    Buckets new_buckets(buckets.size() * 2);
    buckets.swap(new_buckets);
    g_nodes_by_path.rehash({buckets.data(), buckets.size()});
  }
}

// Detects and resolves path collisions by renaming the given node if necessary.
//
// Preconditions:
// - `node` must be a valid, fully-initialized Node (with its parent assigned).
// - `node` must not be present in `g_nodes_by_path` yet.
//
// Postconditions:
// - If a collision occurs with an existing node in `g_nodes_by_path`, `node`'s
//   name is modified by appending a numeric suffix (e.g., " (1)") before its
//   filename extension, until the path becomes unique.
// - `node` is successfully inserted into `g_nodes_by_path`.
// - The path hash for `node` is recomputed if it was renamed.
void RenameIfCollision(Node* const node) {
  assert(node);
  auto const [pos, ok] = g_nodes_by_path.insert(*node);
  if (ok) {
    RehashIfNecessary();
    return;
  }

  // There is a name collision
  LOG(DEBUG) << *node << " conflicts with " << *pos;

  // Extract filename extension
  std::string& f = node->name;
  std::string::size_type const e =
      node->IsDir() ? f.size() : Path(f).ExtensionPosition();
  std::string const ext(f, e);
  f.resize(e);
  RemoveNumericSuffix(f);
  std::string const base = f;

  // Add a number before the extension
  for (int* i = nullptr;;) {
    std::string const suffix =
        StrCat(" (", std::to_string(i ? ++*i + 1 : 1), ")", ext);
    f.assign(base, 0, Path(base).TruncationPosition(NAME_MAX - suffix.size()));
    f += suffix;

    node->ComputePathHash();

    auto const [pos, ok] = g_nodes_by_path.insert(*node);
    if (ok) {
      LOG(DEBUG) << "Resolved conflict for " << *node;
      RehashIfNecessary();
      return;
    }

    LOG(DEBUG) << *node << " conflicts with " << *pos;
    if (!i) {
      i = &pos->collision_count;
    }
  }
}

// Gets or creates the directory hierarchy for the given path.
//
// Preconditions:
// - `path` must be an absolute path (starting with '/').
//
// Postconditions:
// - Returns a pointer to the Node corresponding to `path`.
// - If the Node did not exist, it and any missing ancestor directories are
//   created and inserted into the virtual file system.
// - If an existing non-directory node conflicts with any part of the path,
//   that non-directory node is renamed (via `RenameIfCollision`) to make room
//   for the new directory.
Node* GetOrCreateDirNode(std::string_view path) {
  if (!g_dirs || path.size() <= 1) {
    return g_root_node;
  }

  struct Segment {
    std::string_view name;
    size_t begin;
    size_t end;
    size_t path_hash;
  };

  std::vector<Segment> segments;

  {
    segments.reserve(std::ranges::count(path, '/'));
    size_t path_hash = 0;
    assert(path.starts_with('/'));

    size_t i = 0;
    size_t segment_begin = i + 1;
    boost::hash_combine(path_hash, path[i]);

    while (++i < path.size()) {
      char const c = path[i];
      if (c == '/') {
        assert(segment_begin < i);
        segments.emplace_back(path.substr(segment_begin, i - segment_begin),
                              segment_begin, i, path_hash);
        segment_begin = i + 1;
      }
      boost::hash_combine(path_hash, c);
    }

    assert(segment_begin < i);
    segments.emplace_back(path.substr(segment_begin, i - segment_begin),
                          segment_begin, i, path_hash);
  }

  Node* node = nullptr;
  size_t i = segments.size();
  while (!node && i > 0) {
    const Segment& segment = segments[--i];
    node = FindNode(
        HashedStringView(path.substr(0, segment.end), segment.path_hash));
  }

  Node* to_rename = nullptr;
  if (!node) {
    assert(i == 0);
    node = g_root_node;
    --i;
  } else if (!node->IsDir()) {
    // There is an existing node with the given name, but it's not a
    // directory.
    LOG(DEBUG) << "Found conflicting " << *node << " while creating Dir "
               << Path(path);

    // Remove it from g_nodes_by_path, in order to insert it again later with a
    // different name.
    to_rename = node;
    g_nodes_by_path.erase(g_nodes_by_path.iterator_to(*node));
    node = node->parent;
    --i;
  }

  assert(node);
  assert(node->IsDir());

  while (++i < segments.size()) {
    const Segment& segment = segments[i];
    // Create a Directory node.
    Node* const child = new Node{
        .name = std::string(segment.name),
        .mode = static_cast<mode_t>(S_IFDIR | (0777 & ~g_options.dmask)),
        .nlink = 2,
        .path_length = segment.end,
        .path_hash = segment.path_hash,
    };

    g_inode_count += 1;
    node->AddChild(child);
    node = child;
    [[maybe_unused]] auto const [_, ok] = g_nodes_by_path.insert(*node);
    assert(ok);
    RehashIfNecessary();
  }

  if (to_rename) {
    RenameIfCollision(to_rename);
  }

  return node;
}

bool ShouldSkip(FileType const ft) {
  switch (ft) {
    case FileType::BlockDevice:
    case FileType::CharDevice:
    case FileType::Fifo:
    case FileType::Socket:
      return !g_specials;

    case FileType::Symlink:
      return !g_symlinks;

    case FileType::Directory:
      return !g_dirs;

    case FileType::File:
      return false;
  }

  return true;
}

// Caches the uncompressed data of the current archive entry into the cache
// file.
//
// Preconditions:
// - `a` must be an initialized libarchive descriptor, currently positioned
//   at the beginning of an entry's data blocks.
// - `dest_fd` must be a valid, writable file descriptor for the cache file.
// - `file_start_offset >= 0`, representing the logical starting position in the
//   cache.
//
// Postconditions:
// - The entry's data is fully written to `dest_fd`.
// - Sparse "holes" (long sequences of NUL bytes) are skipped to save disk
//   space.
// - If `node` is not null, its `holes` list and `saved_blocks` count are
//   updated.
// - The cache file is truncated to the correct length to ensure trailing holes
//   are reflected in the file size.
// - Returns the new cache file size.
//
// Throws:
// - ExitCode::CANNOT_WRITE_CACHE in case of an I/O error when writing.
// - ExitCode::INVALID_ARCHIVE_CONTENTS if libarchive fails to read the data.
i64 CacheEntryData(Archive* const a,
                   const ScopedFile& dest_fd,
                   i64 const file_start_offset,
                   Node* const node = nullptr) try {
  assert(file_start_offset >= 0);
  i64 dest_offset = file_start_offset;
  i64 last_hole_start = file_start_offset;

  ScopedFile::HoleCallback on_hole;
  if (node) {
    assert(node->holes.empty());
    assert(node->saved_blocks == 0);

    on_hole = [node, file_start_offset](i64 from, i64 to) {
      from -= file_start_offset;
      to -= file_start_offset;
      node->saved_blocks +=
          node->holes.emplace_back(from, to).GetSavedBlocks(node->size);
    };
  }

  while (true) {
    const void* buff = nullptr;
    size_t len = 0;
    off_t offset = dest_offset - file_start_offset;

    switch (archive_read_data_block(a, &buff, &len, &offset)) {
      case ARCHIVE_RETRY:
        continue;

      case ARCHIVE_WARN:
        LOG(WARNING) << GetErrorString(a);
        [[fallthrough]];

      case ARCHIVE_OK:
        assert(offset >= 0);
        assert(dest_offset <= file_start_offset + offset);
        dest_offset = file_start_offset + offset;
        last_hole_start = dest_fd.WriteBytesAndSkipHoles(
            std::string_view(static_cast<const char*>(buff), len), dest_offset,
            last_hole_start, on_hole);
        dest_offset += len;

        continue;

      case ARCHIVE_EOF:
        assert(len == 0);
        assert(offset >= 0);
        assert(dest_offset <= file_start_offset + offset);

        // Adjust the cache size if there is a final "hole".
        // See https://github.com/google/fuse-archive/issues/40
        dest_offset = file_start_offset + offset;
        if (last_hole_start < dest_offset) {
          dest_fd.Truncate(dest_offset);
          if (on_hole) {
            on_hole(last_hole_start, dest_offset);
          }
        }

        return dest_offset;

      case ARCHIVE_FAILED:
      case ARCHIVE_FATAL:
        std::string_view const error = GetErrorString(a);
        LOG(ERROR) << "Cannot read data from archive: " << error;
        ThrowExitCode(error);
        throw ExitCode::INVALID_ARCHIVE_CONTENTS;
    }
  }
} catch (...) {
  // In case of error, erase the data of the partially cached file.
  if (node) {
    node->holes.clear();
    node->saved_blocks = 0;
  }
  dest_fd.Truncate(file_start_offset);
  throw;
}

// Processes an archive entry and creates the corresponding Node(s) in the
// virtual file system.
//
// Preconditions:
// - `r` must be a valid Reader currently positioned at an archive entry.
// - `path` is a buffer used to hold the entry's normalized path. It must
// initially contain the base path for the archive within the virtual file
// system.
// - `local_root` is the root node for this archive.
//
// Postconditions:
// - Creates a Node (or updates directories) for the entry and inserts it into
//   the file system tree under `local_root`.
// - Caches the data if `g_cache == Cache::Full`.
// - Extended attributes and hardlinks are processed and recorded.
void ProcessEntry(Reader& r, std::string& path, Node* const local_root) {
  Archive* const a = r.archive.get();
  Entry* const e = r.entry;
  i64 const i = r.index_within_archive;
  mode_t const mode = archive_entry_mode(e);
  FileType const ft = GetFileType(mode);

  assert(path.starts_with('/'));
  size_t const original_path_size = path.size();
  GetNormalizedEntryPath(r, &path);
  assert(path.starts_with('/'));

  if (const char* const s =
          archive_entry_hardlink_utf8(e) ?: archive_entry_hardlink(e)) {
    // Entry is a hard link.
    if (g_hardlinks) {
      // Save it for further resolution.
      g_hardlinks_to_resolve.push_back({
          .index_within_archive = i,
          .source_path = path,
          .target_path = Path(s).Normalized(path.substr(0, original_path_size)),
      });
    } else {
      LOG(DEBUG) << "Skipped hard link "
                 << " [" << i << "] " << Path(path) << " -> " << Path(s);
    }
    return;
  }

  if (ShouldSkip(ft)) {
    LOG(DEBUG) << "Skipped " << ft << " [" << i << "] " << Path(path);
    return;
  }

  // Is this entry a directory?
  if (ft == FileType::Directory) {
    assert(g_dirs);
    Node* const node = GetOrCreateDirNode(path);
    assert(node);

    node->mtime = archive_entry_mtime(e);

    if (g_default_permissions) {
      node->uid = archive_entry_uid(e);
      node->gid = archive_entry_gid(e);
      mode_t const pbits = 07777;
      node->mode &= ~pbits;
      node->mode |= mode & pbits & ~g_options.dmask;
    }

    return;
  }

  // This entry is not a directory.
  if (path.size() == original_path_size) {
    Path::Append(&path, "data");
  }

  auto const [parent_path, name] = Path(path).Split();

  // Get or create the parent directory node.
  Node* const parent = g_dirs ? GetOrCreateDirNode(parent_path) : local_root;
  assert(parent);
  assert(parent->IsDir());

  // Create the node for this entry.
  Node* const node =
      new Node{.name = std::string(name),
               .mode = static_cast<mode_t>(static_cast<mode_t>(ft) |
                                           (0666 & ~g_options.fmask)),
               .descriptor = r.descriptor,
               .index_within_archive = i,
               .mtime = archive_entry_mtime(e)};

  g_inode_count += 1;

  if (g_default_permissions) {
    node->uid = archive_entry_uid(e);
    node->gid = archive_entry_gid(e);
    mode_t const pbits = 07777;
    node->mode &= ~pbits;
    node->mode |= mode & pbits & ~g_options.fmask;
  } else if (mode_t const xbits = 0111; (mode & xbits) != 0) {
    // Adjust the access bits if the file is executable.
    node->mode |= xbits & ~g_options.fmask;
  }

  parent->AddChild(node);
  node->ComputePathHash();

  // Add to g_nodes_by_path.
  RenameIfCollision(node);

  // Do some extra processing depending on the file type.
  // Block or Char Device.
  if (ft == FileType::BlockDevice || ft == FileType::CharDevice) {
    node->rdev = archive_entry_rdev(e);
    return;
  }

  // Symlink.
  if (ft == FileType::Symlink) {
    if (const char* const s =
            archive_entry_symlink_utf8(e) ?: archive_entry_symlink(e)) {
      node->symlink = s;
      node->size = node->symlink.size();
      g_block_count += node->GetBlockCount();
    }
    return;
  }

  if (ft != FileType::File) {
    return;
  }

  // Regular file.
  if (g_cache == Cache::Full) {
    // Cache file data.
    node->size = archive_entry_size(e);
    i64 const offset = g_cache_size;
    g_cache_size = CacheEntryData(a, g_cache_fd, g_cache_size, node);
    // Now that CacheEntryData has succeeded without throwing an exception, we
    // can remember the cache offset.
    node->cache_offset = offset;
    node->cached_size = node->size = g_cache_size - offset;
    node->last_hole_start = g_cache_size;
  } else {
    // Get the entry size without caching the data.
    node->size = r.GetEntrySize();
  }

  // Extract extended attributes.
  if (g_xattrs) {
    if (int const n = archive_entry_xattr_reset(e)) {
      node->attributes.reserve(n);
      const char* key;
      const void* value;
      size_t len;
      while (archive_entry_xattr_next(e, &key, &value, &len) == ARCHIVE_OK) {
        assert(key);
        assert(value);
        node->attributes.push_back(
            {.key = GetOrCreateUnique(key),
             .value = std::string(static_cast<const char*>(value), len)});
      }
    }
  }

  // Check password if necessary.
  r.CheckPassword();

  // Adjust the total block count.
  g_block_count += node->GetBlockCount();
}

// Resolve the hard links set aside in g_hardlinks_to_resolve.
void ResolveHardlinks() {
  for (const Hardlink& entry : g_hardlinks_to_resolve) {
    // Find its target.
    Node* target = FindNode(entry.target_path);
    if (!target) {
      LOG(DEBUG) << "Skipped hard link [" << entry.index_within_archive << "] "
                 << Path(entry.source_path) << ": Cannot find target "
                 << Path(entry.target_path);
      continue;
    }

    while (target->hardlink_target) {
      target = target->hardlink_target;
    }

    if (target->IsDir()) {
      LOG(DEBUG) << "Skipped hard link [" << entry.index_within_archive << "] "
                 << Path(entry.source_path) << ": Target "
                 << Path(entry.target_path) << " is a directory";
      continue;
    }

    // Check if this link already exists.
    if (const Node* const source = FindNode(entry.source_path)) {
      if (source->GetTarget() == target) {
        LOG(DEBUG) << "Skipped duplicate hard link ["
                   << entry.index_within_archive << "] "
                   << Path(entry.source_path) << " -> " << *target;
        continue;
      }
    }

    auto const [parent_path, name] = Path(entry.source_path).Split();

    // Get or create the parent node.
    Node* const parent = GetOrCreateDirNode(parent_path);
    assert(parent);
    assert(parent->IsDir());

    // Create the node for this entry.
    Node* const node = new Node{
        .name = std::string(name.empty() ? "data" : name),
        .symlink = target->symlink,
        .mode = target->mode,
        .ino = g_hardlinks ? target->ino : ++Node::count,
        .uid = target->uid,
        .gid = target->gid,
        .descriptor = target->descriptor,
        .index_within_archive = target->index_within_archive,
        .size = target->size,
        .cache_offset = target->cache_offset,
        .cached_size = target->cached_size,
        .last_hole_start = target->last_hole_start,
        .mtime = target->mtime,
        .rdev = target->rdev,
        .nlink = g_hardlinks ? (target->nlink++, 0) : 1,
        .saved_blocks = target->saved_blocks,
        .hardlink_target = g_hardlinks ? target : nullptr,
        // For performance reasons, we don't copy holes and attributes here.
        // FUSE callbacks that rely on these members will explicitely get the
        // hardlink target.
    };

    if (!g_hardlinks) {
      node->holes = target->holes;
      node->attributes = target->attributes;
      g_inode_count += 1;
      g_block_count += node->GetBlockCount();
    }

    parent->AddChild(node);
    node->ComputePathHash();

    // Add to g_nodes_by_path.
    RenameIfCollision(node);

    LOG(DEBUG) << "Resolved hard link [" << entry.index_within_archive << "] "
               << Path(node->GetPath()) << " -> " << *target;
  }

  g_hardlinks_to_resolve.clear();
}

// Verifies the archive format.
//
// Preconditions:
// - `r` must be a valid Reader positioned at an archive entry.
//
// Throws ExitCode::UNKNOWN_ARCHIVE_FORMAT if no valid compression filters are
// found for a 'raw' archive.
void CheckRawArchive(Reader& r) {
  if (r.descriptor->format != ArchiveFormat::NONE) {
    // Already checked.
    return;
  }

  Archive* const a = r.archive.get();
  r.descriptor->format = ArchiveFormat(archive_format(a));
  LOG(DEBUG) << "Archive format is " << archive_format_name(a) << " ("
             << r.descriptor->format << ")";

  assert(r.descriptor->filter_count == 0);
  for (int i = archive_filter_count(a); i > 0;) {
    if (archive_filter_code(a, --i) != ARCHIVE_FILTER_NONE) {
      ++r.descriptor->filter_count;
      LOG(DEBUG) << "Filter #" << r.descriptor->filter_count << " is "
                 << archive_filter_name(a, i);
    }
  }

  // For 'raw' archives, check that at least one of the compression filters
  // (e.g. bzip2, gzip) actually triggered. We don't want to mount arbitrary
  // data (e.g. foo.jpeg).
  if (r.descriptor->format == ArchiveFormat::RAW &&
      r.descriptor->filter_count == 0) {
    LOG(ERROR) << "Cannot recognize the archive format";
    throw ExitCode::UNKNOWN_ARCHIVE_FORMAT;
  }

  if (r.descriptor->filter_count > 0 && g_cache != Cache::Full) {
    LOG(WARNING) << "Using the lazycache or the nocache option with this kind "
                    "of archive can result in poor performance";
  }
}

void Deindex(Node& node) {
  for (Node& c : node.children) {
    Deindex(c);
  }
  g_nodes_by_path.erase(g_nodes_by_path.iterator_to(node));
}

void Reindex(Node& node) {
  node.ComputePathHash();
  [[maybe_unused]] bool const ok = g_nodes_by_path.insert(node).second;
  assert(ok);

  for (Node& c : node.children) {
    Reindex(c);
  }
}

void Trim(Node& a) {
  Node* p = a.GetUniqueChildDirectory();
  if (!p) {
    return;
  }

  Deindex(*p);
  a.children.clear();

  while (Node* const q = p->GetUniqueChildDirectory()) {
    p->children.clear();
    p = q;
  }

  LOG(DEBUG) << "Collapsing " << *p << " into " << a;

  assert(a.IsDir());
  assert(p->IsDir());
  a.ino = p->ino;
  a.uid = p->uid;
  a.gid = p->gid;
  a.mode = p->mode;
  a.size = p->size;
  a.mtime = p->mtime;
  a.nlink = p->nlink;
  assert(!a.hardlink_target);
  assert(!p->hardlink_target);
  a.children = std::move(p->children);
  assert(p->children.empty());

  for (Node& c : a.children) {
    assert(c.parent == p);
    c.parent = &a;
    Reindex(c);
  }

  LOG(INFO) << "Collapsed " << *p << " into " << a;
  LOG(INFO)
      << "Use `-o notrim` if you want to keep these intermediate directories";

  while (p != &a) {
    g_block_count -= 1;
    g_inode_count -= 1;
    Node* const q = p->parent;
    delete p;
    p = q;
  }
}

// Opens the archive file, scans it and builds the tree representing the files
// and directories contained in this archive.
void BuildTree() {
  for (ArchiveDescriptor& archive : g_archives) {
    try {
      if (archive.path.empty()) {
        LOG(ERROR) << "Empty archive file name";
        throw ExitCode::GENERIC_FAILURE;
      }

      // Open archive file.
      assert(!archive.fd.IsValid());
      archive.fd = ScopedFile(open(archive.path.c_str(), O_RDONLY));
      if (!archive.fd.IsValid()) {
        PLOG(ERROR) << "Cannot open " << Path(archive.path);
        throw ExitCode::CANNOT_OPEN_ARCHIVE;
      }

      // Check archive file size and type.
      if (struct stat z; fstat(archive.fd, &z) != 0) {
        PLOG(ERROR) << "Cannot stat " << Path(archive.path);
        throw ExitCode::CANNOT_OPEN_ARCHIVE;
      } else if (FileType const ft = GetFileType(z.st_mode);
                 ft != FileType::File) {
        LOG(ERROR) << "Archive " << Path(archive.path)
                   << " is not a regular file: It is a " << ft;
        throw ExitCode::CANNOT_OPEN_ARCHIVE;
      } else {
        archive.size = z.st_size;
        LOG(DEBUG) << "File size of " << Path(archive.path) << " is "
                   << archive.size << " bytes";
      }
    } catch (ExitCode const error) {
      archive.fd.Close();

      if (!g_force) {
        throw;
      }

      LOG(DEBUG) << "Suppressed error " << error << " because of -o force";
    }
  }

  // Create root node.
  assert(!g_root_node);
  g_root_node =
      new Node{.name = "/",
               .mode = static_cast<mode_t>(S_IFDIR | (0777 & ~g_options.dmask)),
               .nlink = 2};
  g_root_node->ComputePathHash();
  [[maybe_unused]] auto const [_, ok] = g_nodes_by_path.insert(*g_root_node);
  assert(ok);

  // Declare this variable outside of the following loop in order to keep its
  // internal buffer.
  std::string path;

  for (ArchiveDescriptor& archive : g_archives) {
    if (!archive.fd.IsValid()) {
      continue;
    }

    LOG(DEBUG) << "Loading " << Path(archive.path) << "...";

    try {
      // Prepare a Reader to read the archive.
      std::unique_ptr<Reader> r = std::make_unique<Reader>(&archive);
      r->should_print_progress = LOG_IS_ON(INFO) && archive.size > 0;

      if (g_cache == Cache::Full && archive.filtered_zip) {
        // Cache full ZIP file.
        if (!r->NextEntry()) {
          LOG(ERROR) << "Reached EOF while expecting a unique entry";
          throw ExitCode::INVALID_ARCHIVE_HEADER;
        }

        ScopedFile fd = CreateCacheFile();
        CheckCacheFile(fd);
        i64 const size = CacheEntryData(r->archive.get(), fd, 0);
        r.reset();
        archive =
            ArchiveDescriptor{.path = std::move(archive.name_without_extension),
                              .fd = std::move(fd),
                              .size = size};
        r = std::make_unique<Reader>(&archive);
        r->should_print_progress = LOG_IS_ON(INFO) && archive.size > 0;
      }

      path = "/";
      Node* local_root = g_root_node;
      if (!g_merge) {
        // Create a Directory node for the archive.
        local_root = new Node{
            .name = archive.name_without_extension,
            .mode = static_cast<mode_t>(S_IFDIR | (0777 & ~g_options.dmask)),
            .nlink = 2,
        };

        g_inode_count += 1;
        g_root_node->AddChild(local_root);
        local_root->ComputePathHash();
        RenameIfCollision(local_root);
        path += local_root->name;
        assert(local_root->GetPath() == path);

        LOG(DEBUG) << "Created " << *local_root;
      }

      size_t const original_path_size = path.size();

      // Read and process every entry of the archive.
      while (r->NextEntry()) {
        CheckRawArchive(*r);

        try {
          path.resize(original_path_size);
          ProcessEntry(*r, path, local_root);
        } catch (ExitCode const error) {
          if (!g_force) {
            throw;
          }

          LOG(DEBUG) << "Suppressed error " << error << " because of -o force";
        }
      }

      // Resolve hard links.
      ResolveHardlinks();

      if (g_latest_log_is_ephemeral) {
        LOG(INFO) << "Loading " << Path(r->descriptor->path) << "... "
                  << ProgressMessage(100);
      }
    } catch (ExitCode const error) {
      if (!g_force) {
        throw;
      }

      LOG(DEBUG) << "Suppressed error " << error << " because of -o force";
    }

    // Close archive file if decompressed data is already cached.
    if (g_cache == Cache::Full) {
      archive.fd.Close();
    }
  }

  // Trim the top level if necessary.
  if (g_trim) {
    if (g_merge) {
      Trim(*g_root_node);
    } else {
      for (Node& c : g_root_node->children) {
        Trim(c);
      }
    }
  }
}

// ---- FUSE Callbacks

int GetAttr(const char* const path,
#if FUSE_USE_VERSION >= 30
            struct stat* const z,
            fuse_file_info* const fi) {
#else
            struct stat* const z) {
  fuse_file_info* const fi = nullptr;
#endif

  const Node* n;

  if (fi) {
    FileHandle* const h = reinterpret_cast<FileHandle*>(fi->fh);
    assert(h);
    n = h->node;
    assert(n);
  } else {
    assert(path);
    n = FindNode(path);
    if (!n) {
      LOG(DEBUG) << "Cannot stat " << Path(path) << ": No such item";
      return -ENOENT;
    }
  }

  const Node* const t = n->GetTarget();
  assert(t);

  assert(z);
  *z = t->GetStat();
  return 0;
}

int GetXattr(const char* const path,
             const char* const xattr_name,
             char* const dst_ptr,
#if defined(__APPLE__) && FUSE_USE_VERSION < 30
             size_t const dst_len,
             uint32_t) {
#else
             size_t const dst_len) {
#endif
  assert(path);
  assert(xattr_name);

  const Node* const node = FindNode(path);
  if (!node) {
    LOG(ERROR) << "Cannot get xattr " << std::quoted(xattr_name) << " of "
               << Path(path) << ": No such file or directory";
    return -ENOENT;
  }

  const Node::Attributes& attributes = node->GetTarget()->attributes;

  if (attributes.empty()) {
    // The node has no extended attributes.
    LOG(DEBUG) << *node << " has no xattr " << std::quoted(xattr_name);
    return -ENODATA;
  }

  const HashedString* const key = GetUniqueOrNull(xattr_name);
  if (!key) {
    // No extended attribute has ever been recorded with the given name.
    LOG(DEBUG) << *node << " has no xattr " << std::quoted(xattr_name);
    return -ENODATA;
  }

  auto const it = std::ranges::find(attributes, key, &Node::Attribute::key);
  if (it == attributes.end()) {
    // The node has some extended attributes, but none matching the given name.
    LOG(DEBUG) << *node << " has no xattr " << std::quoted(xattr_name);
    return -ENODATA;
  }

  assert(it->key->string == xattr_name);
  const std::string& value = it->value;

  if (dst_len > 0) {
    assert(dst_ptr);
    if (dst_len < value.size()) {
      LOG(ERROR) << "Cannot get xattr " << std::quoted(xattr_name) << " of "
                 << *node << ": The destination buffer of " << dst_len
                 << " bytes is too small: Needs at least " << value.size()
                 << " bytes";
      return -ERANGE;
    }

    std::copy_n(value.data(), value.size(), dst_ptr);
  }

  if (value.size() > std::numeric_limits<int>::max()) {
    LOG(ERROR) << "Cannot get xattr " << std::quoted(xattr_name) << " of "
               << *node << ": The value is " << value.size()
               << " bytes long, which is greater than MAX_INT";
    return -E2BIG;
  }

  LOG(DEBUG) << "Get xattr " << std::quoted(xattr_name) << " of " << *node
             << " -> " << value.size() << " bytes";
  return static_cast<int>(value.size());
}

int ListXattr(const char* const path,
              char* const dst_ptr,
              size_t const dst_len) {
  const Node* const node = FindNode(path);
  if (!node) {
    LOG(ERROR) << "Cannot list xattrs of " << Path(path)
               << ": No such file or directory";
    return -ENOENT;
  }

  const Node::Attributes& attributes = node->GetTarget()->attributes;

  size_t total_bytes = 0;
  if (dst_len == 0) {
    // Compute required buffer size.
    for (const Node::Attribute& a : attributes) {
      const std::string& key = a.key->string;
      total_bytes += key.size() + 1;
    }
  } else {
    assert(dst_ptr);
    std::span<char> dst(dst_ptr, dst_len);
    for (const Node::Attribute& a : attributes) {
      const std::string& key = a.key->string;
      const size_t n = key.size() + 1;
      if (dst.size() < n) {
        LOG(ERROR) << "Cannot list " << attributes.size() << " xattrs of "
                   << *node << ": The destination buffer of " << dst_len
                   << " bytes is too small";
        return -ERANGE;
      }

      // Copy the NUL terminator as well.
      std::copy_n(key.c_str(), n, dst.data());
      dst = dst.subspan(n);
      total_bytes += n;
    }
  }

  if (total_bytes > std::numeric_limits<int>::max()) {
    LOG(ERROR) << "Cannot list " << attributes.size() << " xattrs of " << *node
               << ": The list is " << total_bytes
               << " bytes long, which is greater than MAX_INT";
    return -E2BIG;
  }

  LOG(DEBUG) << "List " << attributes.size() << " xattrs of " << *node << " -> "
             << total_bytes << " bytes";
  return static_cast<int>(total_bytes);
}

int ReadLink(const char* const path, char* const buf, size_t const size) {
  assert(path);
  assert(buf);
  assert(size > 1);

  const Node* const n = FindNode(path);
  if (!n) {
    LOG(ERROR) << "Cannot read link " << Path(path) << ": No such item";
    return -ENOENT;
  }

  const Node* const t = n->GetTarget();
  assert(t);

  if (t->GetType() != FileType::Symlink) {
    LOG(ERROR) << "Cannot read link " << *n << ": Not a symlink";
    return -ENOLINK;
  }

  snprintf(buf, size, "%s", t->symlink.c_str());
  return 0;
}

int Open(const char* const path, fuse_file_info* const fi) try {
  assert(path);
  Node* const n = FindNode(path);
  if (!n) {
    LOG(ERROR) << "Cannot open " << Path(path) << ": No such item";
    return -ENOENT;
  }

  Node* const t = n->GetTarget();
  assert(t);

  if (t->IsDir()) {
    LOG(ERROR) << "Cannot open " << *n << ": It is a directory";
    return -EISDIR;
  }

  assert(t->index_within_archive > 0);

  if (g_cache == Cache::Full && t->cache_offset < 0) {
    LOG(ERROR) << "Cannot open " << *n << ": No cached data";
    return -EIO;
  }

  assert(fi);
  static_assert(sizeof(fi->fh) >= sizeof(FileHandle*));
  fi->fh = reinterpret_cast<uintptr_t>(new FileHandle{.node = n});
  int const fd_count = ++t->fd_count;
  assert(fd_count > 0);
  if (fd_count == 1) {
    LOG(DEBUG) << "Opened " << *n;
  } else {
    LOG(DEBUG) << "Opened " << *n << " (" << fd_count
               << " file descriptors currently open)";
  }
  return 0;
} catch (...) {
  LOG(DEBUG) << "Caught exception";
  return -EIO;
}

int Read(const char*,
         char* const dst_ptr,
         size_t const dst_len,
         off_t offset,
         fuse_file_info* const fi) try {
  if (offset < 0 || dst_len > std::numeric_limits<int>::max()) {
    return -EINVAL;
  }

  std::span dst(dst_ptr, dst_len);

  assert(fi);
  FileHandle* const h = reinterpret_cast<FileHandle*>(fi->fh);
  assert(h);

  Node* const node = h->node;
  assert(node);
  Node* const t = node->GetTarget();
  assert(t);

  i64 const size = t->size;
  assert(size >= 0);

  i64 const remaining = size - offset;
  if (remaining <= 0) {
    // No data past the end of a file.
    return 0;
  }

  if (dst.size() > remaining) {
    // No data past the end of a file.
    dst = dst.first(static_cast<ssize_t>(remaining));
  }

  if (dst.empty()) {
    return 0;
  }

  if (g_cache == Cache::Lazy) {
    t->CacheUpTo(offset + dst.size());
    assert(t->cache_offset >= 0);
  }

  if (g_cache != Cache::None) {
    assert(t->cache_offset >= 0);
    offset += t->cache_offset;

    // Read data from the cache file.
    ssize_t const n = pread(g_cache_fd, dst.data(), dst.size(), offset);
    if (n < 0) {
      int const e = errno;
      PLOG(ERROR) << "Cannot read " << dst.size()
                  << " bytes from cache at offset " << offset;
      return -e;
    }

    assert(n <= dst.size());
    return n;
  }

  Reader::Ptr& r = h->reader;
  if (r) {
    assert(r->descriptor == t->descriptor);
    assert(r->index_within_archive == t->index_within_archive);
    if (offset < r->GetBufferOffset()) {
      // libarchive is designed for streaming access, not random access. If we
      // need to seek backwards, there's more work to do.
      LOG(DEBUG) << *r << " cannot jump " << r->offset_within_entry - offset
                 << " bytes backwards from offset " << r->offset_within_entry
                 << " to " << offset;
      r.reset();
    } else if (offset > r->offset_within_entry + r->rolling_buffer_size) {
      LOG(DEBUG) << *r << " might have to jump "
                 << offset - r->offset_within_entry
                 << " bytes forwards from offset " << r->offset_within_entry
                 << " to " << offset;
      r.reset();
    }
  }

  if (!r) {
    r = Reader::ReuseOrCreate(t->descriptor, t->index_within_archive, offset);
  }

  assert(r);
  assert(r->index_within_archive == t->index_within_archive);
  assert(r->offset_within_entry <= offset + r->rolling_buffer_size);

  ssize_t n = r->Read(offset, dst);
  assert(n >= 0);
  assert(n <= dst.size());
  dst = dst.subspan(n);

  // Pad the buffer with NUL bytes. This is a workaround for
  // https://github.com/libarchive/libarchive/issues/1194.
  // See https://github.com/google/fuse-archive/issues/40.
  std::ranges::fill(dst, '\0');
  n += dst.size();

  return static_cast<int>(n);
} catch (...) {
  LOG(DEBUG) << "Caught exception";
  return -EIO;
}

int Release(const char*, fuse_file_info* const fi) {
  assert(fi);
  FileHandle* const h = reinterpret_cast<FileHandle*>(fi->fh);
  assert(h);

  Node* const n = h->node;
  assert(n);
  Node* const t = n->GetTarget();
  assert(t);
  int const fd_count = --t->fd_count;
  assert(fd_count >= 0);
  delete h;

  if (fd_count > 0) {
    LOG(DEBUG) << "Closed " << *n << " (" << fd_count
               << " file descriptors are still open)";
  } else {
    LOG(DEBUG) << "Closed " << *n;

    if (g_cache == Cache::Lazy) {
      t->reader = nullptr;
    }
  }

  return 0;
}

int OpenDir(const char* const path, fuse_file_info* const fi) {
  assert(path);
  const Node* const n = FindNode(path);
  if (!n) {
    LOG(ERROR) << "Cannot open " << Path(path) << ": No such item";
    return -ENOENT;
  }

  if (!n->IsDir()) {
    LOG(ERROR) << "Cannot open " << *n << ": Not a directory";
    return -ENOTDIR;
  }

  assert(fi);
  static_assert(sizeof(fi->fh) >= sizeof(Node*));
  fi->fh = reinterpret_cast<uintptr_t>(n);
#if FUSE_USE_VERSION >= 30
  fi->cache_readdir = true;
#endif
  return 0;
}

int ReadDir(const char*,
            void* const buf,
            fuse_fill_dir_t const filler,
            off_t,
#if FUSE_USE_VERSION >= 30
            fuse_file_info* const fi,
            fuse_readdir_flags) try {
#else
            fuse_file_info* const fi) try {
#endif
  assert(filler);
  assert(fi);
  const Node* const n = reinterpret_cast<const Node*>(fi->fh);
  assert(n);
  assert(n->IsDir());

  const auto add = [buf, filler, n](const char* const name,
                                    const struct stat* const z) {
#if FUSE_USE_VERSION >= 30
    if (filler(buf, name, z, 0, FUSE_FILL_DIR_PLUS)) {
#else
    if (filler(buf, name, z, 0)) {
#endif
      LOG(ERROR) << "Cannot list items in " << *n << ": Cannot allocate memory";
      throw std::bad_alloc();
    }
  };

  struct stat z = n->GetStat();
  add(".", &z);

  if (const Node* const parent = n->parent) {
    z = parent->GetStat();
    add("..", &z);
  } else {
    add("..", nullptr);
  }

  for (const Node& child : n->children) {
    struct stat const z = child.GetTarget()->GetStat();
    add(child.name.c_str(), &z);
  }

  LOG(DEBUG) << "List " << *n << " -> " << n->children.size() << " items";
  return 0;
} catch (const std::bad_alloc&) {
  return -ENOMEM;
}

int StatFs(const char*, struct statvfs* const z) {
  assert(z);
  z->f_bsize = block_size;
  z->f_frsize = block_size;
  z->f_blocks = g_block_count;
  z->f_bfree = 0;
  z->f_bavail = 0;
  z->f_files = g_inode_count;
  z->f_ffree = 0;
  z->f_favail = 0;
  z->f_flag = ST_RDONLY;
  z->f_namemax = NAME_MAX;
  LOG(DEBUG) << "Got filesystem stats";
  return 0;
}

#if FUSE_USE_VERSION >= 30
void* Init(fuse_conn_info*, fuse_config* const cfg) {
  assert(cfg);
  // Respect inode numbers.
  cfg->use_ino = true;
  cfg->nullpath_ok = true;
  cfg->direct_io = g_direct_io;
  LOG(DEBUG) << "Initialized FUSE server";
  return nullptr;
}

off_t Seek(const char*,
           off_t const offset,
           int const whence,
           fuse_file_info* const fi) {
  assert(fi);
  const FileHandle* const h = reinterpret_cast<const FileHandle*>(fi->fh);
  assert(h);
  const Node* const n = h->node;
  assert(n);

  LOG(DEBUG) << "Seeking " << *n << " with whence = " << Whence(whence)
             << " and offset = " << offset;

  const Node* const t = n->GetTarget();
  Holes::const_iterator const it =
      std::ranges::upper_bound(t->holes, offset, std::less<i64>(), &Hole::to);

  switch (whence) {
    case SEEK_DATA:
      if (offset < 0) {
        return -EINVAL;
      }

      if (offset >= t->size) {
        return -ENXIO;
      }

      if (it != t->holes.end() && it->from <= offset) {
        assert(offset < it->to);
        // offset is located in a hole
        LOG(DEBUG) << "In " << *it;
        return it->to < t->size ? it->to : -ENXIO;
      }

      LOG(DEBUG) << "In Data";
      return offset;

    case SEEK_HOLE:
      if (offset < 0) {
        return -EINVAL;
      }

      if (offset > t->size) {
        return -ENXIO;
      }

      if (it == t->holes.end()) {
        // offset is past the last hole
        LOG(DEBUG) << "In Data past the last hole";
        return t->size;
      }

      assert(it != t->holes.end());
      assert(offset < it->to);

      if (it->from <= offset) {
        // offset is located in a hole
        LOG(DEBUG) << "In " << *it;
        return offset;
      }

      // offset is before a hole
      assert(offset < it->from);
      LOG(DEBUG) << "In Data before " << *it;
      return it->from;
  }

  LOG(ERROR) << "Cannot seek " << *n << " with whence = " << Whence(whence)
             << " and offset = " << offset;
  return -EINVAL;
}
#endif

fuse_operations const operations = {
    .getattr = GetAttr,
    .readlink = ReadLink,
    .open = Open,
    .read = Read,
    .statfs = StatFs,
    .release = Release,
    .getxattr = GetXattr,
    .listxattr = ListXattr,
    .opendir = OpenDir,
    .readdir = ReadDir,
#if FUSE_USE_VERSION >= 30
    .init = Init,
    .lseek = Seek,
#else
    .flag_nullpath_ok = true,
    .flag_nopath = true,
#endif
};

// ---- Main

int ProcessArg(void*, const char* const arg, int const key, fuse_args*) {
  constexpr int KEEP = 1;
  constexpr int DISCARD = 0;

  switch (key) {
    case FUSE_OPT_KEY_NONOPT:
      g_archives.push_back({.path = arg});
      return DISCARD;

    case KEY_HELP:
      g_help = true;
      return DISCARD;

    case KEY_VERSION:
      g_version = true;
      return DISCARD;

    case KEY_QUIET:
      SetLogLevel(LogLevel::ERROR);
      return DISCARD;

    case KEY_VERBOSE:
      SetLogLevel(LogLevel::DEBUG);
      return DISCARD;

    case KEY_REDACT:
      g_redact = true;
      return DISCARD;

    case KEY_FORCE:
      g_force = true;
      return DISCARD;

    case KEY_LAZY_CACHE:
      g_cache = Cache::Lazy;
      return DISCARD;

    case KEY_NO_CACHE:
      g_cache = Cache::None;
      return DISCARD;

    case KEY_NO_MERGE:
      g_merge = false;
      return DISCARD;

    case KEY_NO_TRIM:
      g_trim = false;
      return DISCARD;

    case KEY_NO_DIRS:
      g_dirs = false;
      g_hardlinks = false;
      return DISCARD;

    case KEY_NO_SPECIALS:
      g_specials = false;
      return DISCARD;

    case KEY_NO_SYMLINKS:
      g_symlinks = false;
      return DISCARD;

    case KEY_NO_HARDLINKS:
      g_hardlinks = false;
      return DISCARD;

    case KEY_NO_XATTRS:
      g_xattrs = false;
      return DISCARD;

    case KEY_DEFAULT_PERMISSIONS:
      g_default_permissions = true;
      return DISCARD;

#if FUSE_USE_VERSION >= 30
    case KEY_DIRECT_IO:
      g_direct_io = true;
      return DISCARD;
#endif
  }

  return KEEP;
}

void EnsureUtf8() {
  // libarchive (especially for reading 7z) has locale-dependent behavior.
  // Non-ASCII paths can trigger "Pathname cannot be converted from UTF-16LE to
  // current locale" warnings from archive_read_next_header and
  // archive_entry_pathname_utf8 subsequently returning nullptr.
  //
  // Calling setlocale to enforce a UTF-8 encoding can avoid that. Try various
  // arguments and pick the first one that is supported and produces UTF-8.
  const char* const locales[] = {
      // As of 2021, many systems (including Debian) support "C.UTF-8".
      "C.UTF-8",
      // However, "C.UTF-8" is not a POSIX standard and glibc 2.34 (released
      // 2021-08-01) does not support it. It may come to glibc 2.35 (see the
      // sourceware.org commit link below), but until then and on older
      // systems, try the popular "en_US.UTF-8".
      //
      // https://sourceware.org/git/?p=glibc.git;a=commit;h=466f2be6c08070e9113ae2fdc7acd5d8828cba50
      "en_US.UTF-8",
      // As a final fallback, an empty string means to use the relevant
      // environment variables (LANG, LC_ALL, etc).
      "",
  };

  std::string_view const want = "UTF-8";
  for (const char* const locale : locales) {
    if (setlocale(LC_ALL, locale) && want == nl_langinfo(CODESET)) {
      return;
    }
  }

  LOG(ERROR) << "Cannot ensure UTF-8 encoding";
  throw ExitCode::GENERIC_FAILURE;
}

// Runs a function in its destructor.
struct Cleanup {
  std::function<void()> fn;

  ~Cleanup() {
    if (fn) {
      fn();
    }
  }
};

class NumPunct : public std::numpunct<char> {
 private:
  char do_thousands_sep() const override { return ','; }
  std::string do_grouping() const override { return "\3"; }
};

void PrintUsage() {
  std::cout
      << R"(Mount one or several archives or compressed files as a read-only FUSE file system.

Usage:
    )" PROGRAM_NAME
         R"( [options] archive [mount_point]
    )" PROGRAM_NAME
         R"( [options] archive... mount_point

general options:
    -o opt,[opt...]        mount options
    -h   --help            print help
    -V   --version         print version

)" PROGRAM_NAME R"( options:
    -q   -o quiet          do not print progress messages
    -v   -o verbose        print more log messages
    -o redact              redact paths from log messages
    -o force               continue despite errors
    -o maxfilters=N        maximum number of filters per archive (default 1)
    -o lazycache           incremental caching of uncompressed data
    -o nocache             no caching of uncompressed data
    -o nomerge             don't merge multiple archives in the same directory
    -o notrim              don't trim the base of the tree
    -o nodirs              no directories
    -o nospecials          no special files (FIFOs, sockets, devices)
    -o nosymlinks          no symlinks
    -o nohardlinks         no hard links
    -o noxattrs            no extended attributes
    -o dmask=M             directory permission mask in octal (default 0022)
    -o fmask=M             file permission mask in octal (default 0022))"
#if FUSE_USE_VERSION >= 30
         R"(
    -o direct_io           use direct I/O)"
#endif
         "\n\n"
      << std::flush;
}

}  // namespace

std::ostream& operator<<(std::ostream& out, const fuse_args& args) {
  std::string_view sep;
  for (int i = 0; i < args.argc; ++i) {
    out << sep << std::quoted(args.argv[i]);
    sep = " ";
  }

  assert(!args.argv[args.argc]);
  return out;
}

int main(int const argc, char** const argv) try {
  // Ensure that numbers in debug messages have thousands separators.
  // It makes big numbers much easier to read (eg sizes expressed in bytes).
  std::locale::global(std::locale(std::locale::classic(), new NumPunct));
  openlog(PROGRAM_NAME, LOG_PERROR, LOG_USER);
  SetLogLevel(LogLevel::INFO);

  EnsureUtf8();

  fuse_args args = FUSE_ARGS_INIT(argc, argv);
  if (fuse_opt_parse(&args, &g_options, g_fuse_opts, &ProcessArg) < 0) {
    LOG(ERROR) << "Cannot parse command line arguments";
    throw ExitCode::GENERIC_FAILURE;
  }

  if (g_help) {
    PrintUsage();
#if FUSE_USE_VERSION >= 30
    fuse_opt_add_arg(&args, "--help");
    char empty[] = "";
    args.argv[0] = empty;
#else
    fuse_opt_add_arg(&args, "-ho");  // I think ho means "help output".
#endif
    fuse_main(args.argc, args.argv, &operations, nullptr);
    return EXIT_SUCCESS;
  }

  if (g_version) {
    std::cout << PROGRAM_NAME " " PROGRAM_VERSION "\n";
    std::cout << archive_version_details() << "\n";
    std::cout.flush();

    fuse_opt_add_arg(&args, "--version");
    fuse_main(args.argc, args.argv, &operations, nullptr);
    return EXIT_SUCCESS;
  }

  if (g_archives.empty()) {
    PrintUsage();
    return EXIT_FAILURE;
  }

  // Determine where the mount point should be.
  bool const mount_point_specified_by_user = g_archives.size() > 1;
  if (mount_point_specified_by_user) {
    g_mount_point = std::move(g_archives.back().path);
    g_archives.pop_back();
  } else {
    g_mount_point = Path(g_archives.front().path)
                        .WithoutTrailingSeparator()
                        .Split()
                        .second.WithoutExtension();
  }

  std::string mount_point_parent, mount_point_basename;
  std::tie(mount_point_parent, mount_point_basename) =
      Path(g_mount_point).WithoutTrailingSeparator().Split();

  if (mount_point_basename.empty()) {
    LOG(ERROR) << "Cannot use " << Path(g_mount_point) << " as a mount point";
    throw ExitCode::CANNOT_CREATE_MOUNT_POINT;
  }

  // Get a file descriptor to the parent directory of the mount point.
  int mount_point_parent_fd =
      open(!mount_point_parent.empty() ? mount_point_parent.c_str() : ".",
#if defined(O_PATH)
           O_DIRECTORY | O_PATH);  // Linux, FreeBSD >= 13
#elif defined(O_EXEC)
           O_DIRECTORY | O_EXEC);  // FreeBSD <= 12
#else
           O_DIRECTORY | O_RDONLY);  // OpenBSD, macOS
#endif
  if (mount_point_parent_fd < 0) {
    PLOG(ERROR) << "Cannot access directory " << Path(mount_point_parent);
    throw ExitCode::CANNOT_CREATE_MOUNT_POINT;
  }

  // Create cache file if necessary.
  if (g_cache != Cache::None) {
    assert(!g_cache_fd.IsValid());
    assert(g_cache_size == 0);
    g_cache_fd = CreateCacheFile();
    CheckCacheFile(g_cache_fd);
  }

  // Force single-threading if not fully cached.
  if (g_cache != Cache::Full) {
    fuse_opt_add_arg(&args, "-s");
  }

  // Mount read-only.
  fuse_opt_add_arg(&args, "-r");

#if FUSE_USE_VERSION < 30
  // Respect inode numbers.
  fuse_opt_add_arg(&args, "-o");
  fuse_opt_add_arg(&args, "use_ino");
#endif

  if (g_default_permissions) {
    fuse_opt_add_arg(&args, "-o");
    fuse_opt_add_arg(&args, "default_permissions");
  }

  // Read archive and build tree.
  Timer timer;
  BuildTree();

  // Log some debug messages.
  if (LOG_IS_ON(DEBUG)) {
    if (g_archives.size() > 1) {
      LOG(DEBUG) << "Loaded " << g_archives.size() << " archives in " << timer;
    } else {
      LOG(DEBUG) << "Loaded " << Path(g_archives.front().path) << " in "
                 << timer;
    }
    LOG(DEBUG) << "The file system contains " << g_nodes_by_path.size() - 1
               << " items totalling " << i64(g_block_count) * block_size
               << " bytes";
    if (struct stat z; g_cache == Cache::Full && fstat(g_cache_fd, &z) == 0) {
      LOG(DEBUG) << "The cache takes " << i64(z.st_blocks) * block_size
                 << " bytes of disk space";
      assert(z.st_size == g_cache_size);
    }
  }

  // Create the mount point if it does not already exist.
  Cleanup cleanup;
  {
    auto const n = mount_point_basename.size();
    int i = 0;
    for (;;) {
      g_mount_point = mount_point_parent;
      Path::Append(&g_mount_point, mount_point_basename);

      if (mkdirat(mount_point_parent_fd, mount_point_basename.c_str(), 0777) ==
          0) {
        LOG(INFO) << "Created mount point " << Path(g_mount_point);

        // Set the cleanup function that will eventually remove this mount
        // point.
        cleanup.fn = [mount_point_parent_fd, mount_point_basename]() {
          if (unlinkat(mount_point_parent_fd, mount_point_basename.c_str(),
                       AT_REMOVEDIR) == 0) {
            LOG(INFO) << "Removed mount point " << Path(g_mount_point);
          } else {
            PLOG(ERROR) << "Cannot remove mount point " << Path(g_mount_point);
          }
        };

        mount_point_parent_fd = -1;
        break;
      }

      if (errno != EEXIST) {
        PLOG(ERROR) << "Cannot create mount point " << Path(g_mount_point);
        throw ExitCode::CANNOT_CREATE_MOUNT_POINT;
      }

      if (mount_point_specified_by_user) {
        LOG(DEBUG) << "Using existing mount point " << Path(g_mount_point);
        close(mount_point_parent_fd);
        mount_point_parent_fd = -1;
        break;
      }

      LOG(DEBUG) << "Mount point " << Path(g_mount_point) << " already exists";
      mount_point_basename.resize(n);
      mount_point_basename += StrCat(" (", ++i, ")");
    }
  }

  // The mount point is in place.
  if (g_mount_point.starts_with('-')) {
    // To prevent the mount point from being mistaken as a command line option.
    fuse_opt_add_arg(&args, StrCat("./", g_mount_point).c_str());
  } else {
    fuse_opt_add_arg(&args, g_mount_point.c_str());
  }

  // Start serving the filesystem.
  LOG(DEBUG) << "Calling fuse_main() with " << args;
  int const res = fuse_main(args.argc, args.argv, &operations, nullptr);
  LOG(DEBUG) << "Returning " << ExitCode(res);
  return res;
} catch (ExitCode const e) {
  LOG(DEBUG) << "Returning " << e;
  return static_cast<int>(e);
} catch (const std::exception& e) {
  LOG(ERROR) << e.what();
  LOG(DEBUG) << "Returning " << ExitCode::GENERIC_FAILURE;
  return static_cast<int>(ExitCode::GENERIC_FAILURE);
}
