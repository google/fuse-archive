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

#define FUSE_USE_VERSION 26

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
#include <cassert>
#include <cerrno>
#include <chrono>
#include <climits>
#include <compare>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
#include <locale>
#include <memory>
#include <ostream>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <boost/intrusive/list.hpp>
#include <boost/intrusive/slist.hpp>
#include <boost/intrusive/unordered_set.hpp>

// ---- Compile-time Configuration

#define PROGRAM_NAME "fuse-archive"

// Odd minor versions (e.g. 1.1.x or 1.3.x) are development versions.
// Even minor versions (e.g. 1.2.x or 1.4.x) are stable versions.
#define PROGRAM_VERSION "0.1.15"

namespace {

// Type alias for shorter code.
using i64 = std::int64_t;

// Timer for debug logs.
struct Timer {
  using Clock = std::chrono::steady_clock;

  // Start time.
  Clock::time_point start = Clock::now();

  // Resets this timer.
  void Reset() { start = Clock::now(); }

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
  INVALID_RAW_ARCHIVE = 30,
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
    PRINT(INVALID_RAW_ARCHIVE)
    PRINT(INVALID_ARCHIVE_HEADER)
    PRINT(INVALID_ARCHIVE_CONTENTS)
#undef PRINT
  }

  return out << "Exit Code " << int(e);
}

// ---- Platform specifics

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
#define lseek64 lseek
#endif

// ---- Globals

enum {
  KEY_HELP,
  KEY_VERSION,
  KEY_QUIET,
  KEY_VERBOSE,
  KEY_REDACT,
  KEY_FORCE,
  KEY_NO_CACHE,
  KEY_NO_SPECIALS,
  KEY_NO_SYMLINKS,
  KEY_NO_HARDLINKS,
  KEY_DEFAULT_PERMISSIONS,
};

struct Options {
  unsigned int dmask = 0022;
  unsigned int fmask = 0022;
};

Options g_options;

const fuse_opt g_fuse_opts[] = {
    FUSE_OPT_KEY("-h", KEY_HELP),
    FUSE_OPT_KEY("--help", KEY_HELP),
    FUSE_OPT_KEY("-V", KEY_VERSION),
    FUSE_OPT_KEY("--version", KEY_VERSION),
    FUSE_OPT_KEY("--quiet", KEY_QUIET),
    FUSE_OPT_KEY("-q", KEY_QUIET),
    FUSE_OPT_KEY("--verbose", KEY_VERBOSE),
    FUSE_OPT_KEY("-v", KEY_VERBOSE),
    FUSE_OPT_KEY("--redact", KEY_REDACT),
    FUSE_OPT_KEY("redact", KEY_REDACT),
    FUSE_OPT_KEY("force", KEY_FORCE),
    FUSE_OPT_KEY("nocache", KEY_NO_CACHE),
    FUSE_OPT_KEY("nospecials", KEY_NO_SPECIALS),
    FUSE_OPT_KEY("nosymlinks", KEY_NO_SYMLINKS),
    FUSE_OPT_KEY("nohardlinks", KEY_NO_HARDLINKS),
    FUSE_OPT_KEY("default_permissions", KEY_DEFAULT_PERMISSIONS),
    {"dmask=%o", offsetof(Options, dmask)},
    {"fmask=%o", offsetof(Options, fmask)},
    FUSE_OPT_END,
};

// Command line options.
bool g_help = false;
bool g_version = false;
bool g_redact = false;
bool g_force = false;
bool g_cache = true;
bool g_specials = true;
bool g_symlinks = true;
bool g_hardlinks = true;
bool g_default_permissions = false;

// Number of command line arguments seen so far.
int g_arg_count = 0;

// Command line argument naming the archive file.
std::string g_archive_path;

// Path of the mount point.
std::string g_mount_point;

// File descriptor of the cache file.
int g_cache_fd = -1;

// Size of the cache file.
i64 g_cache_size = 0;

// File descriptor returned by opening g_archive_path.
int g_archive_fd = -1;

// Size of the archive file.
i64 g_archive_size = 0;

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

ArchiveFormat g_archive_format = ArchiveFormat::NONE;

// g_uid and g_gid are the user/group IDs for the files we serve. They're the
// same as the current uid/gid.
//
// libfuse will override my_getattr's use of these variables if the "-o uid=N"
// or "-o gid=N" command line options are set.
const uid_t g_uid = getuid();
const gid_t g_gid = getgid();

using Clock = std::chrono::system_clock;
const time_t g_now = Clock::to_time_t(Clock::now());

// Path manipulations.
class Path : public std::string_view {
 public:
  Path(const char* path) : std::string_view(path) {}
  Path(std::string_view path) : std::string_view(path) {}

  // Removes trailing separators.
  Path WithoutTrailingSeparator() const {
    Path path = *this;

    // Don't remove the first character, even if it is a '/'.
    while (path.size() > 1 && path.back() == '/')
      path.remove_suffix(1);

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
  // An extension cannot be longer than 6 bytes, including the leading dot:
  // * "foo.tool" -> ".tool"
  // * "foo.toolong" -> no extension
  size_type FinalExtensionPosition() const {
    const size_type last_dot = find_last_of("/. ");
    if (last_dot == npos || at(last_dot) != '.' || last_dot == 0 ||
        last_dot == size() - 1 || size() - last_dot > 6)
      return size();

    if (const size_type i = find_last_not_of('.', last_dot - 1);
        i == npos || at(i) == '/')
      return size();

    return last_dot;
  }

  // Same as FinalExtensionPosition, but also takes in account some double
  // extensions such as ".tar.gz".
  size_type ExtensionPosition() const {
    const size_type last_dot = FinalExtensionPosition();
    if (last_dot >= size())
      return last_dot;

    // Extract extension without dot and in ASCII lowercase.
    assert(at(last_dot) == '.');
    std::string ext(substr(last_dot + 1));
    for (char& c : ext) {
      if ('A' <= c && c <= 'Z')
        c += 'a' - 'A';
    }

    // Is it a special extension?
    static const std::unordered_set<std::string_view> special_exts = {
        "z", "gz", "bz", "bz2", "xz", "zst", "lz", "lzma"};
    if (special_exts.count(ext)) {
      return Path(substr(0, last_dot)).FinalExtensionPosition();
    }

    return last_dot;
  }

  // Removes the final extension, if any.
  Path WithoutFinalExtension() const {
    return substr(0, FinalExtensionPosition());
  }

  // Removes the extension, if any.
  Path WithoutExtension() const { return substr(0, ExtensionPosition()); }

  // Gets a safe truncation position `x` such that `0 <= x && x <= i`. Avoids
  // truncating in the middle of a multi-byte UTF-8 sequence. Returns `size()`
  // if `i >= size()`.
  size_type TruncationPosition(size_type i) const {
    if (i >= size())
      return size();

    while (true) {
      // Avoid truncating at a UTF-8 trailing byte.
      while (i > 0 && (at(i) & 0b1100'0000) == 0b1000'0000)
        --i;

      if (i == 0)
        return i;

      const std::string_view zero_width_joiner = "\u200D";

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
    const std::string_view::size_type i = find_last_of('/') + 1;
    return {Path(substr(0, i)).WithoutTrailingSeparator(), substr(i)};
  }

  // Appends the |tail| path to |*head|. If |tail| is an absolute path, then
  // |*head| takes the value of |tail|. If |tail| is a relative path, then it is
  // appended to |*head|. A '/' separator is added if |*head| doesn't already
  // end with one.
  static void Append(std::string* const head, std::string_view const tail) {
    assert(head);

    if (tail.empty())
      return;

    if (head->empty() || tail.starts_with('/')) {
      *head = tail;
      return;
    }

    assert(!head->empty());
    assert(!tail.empty());

    if (!head->ends_with('/'))
      *head += '/';

    *head += tail;
  }

  // Normalizes path.
  std::string Normalize() const {
    if (empty())
      return std::string();

    Path in = *this;
    std::string result = "/";

    if (in == ".") {
      return result;
    }

    while (in.starts_with("./")) {
      in.remove_prefix(2);
    }

    while (in.starts_with("../")) {
      result += "UP";
      in.remove_prefix(3);
    }

    // Extract part after part
    size_type i;
    while ((i = in.find_first_not_of('/')) != npos) {
      in.remove_prefix(i);
      assert(!in.empty());

      i = in.find_first_of('/');
      std::string_view part = in.substr(0, i);
      assert(!part.empty());
      in.remove_prefix(part.size());

      part = part.substr(0, Path(part).TruncationPosition(NAME_MAX));

      if (part.empty() || part == "." || part == "..")
        part = "?";

      Append(&result, part);
    }

    return result;
  }
};

std::ostream& operator<<(std::ostream& out, Path const path) {
  if (g_redact)
    return out << "(redacted)";

  out.put('\'');
  for (const char c : path) {
    switch (c) {
      case '\\':
      case '\'':
        out.put('\\');
        out.put(c);
        break;
      default:
        const int i = static_cast<unsigned char>(c);
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
  return FileType(mode & S_IFMT);
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

constexpr blksize_t block_size = 512;

// Total number of blocks taken by the tree of nodes.
blkcnt_t g_block_count = 1;

namespace bi = boost::intrusive;

#ifdef NDEBUG
using LinkMode = bi::link_mode<bi::normal_link>;
#else
using LinkMode = bi::link_mode<bi::safe_link>;
#endif

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

  // Index of the entry represented by this node in the archive, or 0 if it is
  // not directly represented in the archive (like the root directory, or any
  // intermediate directory).
  i64 index_within_archive = 0;
  i64 size = 0;

  // Where does the cached data start in the cache file?
  i64 cache_offset = std::numeric_limits<i64>::min();

  time_t mtime = g_now;
  dev_t rdev = 0;
  i64 nlink = 1;

  // Number of entries whose name have initially collided with this file node.
  int collision_count = 0;

  // Hard link target.
  Node* hardlink_target = nullptr;

  // Pointer to the parent node. Should be non null. The only exception is the
  // root directory which has a null parent pointer.
  Node* parent = nullptr;

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
  using ByPath = bi::unordered_set_member_hook<LinkMode, bi::store_hash<true>>;
  ByPath by_path;

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

  i64 GetBlockCount() const { return (size + (block_size - 1)) / block_size; }

  struct stat GetStat() const {
    struct stat z = {};
    z.st_nlink = (hardlink_target ?: this)->nlink;
    assert(z.st_nlink > 0);
    z.st_ino = ino;
    z.st_mode = mode;
    z.st_uid = uid;
    z.st_gid = gid;
    z.st_size = size;
    z.st_atime = g_now;
    z.st_ctime = g_now;
    z.st_mtime = mtime;
    z.st_blksize = block_size;
    z.st_blocks = GetBlockCount();
    z.st_rdev = rdev;
    return z;
  }

  std::string GetPath() const {
    if (!parent) {
      return name;
    }

    std::string path = parent->GetPath();
    Path::Append(&path, name);
    return path;
  }
};

ino_t Node::count = 0;

std::ostream& operator<<(std::ostream& out, const Node& n) {
  return out << n.GetType() << " [" << n.index_within_archive << "] "
             << Path(n.GetPath());
}

// These global variables are the in-memory directory tree of nodes.
//
// Building the directory tree can take minutes, for archive file formats like
// .tar.gz that are compressed but also do not contain an explicit on-disk
// directory of archive entries.

// Path extractor for Node.
struct GetPath {
  using type = std::string;
  std::string operator()(const Node& node) const { return node.GetPath(); }
};

using NodesByPath =
    bi::unordered_set<Node,
                      bi::member_hook<Node, Node::ByPath, &Node::by_path>,
                      bi::constant_time_size<true>,
                      bi::power_2_buckets<true>,
                      bi::compare_hash<true>,
                      bi::key_of_value<GetPath>,
                      bi::equal<std::equal_to<std::string_view>>,
                      bi::hash<std::hash<std::string_view>>>;

using Bucket = NodesByPath::bucket_type;
using Buckets = std::vector<Bucket>;
Buckets buckets(1 << 4);

NodesByPath g_nodes_by_path({buckets.data(), buckets.size()});

// Root node of the tree.
Node* g_root_node = nullptr;

// Hardlink to resolve.
struct Hardlink {
  std::string source_path;
  std::string target_path;
};

// Hardlinks to resolve.
std::vector<Hardlink> g_hardlinks_to_resolve;

// g_side_buffer_data and g_side_buffer_metadata combine to hold side buffers:
// statically allocated buffers used as a destination for decompressed bytes
// when Reader::advance_offset isn't a no-op. These buffers are roughly
// equivalent to Unix's /dev/null or Go's io.Discard as a first approximation.
// However, since we are already producing valid decompressed bytes, by saving
// them (and their metadata), we may be able to serve some subsequent my_read
// requests cheaply, without having to spin up another libarchive decompressor
// to walk forward from the start of the archive entry.
//
// In particular (https://crbug.com/1245925#c18), even when libfuse is single-
// threaded, we have seen kernel readahead causing the offset arguments in a
// sequence of my_read calls to sometimes arrive out-of-order, where
// conceptually consecutive reads are swapped. With side buffers, we can serve
// the second-to-arrive request by a cheap memcpy instead of an expensive
// "re-do decompression from the start". That side-buffer was filled by a
// Reader::advance_offset side-effect from serving the first-to-arrive request.
constexpr int NUM_SIDE_BUFFERS = 8;

// This defaults to 128 KiB (0x20000 bytes) because, on a vanilla x86_64 Debian
// Linux, that seems to be the largest buffer size passed to my_read.
constexpr ssize_t SIDE_BUFFER_SIZE = 128 << 10;

uint8_t g_side_buffer_data[NUM_SIDE_BUFFERS][SIDE_BUFFER_SIZE] = {};

struct SideBufferMetadata {
  i64 index_within_archive = -1;
  i64 offset_within_entry = -1;
  i64 length = -1;
  i64 lru_priority = 0;

  static i64 next_lru_priority;

  bool Contains(i64 const index_within_archive,
                i64 const offset_within_entry,
                i64 const length) const {
    if (this->index_within_archive >= 0 &&
        this->index_within_archive == index_within_archive &&
        this->offset_within_entry <= offset_within_entry) {
      const i64 o = offset_within_entry - this->offset_within_entry;
      return this->length >= o && this->length - o >= length;
    }

    return false;
  }
};

i64 SideBufferMetadata::next_lru_priority = 0;

SideBufferMetadata g_side_buffer_metadata[NUM_SIDE_BUFFERS] = {};

// ---- Libarchive Error Codes

// Converts libarchive errors to fuse-archive exit codes. libarchive doesn't
// have designated passphrase-related error numbers. As for whether a particular
// archive file's encryption is supported, libarchive isn't consistent in
// archive_read_has_encrypted_entries returning
// ARCHIVE_READ_FORMAT_ENCRYPTION_UNSUPPORTED. Instead, we do a string
// comparison on the various possible error messages.
[[noreturn]] void ThrowExitCode(std::string_view const e) {
  if (e.starts_with("Incorrect passphrase")) {
    throw ExitCode::PASSPHRASE_INCORRECT;
  }

  if (e.starts_with("Passphrase required")) {
    throw ExitCode::PASSPHRASE_REQUIRED;
  }

  const std::string_view not_supported_prefixes[] = {
      "Crypto codec not supported",
      "Decryption is unsupported",
      "Encrypted file is unsupported",
      "Encryption is not supported",
      "RAR encryption support unavailable",
      "The archive header is encrypted, but currently not supported",
      "The file content is encrypted, but currently not supported",
      "Unsupported encryption format",
  };

  for (const std::string_view prefix : not_supported_prefixes) {
    if (e.starts_with(prefix)) {
      throw ExitCode::PASSPHRASE_NOT_SUPPORTED;
    }
  }

  throw ExitCode::INVALID_ARCHIVE_CONTENTS;
}

template <typename... Args>
std::string StrCat(Args&&... args) {
  return (std::ostringstream() << ... << std::forward<Args>(args)).str();
}

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
  explicit Logger(LogLevel const level, error_t err = -1)
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
      const std::string_view s = "\e[F\e[K";
      write(STDERR_FILENO, s.data(), s.size());
    }

    syslog(static_cast<int>(level_), "%s", std::move(oss_).str().c_str());
    g_latest_log_is_ephemeral = ephemeral_;
  }

  Logger&& operator<<(const auto& a) && {
    oss_ << a;
    return std::move(*this);
  }

  Logger&& operator<<(ProgressMessage const a) && {
    oss_ << "Loading " << static_cast<int>(a) << "%";
    ephemeral_ = true;
    return std::move(*this);
  }

 private:
  const LogLevel level_;
  const error_t err_;
  std::ostringstream oss_;
  bool ephemeral_ = false;
};

#define LOG(level)                    \
  if (LogLevel::level <= g_log_level) \
  Logger(LogLevel::level)

#define PLOG(level)                   \
  if (LogLevel::level <= g_log_level) \
  Logger(LogLevel::level, errno)

std::string GetCacheDir() {
  const char* const val = std::getenv("TMPDIR");
  return val && *val ? val : "/tmp";
}

void CreateCacheFile() {
  assert(g_cache_fd < 0);
  assert(g_cache_size == 0);

  const std::string cache_dir = GetCacheDir();

  g_cache_fd = open(cache_dir.c_str(), O_TMPFILE | O_RDWR | O_EXCL, 0);
  if (g_cache_fd >= 0) {
    LOG(DEBUG) << "Created anonymous cache file in " << Path(cache_dir);
    return;
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

  std::string path = cache_dir;
  Path::Append(&path, "XXXXXX");
  g_cache_fd = mkstemp(path.data());

  if (g_cache_fd < 0) {
    PLOG(ERROR) << "Cannot create named cache file in " << Path(cache_dir);
    throw ExitCode::CANNOT_CREATE_CACHE;
  }

  LOG(DEBUG) << "Created cache file " << Path(path);

  if (unlink(path.c_str()) < 0) {
    PLOG(ERROR) << "Cannot unlink cache file " << Path(path);
    throw ExitCode::CANNOT_CREATE_CACHE;
  }
}

// Checks that the cache file is open and empty.
void CheckCacheFile() {
  struct stat z;
  if (fstat(g_cache_fd, &z) != 0) {
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

using Archive = struct archive;
using Entry = struct archive_entry;

struct ArchiveDeleter {
  void operator()(Archive* const a) const { archive_read_free(a); }
};

using ArchivePtr = std::unique_ptr<Archive, ArchiveDeleter>;

// Read a password from the standard input if necessary.
const char* ReadPassword(Archive*, void*) {
  if (g_password_count++) {
    return nullptr;
  }

  const SuppressEcho guard;
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

// ---- Side Buffer

// Returns the index of the least recently used side buffer. This indexes
// g_side_buffer_data and g_side_buffer_metadata.
int AcquireSideBuffer() {
  int oldest_i = 0;
  i64 oldest_lru_priority = g_side_buffer_metadata[0].lru_priority;
  for (int i = 1; i < NUM_SIDE_BUFFERS; i++) {
    if (oldest_lru_priority > g_side_buffer_metadata[i].lru_priority) {
      oldest_lru_priority = g_side_buffer_metadata[i].lru_priority;
      oldest_i = i;
    }
  }
  g_side_buffer_metadata[oldest_i].index_within_archive = -1;
  g_side_buffer_metadata[oldest_i].offset_within_entry = -1;
  g_side_buffer_metadata[oldest_i].length = -1;
  g_side_buffer_metadata[oldest_i].lru_priority = UINT64_MAX;
  return oldest_i;
}

bool ReadFromSideBuffer(i64 const index_within_archive,
                        char* const dst_ptr,
                        size_t const dst_len,
                        i64 const offset_within_entry) {
  // Find the longest side buffer that contains (index_within_archive,
  // offset_within_entry, dst_len).
  int best_i = -1;
  i64 best_length = -1;
  for (int i = 0; i < NUM_SIDE_BUFFERS; i++) {
    const SideBufferMetadata& meta = g_side_buffer_metadata[i];
    if (meta.length > best_length &&
        meta.Contains(index_within_archive, offset_within_entry, dst_len)) {
      best_i = i;
      best_length = meta.length;
    }
  }

  if (best_i >= 0) {
    SideBufferMetadata& meta = g_side_buffer_metadata[best_i];
    meta.lru_priority = ++SideBufferMetadata::next_lru_priority;
    const i64 o = offset_within_entry - meta.offset_within_entry;
    memcpy(dst_ptr, g_side_buffer_data[best_i] + o, dst_len);
    return true;
  }

  return false;
}

// A Reader bundles libarchive concepts (an archive and an archive entry) and
// other state to point to a particular offset (in decompressed space) of a
// particular archive entry (identified by its index) in an archive.
//
// A Reader is backed by its own archive_read_open call so each can be
// positioned independently.
struct Reader : bi::list_base_hook<LinkMode> {
  // Number of Readers created so far.
  static int count;

  int id = ++count;
  ArchivePtr archive = ArchivePtr(archive_read_new());
  Entry* entry = nullptr;
  i64 index_within_archive = 0;
  i64 offset_within_entry = 0;
  bool should_print_progress = false;
  i64 pos = 0;
  std::byte bytes[16 * 1024];

  ~Reader() { LOG(DEBUG) << "Deleted " << *this; }

  Reader() {
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

    Check(archive_read_support_filter_all(archive.get()));
    Check(archive_read_support_format_all(archive.get()));
    Check(archive_read_support_format_raw(archive.get()));

    Check(archive_read_set_callback_data(archive.get(), this));
    Check(archive_read_set_read_callback(archive.get(), Read));
    Check(archive_read_set_seek_callback(archive.get(), Seek));
    Check(archive_read_set_skip_callback(archive.get(), Skip));
    Check(archive_read_open1(archive.get()));

    LOG(DEBUG) << "Created " << *this;
  }

  friend std::ostream& operator<<(std::ostream& out, const Reader& r) {
    return out << "Reader #" << r.id;
  }

  Entry* NextEntry() {
    offset_within_entry = 0;
    index_within_archive++;
    const int status = archive_read_next_header(archive.get(), &entry);

    if (status == ARCHIVE_EOF) {
      entry = nullptr;
      return nullptr;
    }

    if (status == ARCHIVE_WARN) {
      LOG(WARNING) << archive_error_string(archive.get());
    } else if (status != ARCHIVE_OK) {
      const std::string_view error = archive_error_string(archive.get());
      LOG(ERROR) << "Cannot advance to entry " << index_within_archive << ": "
                 << error;
      ThrowExitCode(error);
    }

    assert(entry);
    return entry;
  }

  // Walks forward until positioned at the want'th index. An index identifies an
  // archive entry. If this Reader wasn't already positioned at that index, it
  // also resets the Reader's offset to zero.
  void AdvanceIndex(i64 const want) {
    if (index_within_archive == want) {
      return;
    }

    assert(index_within_archive < want);
    const Timer timer;

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
    if (offset_within_entry == want) {
      // We are exactly where we want to be.
      return;
    }

    assert(offset_within_entry < want);

    const Timer timer;

    // We are behind where we want to be. Advance (decompressing from the
    // archive entry into a side buffer) until we get there.
    const int sb = AcquireSideBuffer();
    assert(0 <= sb && sb < NUM_SIDE_BUFFERS);

    uint8_t* const dst_ptr = g_side_buffer_data[sb];
    SideBufferMetadata& meta = g_side_buffer_metadata[sb];
    meta.lru_priority = ++SideBufferMetadata::next_lru_priority;
    meta.index_within_archive = index_within_archive;

    do {
      meta.offset_within_entry = offset_within_entry;
      i64 dst_len = want - offset_within_entry;
      assert(dst_len > 0);
      // If the amount we need to advance is greater than the SIDE_BUFFER_SIZE,
      // we need multiple Read calls, but the total advance might not be an
      // exact multiple of SIDE_BUFFER_SIZE. Read that remainder amount first,
      // not last. For example, if advancing 260KiB with a 128KiB
      // SIDE_BUFFER_SIZE then read 4+128+128 instead of 128+128+4. This leaves
      // a full side buffer when we've finished advancing, maximizing later
      // requests' chances of side-buffer-as-cache hits.
      if (dst_len > SIDE_BUFFER_SIZE) {
        dst_len %= SIDE_BUFFER_SIZE;
        if (dst_len == 0) {
          dst_len = SIDE_BUFFER_SIZE;
        }
      }

      meta.length = 0;
      const ssize_t n = Read(dst_ptr, dst_len);
      assert(n >= 0);

      meta.length = n;
    } while (offset_within_entry < want);

    assert(offset_within_entry == want);
    LOG(DEBUG) << "Advanced " << *this << " to offset " << offset_within_entry
               << " in " << timer;
  }

  // Gets the current entry size. 'Raw' archives don't always explicitly record
  // the decompressed size. We'll have to decompress it to find out. Some
  // 'cooked' archives also don't explicitly record this (at the time
  // archive_read_next_header returns). See
  // https://github.com/libarchive/libarchive/issues/1764
  i64 GetEntrySize() {
    if (archive_entry_size_is_set(entry)) {
      return archive_entry_size(entry);
    }

    // Consume the entry's data.
    std::byte buffer[16 << 10];
    while (Read(buffer, sizeof(buffer))) {
    }

    if (archive_entry_is_encrypted(entry)) {
      g_password_checked = true;
    }

    return offset_within_entry;
  }

  void CheckPassword() {
    if (g_password_checked || !archive_entry_is_encrypted(entry)) {
      return;
    }

    // Reading the first bytes of the first encrypted entry will reveal whether
    // we also need a passphrase.
    std::byte buffer[16];
    g_password_checked = Read(buffer, sizeof(buffer)) > 0;
  }

  // Copies from the archive entry's decompressed contents to the destination
  // buffer. It also advances the Reader's offset_within_entry.
  ssize_t Read(void* const dst_ptr, size_t const dst_len) {
    const ssize_t n = archive_read_data(archive.get(), dst_ptr, dst_len);
    if (n < 0) {
      const std::string_view error = archive_error_string(archive.get());
      LOG(ERROR) << error;
      ThrowExitCode(error);
    }

    assert(n <= dst_len);
    offset_within_entry += n;
    return n;
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
  static Ptr ReuseOrCreate(i64 const want_index_within_archive,
                           i64 const want_offset_within_entry) {
    assert(want_index_within_archive > 0);
    assert(want_offset_within_entry >= 0);

    // Find the closest warm Reader that is below or at the requested position.
    Reader* best = nullptr;
    for (Reader& r : recycled) {
      if (std::pair(r.index_within_archive, r.offset_within_entry) <=
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
      r.reset(new Reader());
    }

    assert(r);
    r->AdvanceIndex(want_index_within_archive);
    r->AdvanceOffset(want_offset_within_entry);

    return r;
  }

 private:
  void Check(int const status) const {
    if (status != ARCHIVE_OK) {
      const std::string_view error = archive_error_string(archive.get());
      LOG(ERROR) << error;
      ThrowExitCode(error);
    }
  }

  // The following callbacks are used by libarchive to read the uncompressed
  // data from the archive file.
  static ssize_t Read(Archive* const a, void* const p, const void** const out) {
    assert(p);
    assert(g_archive_fd >= 0);
    Reader& r = *static_cast<Reader*>(p);
    while (true) {
      const ssize_t n = pread(g_archive_fd, r.bytes, sizeof(r.bytes), r.pos);
      if (n >= 0) {
        r.pos += n;
        r.PrintProgress();
        *out = r.bytes;
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

  static i64 Seek(Archive*, void* const p, i64 const offset, int const whence) {
    assert(p);
    Reader& r = *static_cast<Reader*>(p);
    switch (whence) {
      case SEEK_SET:
        r.pos = offset;
        return r.pos;
      case SEEK_CUR:
        r.pos += offset;
        return r.pos;
      case SEEK_END:
        r.pos = g_archive_size + offset;
        return r.pos;
    }
    return ARCHIVE_FATAL;
  }

  static i64 Skip(Archive*, void* const p, i64 const delta) {
    assert(p);
    Reader& r = *static_cast<Reader*>(p);
    r.pos += delta;
    return delta;
  };

  // Print progress if necessary.
  void PrintProgress() const {
    if (!should_print_progress) {
      return;
    }

    constexpr auto period = std::chrono::seconds(1);
    const auto now = std::chrono::steady_clock::now();
    static auto next = now + period;
    if (now < next) {
      return;
    }

    next = now + period;
    assert(g_archive_size > 0);
    LOG(INFO) << ProgressMessage(100 * std::min<i64>(pos, g_archive_size) /
                                 g_archive_size);
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

struct FileHandle {
  const Node* const node;
  Reader::Ptr reader;
};

// ---- In-Memory Directory Tree

// Validates, normalizes and returns e's path, prepending a leading "/" if it
// doesn't already have one.
std::string GetNormalizedPath(Entry* const e) {
  const char* const s =
      archive_entry_pathname_utf8(e) ?: archive_entry_pathname(e);
  if (!s || !*s) {
    LOG(ERROR) << "Entry has an empty path";
    return "";
  }

  const Path path = s;

  // For 'raw' archives, libarchive defaults to "data" when the compression file
  // format doesn't contain the original file's name. For fuse-archive, we use
  // the archive filename's innername instead. Given an archive filename of
  // "/foo/bar.txt.bz2", the sole file within will be served as "bar.txt".
  if (g_archive_format == ArchiveFormat::RAW && path == "data") {
    return Path(g_archive_path)
        .Split()
        .second.WithoutFinalExtension()
        .Normalize();
  }

  return path.Normalize();
}

// Checks if the given character is an ASCII digit.
bool IsAsciiDigit(const char c) {
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
Node* FindNode(std::string_view const path) {
  const auto it = g_nodes_by_path.find(Path(path).WithoutTrailingSeparator(),
                                       g_nodes_by_path.hash_function(),
                                       g_nodes_by_path.key_eq());
  return it == g_nodes_by_path.end() ? nullptr : &*it;
}

void RehashIfNecessary() {
  if (g_nodes_by_path.size() > buckets.size()) {
    Buckets new_buckets(buckets.size() * 2);
    buckets.swap(new_buckets);
    g_nodes_by_path.rehash({buckets.data(), buckets.size()});
  }
}

void RenameIfCollision(Node* const node) {
  assert(node);
  const auto [pos, ok] = g_nodes_by_path.insert(*node);
  if (ok) {
    RehashIfNecessary();
    return;
  }

  // There is a name collision
  LOG(DEBUG) << *node << " conflicts with " << *pos;

  // Extract filename extension
  std::string& f = node->name;
  const std::string::size_type e = Path(f).ExtensionPosition();
  const std::string ext(f, e);
  f.resize(e);
  RemoveNumericSuffix(f);
  const std::string base = f;

  // Add a number before the extension
  for (int* i = nullptr;;) {
    const std::string suffix =
        StrCat(" (", std::to_string(i ? ++*i + 1 : 1), ")", ext);
    f.assign(base, 0, Path(base).TruncationPosition(NAME_MAX - suffix.size()));
    f += suffix;

    const auto [pos, ok] = g_nodes_by_path.insert(*node);
    if (ok) {
      LOG(DEBUG) << "Resolved conflict for " << *node;
      RehashIfNecessary();
      return;
    }

    LOG(DEBUG) << *node << " conflicts with " << *pos;
    if (!i)
      i = &pos->collision_count;
  }
}

Node* GetOrCreateDirNode(std::string_view const path) {
  if (path == "/") {
    assert(g_root_node);
    assert(g_root_node->IsDir());
    return g_root_node;
  }

  const auto [parent_path, name] = Path(path).Split();
  Node* to_rename = nullptr;
  Node* parent = nullptr;

  if (Node* const node = FindNode(path)) {
    if (node->IsDir()) {
      return node;
    }

    // There is an existing node with the given name, but it's not a
    // directory.
    LOG(DEBUG) << "Found conflicting " << *node << " while creating Dir "
               << Path(path);
    parent = node->parent;

    // Remove it from g_nodes_by_path, in order to insert it again later with a
    // different name.
    to_rename = node;
    g_nodes_by_path.erase(g_nodes_by_path.iterator_to(*node));
  } else {
    parent = GetOrCreateDirNode(parent_path);
  }

  assert(parent);

  // Create the Directory node.
  Node* const node = new Node{.name = std::string(name),
                              .mode = S_IFDIR | (0777 & ~g_options.dmask),
                              .nlink = 2};
  parent->AddChild(node);
  assert(node->GetPath() == path);
  [[maybe_unused]] const auto [_, ok] = g_nodes_by_path.insert(*node);
  assert(ok);
  RehashIfNecessary();

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
    case FileType::File:
      return false;
  }

  return true;
}

void CacheEntryData(Archive* const a) {
  assert(g_cache_size >= 0);
  const i64 file_start_offset = g_cache_size;

  while (true) {
    const void* buff;
    size_t len;
    off_t offset;

    const int status = archive_read_data_block(a, &buff, &len, &offset);
    if (status == ARCHIVE_EOF) {
      return;
    }

    if (status == ARCHIVE_RETRY) {
      continue;
    }

    if (status == ARCHIVE_WARN) {
      LOG(WARNING) << archive_error_string(a);
    } else if (status != ARCHIVE_OK) {
      assert(status == ARCHIVE_FAILED || status == ARCHIVE_FATAL);
      const std::string_view error = archive_error_string(a);
      LOG(ERROR) << error;
      ThrowExitCode(error);
    }

    assert(offset >= g_cache_size - file_start_offset);
    offset += file_start_offset;
    assert(offset >= g_cache_size);
    g_cache_size = offset;

    while (len > 0) {
      const ssize_t n = pwrite(g_cache_fd, buff, len, offset);
      if (n < 0) {
        if (errno == EINTR) {
          continue;
        }

        PLOG(ERROR) << "Cannot write to cache";
        throw ExitCode::CANNOT_WRITE_CACHE;
      }

      assert(n <= len);
      buff = static_cast<const std::byte*>(buff) + n;
      len -= n;
      offset += n;
      g_cache_size = offset;
    }
  }
}

void ProcessEntry(Reader& r) {
  Archive* const a = r.archive.get();
  Entry* const e = r.entry;
  const i64 i = r.index_within_archive;
  mode_t mode = archive_entry_mode(e);
  const FileType ft = GetFileType(mode);

  std::string path = GetNormalizedPath(e);
  if (path.empty()) {
    LOG(DEBUG) << "Skipped " << ft << " [" << i << "]: Invalid path";
    return;
  }

  if (const char* const s =
          archive_entry_hardlink_utf8(e) ?: archive_entry_hardlink(e)) {
    // Entry is a hard link. Save it for further resolution.
    std::string target = Path(s).Normalize();
    g_hardlinks_to_resolve.emplace_back(std::move(path), std::move(target));
    return;
  }

  if (ShouldSkip(ft)) {
    LOG(DEBUG) << "Skipped " << ft << " [" << i << "] " << Path(path);
    return;
  }

  // Is this entry a directory?
  if (ft == FileType::Directory) {
    Node* const node = GetOrCreateDirNode(path);
    assert(node);

    if (archive_entry_mtime_is_set(e)) {
      node->mtime = archive_entry_mtime(e);
    }

    if (g_default_permissions) {
      node->uid = archive_entry_uid(e);
      node->gid = archive_entry_gid(e);
      const mode_t pbits = 0777;
      node->mode &= ~pbits;
      node->mode |= mode & pbits;
    }

    return;
  }

  // This entry is not a directory.
  const auto [parent_path, name] = Path(path).Split();

  // Get or create the parent node.
  Node* const parent = GetOrCreateDirNode(parent_path);
  assert(parent);
  assert(parent->IsDir());

  // Create the node for this entry.
  Node* const node = new Node{
      .name = std::string(name),
      .mode = static_cast<mode_t>(ft) | (0666 & ~g_options.fmask),
      .index_within_archive = i,
      .mtime = archive_entry_mtime_is_set(e) ? archive_entry_mtime(e) : g_now};

  if (g_default_permissions) {
    node->uid = archive_entry_uid(e);
    node->gid = archive_entry_gid(e);
    const mode_t pbits = 0777;
    node->mode &= ~pbits;
    node->mode |= mode & pbits;
  } else if (const mode_t xbits = 0111; (mode & xbits) != 0) {
    // Adjust the access bits if the file is executable.
    node->mode |= xbits & ~g_options.fmask;
  }

  parent->AddChild(node);

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
  if (g_cache) {
    // Cache file data.
    node->size = archive_entry_size(e);
    i64 const offset = g_cache_size;
    CacheEntryData(a);
    node->cache_offset = offset;
    node->size = g_cache_size - offset;
  } else {
    // Get the entry size without caching the data.
    node->size = r.GetEntrySize();
  }

  // Check password if necessary.
  r.CheckPassword();

  // Adjust the total block count.
  g_block_count += node->GetBlockCount();
}

// Resolve the hardlinks set aside in g_hardlinks_to_resolve.
void ResolveHardlinks() {
  for (const Hardlink& entry : g_hardlinks_to_resolve) {
    // Find its target.
    Node* target = FindNode(entry.target_path);
    if (!target) {
      LOG(DEBUG) << "Skipped hardlink " << Path(entry.source_path)
                 << ": Cannot find target " << Path(entry.target_path);
      continue;
    }

    while (target->hardlink_target) {
      target = target->hardlink_target;
    }

    if (target->IsDir()) {
      LOG(DEBUG) << "Skipped hardlink " << Path(entry.source_path)
                 << ": Target " << Path(entry.target_path) << " is a directory";
      continue;
    }

    const auto [parent_path, name] = Path(entry.source_path).Split();

    // Get or create the parent node.
    Node* const parent = GetOrCreateDirNode(parent_path);
    assert(parent);
    assert(parent->IsDir());

    // Create the node for this entry.
    Node* const node = new Node{
        .name = std::string(name),
        .symlink = target->symlink,
        .mode = target->mode,
        .ino = g_hardlinks ? target->ino : ++Node::count,
        .uid = target->uid,
        .gid = target->gid,
        .index_within_archive = target->index_within_archive,
        .size = target->size,
        .cache_offset = target->cache_offset,
        .mtime = target->mtime,
        .rdev = target->rdev,
        .nlink = g_hardlinks ? (target->nlink++, 0) : 1,
        .hardlink_target = g_hardlinks ? target : nullptr,
    };

    parent->AddChild(node);
    RenameIfCollision(node);

    LOG(DEBUG) << "Resolved Hardlink " << Path(node->GetPath()) << " -> "
               << *target;
  }

  g_hardlinks_to_resolve.clear();
}

void CheckRawArchive(Archive* const a) {
  if (g_archive_format != ArchiveFormat::NONE) {
    // Already checked.
    return;
  }

  g_archive_format = ArchiveFormat(archive_format(a));
  LOG(DEBUG) << "Archive format is " << archive_format_name(a);

  int filter_count = 0;
  for (int i = archive_filter_count(a); i > 0;) {
    if (archive_filter_code(a, --i) != ARCHIVE_FILTER_NONE) {
      ++filter_count;
      LOG(DEBUG) << "Filter #" << filter_count << " is "
                 << archive_filter_name(a, i);
    }
  }

  // For 'raw' archives, check that at least one of the compression filters
  // (e.g. bzip2, gzip) actually triggered. We don't want to mount arbitrary
  // data (e.g. foo.jpeg).
  if (g_archive_format == ArchiveFormat::RAW && filter_count == 0) {
    LOG(ERROR) << "Cannot recognize the a format";
    throw ExitCode::INVALID_RAW_ARCHIVE;
  }
}

// Opens the archive file, scans it and builds the tree representing the files
// and directories contained in this archive.
void BuildTree() {
  if (g_archive_path.empty()) {
    LOG(ERROR) << "Missing archive_filename argument";
    throw ExitCode::GENERIC_FAILURE;
  }

  Timer timer;

  // Open archive file.
  g_archive_fd = open(g_archive_path.c_str(), O_RDONLY);
  if (g_archive_fd < 0) {
    PLOG(ERROR) << "Cannot open " << Path(g_archive_path);
    throw ExitCode::CANNOT_OPEN_ARCHIVE;
  }

  // Check archive file size and type.
  if (struct stat z; fstat(g_archive_fd, &z) != 0) {
    PLOG(ERROR) << "Cannot stat " << Path(g_archive_path);
    throw ExitCode::CANNOT_OPEN_ARCHIVE;
  } else if (const FileType ft = GetFileType(z.st_mode); ft != FileType::File) {
    LOG(ERROR) << "Archive " << Path(g_archive_path)
               << " is not a regular file: It is a " << ft;
    throw ExitCode::CANNOT_OPEN_ARCHIVE;
  } else {
    g_archive_size = z.st_size;
    LOG(DEBUG) << "Archive file size is " << g_archive_size << " bytes";
  }

  // Prepare a Reader to read the archive.
  Reader r;
  r.should_print_progress = LOG_IS_ON(INFO) && g_archive_size > 0;

  // Create root node.
  assert(!g_root_node);
  g_root_node = new Node{
      .name = "/", .mode = S_IFDIR | (0777 & ~g_options.dmask), .nlink = 2};
  [[maybe_unused]] const auto [_, ok] = g_nodes_by_path.insert(*g_root_node);
  assert(ok);

  // Read and process every entry of the archive.
  try {
    while (Entry* const entry = r.NextEntry()) {
      CheckRawArchive(r.archive.get());

      try {
        ProcessEntry(r);
      } catch (ExitCode const error) {
        if (!g_force) {
          throw;
        }

        LOG(DEBUG) << "Suppressing error " << error << " because of -o force";
      }
    }

    // Resolve hardlinks.
    ResolveHardlinks();

    if (g_latest_log_is_ephemeral) {
      LOG(INFO) << ProgressMessage(100);
    }
  } catch (ExitCode const error) {
    if (!g_force || g_nodes_by_path.size() <= 1) {
      throw;
    }

    LOG(DEBUG) << "Suppressing error " << error << " because of -o force";
  }

  // Log some debug messages.
  if (LOG_IS_ON(DEBUG)) {
    LOG(DEBUG) << "Loaded " << Path(g_archive_path) << " in " << timer;
    LOG(DEBUG) << "The archive contains " << g_nodes_by_path.size() << " items";
    if (struct stat z; g_cache && fstat(g_cache_fd, &z) == 0) {
      LOG(DEBUG) << "The cache takes " << i64(z.st_blocks) * block_size
                 << " bytes of disk space";
      assert(z.st_size == g_cache_size);
    }
  }

  // Close archive file is decompressed data is already cached.
  if (g_cache && close(std::exchange(g_archive_fd, -1)) < 0) {
    PLOG(ERROR) << "Cannot close archive file";
  }
}

// ---- FUSE Callbacks

int my_getattr(const char* const path, struct stat* const z) {
  const Node* const n = FindNode(path);
  if (!n) {
    LOG(DEBUG) << "Cannot stat " << Path(path) << ": No such item";
    return -ENOENT;
  }

  assert(z);
  *z = n->GetStat();
  return 0;
}

int my_readlink(const char* const path,
                char* const dst_ptr,
                size_t const dst_len) {
  const Node* const n = FindNode(path);
  if (!n) {
    LOG(ERROR) << "Cannot read link " << Path(path) << ": No such item";
    return -ENOENT;
  }

  assert(n->GetType() == FileType::Symlink);
  if (n->symlink.empty() || dst_len == 0) {
    return -ENOLINK;
  }

  snprintf(dst_ptr, dst_len, "%s", n->symlink.c_str());
  return 0;
}

int my_open(const char* const path, fuse_file_info* const ffi) try {
  const Node* const n = FindNode(path);
  if (!n) {
    LOG(ERROR) << "Cannot open " << Path(path) << ": No such item";
    return -ENOENT;
  }

  assert(!n->IsDir());
  assert(n->index_within_archive > 0);

  if (g_cache && n->cache_offset < 0) {
    LOG(ERROR) << "Cannot open " << *n << ": No cached data";
    return -EIO;
  }

  assert(ffi);
  static_assert(sizeof(ffi->fh) >= sizeof(FileHandle*));
  ffi->fh = reinterpret_cast<uintptr_t>(new FileHandle{.node = n});
  LOG(DEBUG) << "Opened " << *n;
  return 0;
} catch (...) {
  LOG(DEBUG) << "Caught exception";
  return -EIO;
}

int my_read(const char*,
            char* const dst_ptr,
            size_t dst_len,
            off_t offset,
            fuse_file_info* const ffi) try {
  if (offset < 0 || dst_len > std::numeric_limits<int>::max()) {
    return -EINVAL;
  }

  FileHandle* const h = reinterpret_cast<FileHandle*>(ffi->fh);
  assert(h);

  const Node* const node = h->node;
  assert(node);

  if (g_cache) {
    if (offset >= node->size) {
      // No data past the end of a file.
      return 0;
    }

    if (dst_len >= node->size - offset) {
      // No data past the end of a file.
      dst_len = node->size - offset;
    }

    assert(node->cache_offset >= 0);
    offset += node->cache_offset;

    // Read data from the cache file.
    const ssize_t n = pread(g_cache_fd, dst_ptr, dst_len, offset);
    if (n < 0) {
      const error_t e = errno;
      PLOG(ERROR) << "Cannot read " << dst_len << " bytes from cache at offset "
                  << offset;
      return -e;
    }

    assert(n <= dst_len);
    return n;
  }

  const i64 size = node->size;
  assert(size >= 0);
  if (size <= offset) {
    return 0;
  }

  const i64 remaining = size - offset;
  if (dst_len > remaining) {
    dst_len = remaining;
  }

  if (dst_len == 0) {
    return 0;
  }

  if (ReadFromSideBuffer(node->index_within_archive, dst_ptr, dst_len,
                         offset)) {
    return dst_len;
  }

  // libarchive is designed for streaming access, not random access. If we
  // need to seek backwards, there's more work to do.
  if (Reader* const r = h->reader.get()) {
    assert(r->index_within_archive == node->index_within_archive);
    if (offset < r->offset_within_entry) {
      LOG(DEBUG) << *r << " cannot jump " << r->offset_within_entry - offset
                 << " bytes backwards from offset " << r->offset_within_entry
                 << " to " << offset;
      h->reader.reset();
    } else if (offset > r->offset_within_entry + SIDE_BUFFER_SIZE) {
      LOG(DEBUG) << *r << " might have to jump "
                 << offset - r->offset_within_entry
                 << " bytes forwards from offset " << r->offset_within_entry
                 << " to " << offset;
      h->reader.reset();
    }
  }

  if (h->reader) {
    assert(h->reader->index_within_archive == node->index_within_archive);
    h->reader->AdvanceOffset(offset);
  } else {
    h->reader = Reader::ReuseOrCreate(node->index_within_archive, offset);
  }

  assert(h->reader);
  assert(h->reader->index_within_archive == node->index_within_archive);
  assert(h->reader->offset_within_entry == offset);
  return h->reader->Read(dst_ptr, dst_len);
} catch (...) {
  LOG(DEBUG) << "Caught exception";
  return -EIO;
}

int my_release(const char*, fuse_file_info* const ffi) {
  FileHandle* const h = reinterpret_cast<FileHandle*>(ffi->fh);
  assert(h);

  const Node* const n = h->node;
  assert(n);
  delete h;

  LOG(DEBUG) << "Closed " << *n;
  return 0;
}

int my_readdir(const char* path,
               void* const buf,
               fuse_fill_dir_t const filler,
               off_t,
               fuse_file_info*) {
  const Node* const n = FindNode(path);
  if (!n) {
    LOG(ERROR) << "Cannot read dir " << Path(path) << ": No such item";
    return -ENOENT;
  }

  if (!n->IsDir()) {
    LOG(ERROR) << "Cannot read dir " << *n << ": Not a directory";
    return -ENOTDIR;
  }

  if (filler(buf, ".", nullptr, 0) || filler(buf, "..", nullptr, 0)) {
    return -ENOMEM;
  }

  for (const Node& child : n->children) {
    const struct stat z = child.GetStat();
    if (filler(buf, child.name.c_str(), &z, 0)) {
      return -ENOMEM;
    }
  }

  LOG(DEBUG) << "Read Directory " << Path(path) << " returned "
             << n->children.size() << " items";
  return 0;
}

int my_statfs(const char*, struct statvfs* const st) {
  assert(st);
  st->f_bsize = block_size;
  st->f_frsize = block_size;
  st->f_blocks = g_block_count;
  st->f_bfree = 0;
  st->f_bavail = 0;
  st->f_files = Node::count;
  st->f_ffree = 0;
  st->f_favail = 0;
  st->f_flag = ST_RDONLY;
  st->f_namemax = NAME_MAX;
  return 0;
}

void* my_init(fuse_conn_info*) {
  return nullptr;
}

void my_destroy(void* arg) {
  assert(!arg);
}

const struct fuse_operations my_operations = {
    .getattr = my_getattr,
    .readlink = my_readlink,
    .open = my_open,
    .read = my_read,
    .statfs = my_statfs,
    .release = my_release,
    .readdir = my_readdir,
    .init = my_init,
    .destroy = my_destroy,
};

// ---- Main

int my_opt_proc(void*, const char* const arg, int const key, fuse_args*) {
  constexpr int KEEP = 1;
  constexpr int DISCARD = 0;
  constexpr int ERROR = -1;

  switch (key) {
    case FUSE_OPT_KEY_NONOPT:
      switch (++g_arg_count) {
        case 1:
          g_archive_path = arg;
          return DISCARD;

        case 2:
          g_mount_point = arg;
          return DISCARD;

        default:
          LOG(ERROR) << "Too many arguments";
          return ERROR;
      }

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

    case KEY_NO_CACHE:
      g_cache = false;
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

    case KEY_DEFAULT_PERMISSIONS:
      g_default_permissions = true;
      return KEEP;
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

  const std::string_view want = "UTF-8";
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
  std::cerr << "usage: " PROGRAM_NAME
               R"( [options] <archive_file> [mount_point]

general options:
    -o opt,[opt...]        mount options
    -h   --help            print help
    -V   --version         print version

)" PROGRAM_NAME R"( options:
    -q   --quiet           do not print progress messages
    -v   --verbose         print more log messages
         --redact          redact paths from log messages
         -o force          continue despite errors
         -o nocache        no caching of uncompressed data
         -o nospecials     no special files (FIFOs, sockets, devices)
         -o nosymlinks     no symlinks
         -o nohardlinks    no hardlinks
         -o dmask=M        directory permission mask in octal (default 0022)
         -o fmask=M        file permission mask in octal (default 0022)

)";
}

}  // namespace

int main(int const argc, char** const argv) try {
  // Ensure that numbers in debug messages have thousands separators.
  // It makes big numbers much easier to read (eg sizes expressed in bytes).
  std::locale::global(std::locale(std::locale::classic(), new NumPunct));
  openlog(PROGRAM_NAME, LOG_PERROR, LOG_USER);
  SetLogLevel(LogLevel::INFO);

  EnsureUtf8();

  fuse_args args = FUSE_ARGS_INIT(argc, argv);
  if (fuse_opt_parse(&args, &g_options, g_fuse_opts, &my_opt_proc) < 0) {
    LOG(ERROR) << "Cannot parse command line arguments";
    throw ExitCode::GENERIC_FAILURE;
  }

  if (g_help) {
    PrintUsage();
    fuse_opt_add_arg(&args, "-ho");  // I think ho means "help output".
    fuse_main(args.argc, args.argv, &my_operations, nullptr);
    return EXIT_SUCCESS;
  }

  if (g_version) {
    std::cerr << PROGRAM_NAME " version: " PROGRAM_VERSION "\n";
    std::cerr << "libarchive version: " << archive_version_string() << "\n";
    if (const char* const s = archive_bzlib_version()) {
      std::cerr << "bzlib version: " << s << "\n";
    }
    if (const char* const s = archive_liblz4_version()) {
      std::cerr << "liblz4 version: " << s << "\n";
    }
    if (const char* const s = archive_liblzma_version()) {
      std::cerr << "liblzma version: " << s << "\n";
    }
    if (const char* const s = archive_libzstd_version()) {
      std::cerr << "libzstd version: " << s << "\n";
    }
    if (const char* const s = archive_zlib_version()) {
      std::cerr << "zlib version: " << s << "\n";
    }

    fuse_opt_add_arg(&args, "--version");
    fuse_main(args.argc, args.argv, &my_operations, nullptr);
    return EXIT_SUCCESS;
  }

  if (g_archive_path.empty()) {
    PrintUsage();
    return EXIT_FAILURE;
  }

  // Determine where the mount point should be.
  std::string mount_point_parent, mount_point_basename;
  const bool mount_point_specified_by_user = !g_mount_point.empty();
  if (!mount_point_specified_by_user) {
    g_mount_point =
        Path(g_archive_path).WithoutTrailingSeparator().WithoutExtension();
  }

  std::tie(mount_point_parent, mount_point_basename) =
      Path(g_mount_point).WithoutTrailingSeparator().Split();

  if (mount_point_basename.empty()) {
    LOG(ERROR) << "Cannot use " << Path(g_mount_point) << " as a mount point";
    throw ExitCode::CANNOT_CREATE_MOUNT_POINT;
  }

  // Get a file descriptor to the parent directory of the mount point.
  const int mount_point_parent_fd =
      open(!mount_point_parent.empty() ? mount_point_parent.c_str() : ".",
           O_DIRECTORY | O_PATH);
  if (mount_point_parent_fd < 0) {
    PLOG(ERROR) << "Cannot access directory " << Path(mount_point_parent);
    throw ExitCode::CANNOT_CREATE_MOUNT_POINT;
  }

  // Create cache file if necessary.
  if (g_cache) {
    CreateCacheFile();
    CheckCacheFile();
  } else {
    // Force single-threading if no cache is used.
    fuse_opt_add_arg(&args, "-s");
  }

  // Read archive and build tree.
  BuildTree();

  // Create the mount point if it does not already exist.
  Cleanup cleanup;
  {
    const auto n = mount_point_basename.size();
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

        break;
      }

      if (errno != EEXIST) {
        PLOG(ERROR) << "Cannot create mount point " << Path(g_mount_point);
        throw ExitCode::CANNOT_CREATE_MOUNT_POINT;
      }

      if (mount_point_specified_by_user) {
        LOG(INFO) << "Using existing mount point " << Path(g_mount_point);
        break;
      }

      LOG(DEBUG) << "Mount point " << Path(g_mount_point) << " already exists";
      mount_point_basename.resize(n);
      mount_point_basename += StrCat(" (", ++i, ")");
    }
  }

  // The mount point is in place.
  fuse_opt_add_arg(&args, g_mount_point.c_str());

  // Respect inode numbers.
  fuse_opt_add_arg(&args, "-ouse_ino");

  // Mount read-only.
  fuse_opt_add_arg(&args, "-o");
  fuse_opt_add_arg(&args, "ro");

  // Start serving the filesystem.
  const int res = fuse_main(args.argc, args.argv, &my_operations, nullptr);
  LOG(DEBUG) << "Returning " << ExitCode(res);
  return res;
} catch (const ExitCode e) {
  LOG(DEBUG) << "Returning " << e;
  return static_cast<int>(e);
} catch (const std::exception& e) {
  LOG(ERROR) << e.what();
  LOG(DEBUG) << "Returning " << ExitCode::GENERIC_FAILURE;
  return static_cast<int>(ExitCode::GENERIC_FAILURE);
}
