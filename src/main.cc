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

// ----------------

// fuse-archive read-only mounts an archive or compressed file (e.g. foo.tar,
// foo.tar.gz, foo.xz, foo.zip) as a FUSE file system
// (https://en.wikipedia.org/wiki/Filesystem_in_Userspace).
//
// To build:
//   g++ -O3 main.cc `pkg-config libarchive fuse --cflags --libs` -o example
//
// To use:
//   ./example ../test/data/archive.zip the/path/to/the/mountpoint
//   ls -l                              the/path/to/the/mountpoint
//   fusermount -u                      the/path/to/the/mountpoint
//
// Pass the "-f" flag to "./example" for foreground operation.

// ---- Preprocessor

#define FUSE_USE_VERSION 26

#include <archive.h>
#include <archive_entry.h>
#include <fcntl.h>
#include <fuse.h>
#include <langinfo.h>
#include <locale.h>
#include <sys/stat.h>
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
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace {

#define TRY(operation)               \
  do {                               \
    int try_status_code = operation; \
    if (try_status_code) {           \
      return try_status_code;        \
    }                                \
  } while (false)

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
  PASSPHRASE_REQUIRED = 20,
  PASSPHRASE_INCORRECT = 21,
  PASSPHRASE_NOT_SUPPORTED = 22,
  INVALID_RAW_ARCHIVE = 30,
  INVALID_ARCHIVE_HEADER = 31,
  INVALID_ARCHIVE_CONTENTS = 32,
};

// ---- Compile-time Configuration

#define PROGRAM_NAME "fuse-archive"

#ifndef FUSE_ARCHIVE_VERSION
#define FUSE_ARCHIVE_VERSION "0.1.14"
#endif

constexpr int NUM_SIDE_BUFFERS = 8;

// This defaults to 128 KiB (0x20000 bytes) because, on a vanilla x86_64 Debian
// Linux, that seems to be the largest buffer size passed to my_read.
constexpr ssize_t SIDE_BUFFER_SIZE = 131072;

// ---- Platform specifics

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
#define lseek64 lseek
#endif

// ---- Globals

struct {
  int arg_count = 0;
  bool help = false;
  bool version = false;
  bool quiet = false;
  bool redact = false;
} g_options;

enum {
  KEY_HELP,
  KEY_VERSION,
  KEY_QUIET,
  KEY_VERBOSE,
  KEY_REDACT,
};

fuse_opt g_fuse_opts[] = {
    FUSE_OPT_KEY("-h", KEY_HELP),            //
    FUSE_OPT_KEY("--help", KEY_HELP),        //
    FUSE_OPT_KEY("-V", KEY_VERSION),         //
    FUSE_OPT_KEY("--version", KEY_VERSION),  //
    FUSE_OPT_KEY("--quiet", KEY_QUIET),      //
    FUSE_OPT_KEY("-q", KEY_QUIET),           //
    FUSE_OPT_KEY("--verbose", KEY_VERBOSE),  //
    FUSE_OPT_KEY("-v", KEY_VERBOSE),         //
    FUSE_OPT_KEY("--redact", KEY_REDACT),    //
    FUSE_OPT_KEY("redact", KEY_REDACT),      //
    // The remaining options are listed for e.g. "-o formatraw" command line
    // compatibility with the https://github.com/cybernoid/archivemount program
    // but are otherwise ignored. For example, this program detects 'raw'
    // archives automatically and only supports read-only, not read-write.
    FUSE_OPT_KEY("--passphrase", FUSE_OPT_KEY_DISCARD),  //
    FUSE_OPT_KEY("passphrase", FUSE_OPT_KEY_DISCARD),    //
    FUSE_OPT_KEY("formatraw", FUSE_OPT_KEY_DISCARD),     //
    FUSE_OPT_KEY("nobackup", FUSE_OPT_KEY_DISCARD),      //
    FUSE_OPT_KEY("nosave", FUSE_OPT_KEY_DISCARD),        //
    FUSE_OPT_KEY("readonly", FUSE_OPT_KEY_DISCARD),      //
    FUSE_OPT_END,
};

// Command line argument naming the archive file.
std::string g_archive_filename;

// Base name of g_archive_filename, minus the file extension suffix. For
// example, if g_archive_filename is "/foo/bar.tar.gz" then
// g_archive_innername is "bar".
std::string g_archive_innername;

// Path of the mount point.
std::string g_mount_point;

// g_archive_fd is the file descriptor returned by opening g_archive_filename.
int g_archive_fd = -1;

// g_archive_file_size is the size of the g_archive_filename file.
int64_t g_archive_file_size = 0;

// g_archive_fd_position_current is the read position of g_archive_fd.
//
// etc_hwm is the etc_current high water mark (the largest value seen). When
// compared to g_archive_file_size, it proxies what proportion of the archive
// has been processed. This matters for 'raw' archives that need a complete
// decompression pass (as they do not have a table of contents within to
// explicitly record the decompressed file size).
int64_t g_archive_fd_position_current = 0;
int64_t g_archive_fd_position_hwm = 0;

// g_archive_realpath holds the canonicalised absolute path of the archive
// file. The command line argument may give a relative filename (one that
// doesn't start with a slash) and the fuse_main function may change the
// current working directory, so subsequent archive_read_open_filename calls
// use this absolute filepath instead. g_archive_filename is still used for
// logging. g_archive_realpath is allocated in pre_initialize and never freed.
const char* g_archive_realpath = nullptr;

// Decryption password.
std::string password;

// Number of times the decryption password has been requested.
int password_count = 0;

// g_archive_is_raw is whether the archive file is 'cooked' or 'raw'.
//
// We support 'cooked' archive files (e.g. foo.tar.gz or foo.zip) but also what
// libarchive calls 'raw' files (e.g. foo.gz), which are compressed but not
// explicitly an archive (a collection of files). libarchive can still present
// it as an implicit archive containing 1 file.
bool g_archive_is_raw = false;

// g_uid and g_gid are the user/group IDs for the files we serve. They're the
// same as the current uid/gid.
//
// libfuse will override my_getattr's use of these variables if the "-o uid=N"
// or "-o gid=N" command line options are set.
const uid_t g_uid = getuid();
const gid_t g_gid = getgid();

// We serve ls and stat requests from an in-memory directory tree of nodes.
// Building that tree is one of the first things that we do.
struct archive* g_initialize_archive = nullptr;
struct archive_entry* g_initialize_archive_entry = nullptr;
int64_t g_initialize_index_within_archive = -1;

// g_displayed_progress is whether we have printed a progress message.
bool g_displayed_progress = false;

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
        part = "-";

      Append(&result, part);
    }

    return result;
  }
};

std::ostream& operator<<(std::ostream& out, Path const path) {
  if (g_options.redact)
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
  Unknown = 0,            // Unknown
  BlockDevice = S_IFBLK,  // Block-oriented device
  CharDevice = S_IFCHR,   // Character-oriented device
  Directory = S_IFDIR,    // Directory
  Fifo = S_IFIFO,         // FIFO or pipe
  File = S_IFREG,         // Regular file
  Socket = S_IFSOCK,      // Socket
  Symlink = S_IFLNK,      // Symbolic link
};

FileType GetFileType(mode_t mode) {
  return FileType(mode & S_IFMT);
}

std::ostream& operator<<(std::ostream& out, const FileType t) {
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
    default:
      return out << "Unknown";
  }
}

constexpr blksize_t block_size = 512;

struct Node {
  // Name of this node in the context of its parent. This name should be a valid
  // and non-empty filename, and it shouldn't contain any '/' separator. The
  // only exception is the root directory, which is just named "/".
  std::string name;
  std::string symlink;
  mode_t mode;

  // Index of the entry represented by this node in the archive, or -1 if it is
  // not directly represented in the archive (like the root directory, or any
  // intermediate directory).
  int64_t index_within_archive = -1;
  int64_t size = 0;
  time_t mtime = 0;
  int nlink = 0;

  // Pointer to the parent node. Should be non null. The only exception is the
  // root directory which has a null parent pointer.
  Node* parent = nullptr;
  Node* last_child = nullptr;
  Node* first_child = nullptr;
  Node* next_sibling = nullptr;

  // Number of entries whose name have initially collided with this file node.
  int collision_count = 0;

  bool is_dir() const { return S_ISDIR(mode); }

  void add_child(Node* n) {
    assert(n);
    assert(!n->parent);
    assert(is_dir());
    // Count one "block" for each directory entry.
    size += block_size;
    n->nlink += 1;
    nlink += n->is_dir();
    n->parent = this;
    if (last_child == nullptr) {
      last_child = n;
      first_child = n;
    } else {
      last_child->next_sibling = n;
      last_child = n;
    }
  }

  int64_t get_block_count() const {
    return (size + (block_size - 1)) / block_size;
  }

  struct stat get_stat() const {
    struct stat z = {};
    z.st_nlink = nlink;
    z.st_mode = mode;
    z.st_nlink = 1;
    z.st_uid = g_uid;
    z.st_gid = g_gid;
    z.st_size = size;
    z.st_mtime = mtime;
    z.st_blksize = block_size;
    z.st_blocks = get_block_count();
    return z;
  }

  std::string path() const {
    if (!parent) {
      return name;
    }

    std::string path = parent->path();
    Path::Append(&path, name);
    return path;
  }
};

std::strong_ordering ComparePath(const Node* a, const Node* b);

std::strong_ordering ComparePath(const Node& a, const Node& b) {
  if (&a == &b) {
    return std::strong_ordering::equal;
  }

  if (const auto c = ComparePath(a.parent, b.parent);
      c != std::strong_ordering::equal) {
    return c;
  }

  return a.name <=> b.name;
}

std::strong_ordering ComparePath(const Node* const a, const Node* const b) {
  if (a) {
    if (b) {
      return ComparePath(*a, *b);
    } else {
      return std::strong_ordering::greater;
    }
  } else {
    if (b) {
      return std::strong_ordering::less;
    } else {
      return std::strong_ordering::equal;
    }
  }
}

std::ostream& operator<<(std::ostream& out, const Node& n) {
  return out << GetFileType(n.mode) << " " << Path(n.path());
}

// These global variables are the in-memory directory tree of nodes.
//
// Building the directory tree can take minutes, for archive file formats like
// .tar.gz that are compressed but also do not contain an explicit on-disk
// directory of archive entries.
std::unordered_map<std::string, Node*> g_nodes_by_path;
std::vector<Node*> g_nodes_by_index;

// Root node of the tree.
Node* const g_root_node =
    new Node{.name = "/", .mode = S_IFDIR | 0777, .nlink = 1};
blkcnt_t g_block_count = 1;

// g_saved_readers is a cache of warm readers. libarchive is designed for
// streaming access, not random access, and generally does not support seeking
// backwards. For example, if some other program reads "/foo", "/bar" and then
// "/baz" sequentially from an archive (via this program) and those correspond
// to the 60th, 40th and 50th archive entries in that archive, then:
//
//  - A naive implementation (calling archive_read_free when each FUSE file is
//    closed) would have to start iterating from the first archive entry each
//    time a FUSE file is opened, for 150 iterations (60 + 40 + 50) in total.
//  - Saving readers in an LRU (Least Recently Used) cache (calling
//    release_reader when each FUSE file is closed) allows just 110 iterations
//    (60 + 40 + 10) in total. The Reader for "/bar" can be re-used for "/baz".
//
// Re-use eligibility is based on the archive entries' sequential numerical
// indexes within the archive, not on their string pathnames.
//
// When copying all of the files out of an archive (e.g. "cp -r" from the
// command line) and the files are accessed in the natural order, caching
// readers means that the overall time can be linear instead of quadratic.
//
// Each array element is a pair. The first half of the pair is a unique_ptr for
// the Reader. The second half of the pair is a uint64_t LRU priority value.
// Higher/lower values are more/less recently used and the release_reader
// function evicts the array element with the lowest LRU priority value.
struct Reader;
constexpr int NUM_SAVED_READERS = 8;
std::pair<std::unique_ptr<Reader>, uint64_t>
    g_saved_readers[NUM_SAVED_READERS] = {};

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
uint8_t g_side_buffer_data[NUM_SIDE_BUFFERS][SIDE_BUFFER_SIZE] = {};
struct side_buffer_metadata {
  int64_t index_within_archive;
  int64_t offset_within_entry;
  int64_t length;
  uint64_t lru_priority;

  static uint64_t next_lru_priority;

  bool contains(int64_t index_within_archive,
                int64_t offset_within_entry,
                uint64_t length) {
    if (this->index_within_archive >= 0 &&
        this->index_within_archive == index_within_archive &&
        this->offset_within_entry <= offset_within_entry) {
      const int64_t o = offset_within_entry - this->offset_within_entry;
      return this->length >= o && (this->length - o) >= length;
    }
    return false;
  }
} g_side_buffer_metadata[NUM_SIDE_BUFFERS] = {};
uint64_t side_buffer_metadata::next_lru_priority = 0;

// The side buffers are also repurposed as source (compressed) and destination
// (decompressed) buffers during the initial pass over the archive file.
#define SIDE_BUFFER_INDEX_COMPRESSED 0
#define SIDE_BUFFER_INDEX_DECOMPRESSED 1

// ---- Libarchive Error Codes

// determine_passphrase_exit_code converts libarchive errors to fuse-archive
// exit codes. libarchive doesn't have designated passphrase-related error
// numbers. As for whether a particular archive file's encryption is supported,
// libarchive isn't consistent in archive_read_has_encrypted_entries returning
// ARCHIVE_READ_FORMAT_ENCRYPTION_UNSUPPORTED. Instead, we do a string
// comparison on the various possible error messages.
ExitCode determine_passphrase_exit_code(const std::string_view e) {
  if (e.starts_with("Incorrect passphrase")) {
    return ExitCode::PASSPHRASE_INCORRECT;
  }

  if (e.starts_with("Passphrase required")) {
    return ExitCode::PASSPHRASE_REQUIRED;
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
      return ExitCode::PASSPHRASE_NOT_SUPPORTED;
    }
  }

  return ExitCode::INVALID_ARCHIVE_CONTENTS;
}

template <typename... Args>
std::string StrCat(Args&&... args) {
  return (std::ostringstream() << ... << std::forward<Args>(args)).str();
}

// Logs a debug or error message.
//
// `priority` is one of:
// LOG_ERR        error conditions
// LOG_WARNING    warning conditions
// LOG_NOTICE     normal, but significant, condition
// LOG_INFO       informational message
// LOG_DEBUG      debug-level message
template <typename... Args>
void Log(int priority, Args&&... args) noexcept {
  try {
    syslog(priority, "%s", StrCat(std::forward<Args>(args)...).c_str());
  } catch (const std::exception& e) {
    syslog(LOG_ERR, "Cannot log message: %s", e.what());
  }
}

// Throws an std::system_error with the current errno.
template <typename... Args>
[[noreturn]] void ThrowSystemError(Args&&... args) {
  const int err = errno;
  throw std::system_error(err, std::system_category(),
                          StrCat(std::forward<Args>(args)...));
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

const char* read_password_from_stdin(struct archive*, void* /*data*/) {
  if (password_count++) {
    return nullptr;
  }

  const SuppressEcho guard;
  if (guard) {
    std::cout << "Password > " << std::flush;
  }

  // Read password from standard input.
  if (!std::getline(std::cin, password)) {
    password.clear();
  }

  if (guard) {
    std::cout << "Got it!" << std::endl;
  }

  // Remove newline at the end of password.
  while (password.ends_with('\n')) {
    password.pop_back();
  }

  if (password.empty()) {
    Log(LOG_DEBUG, "Got an empty password");
    return nullptr;
  }

  Log(LOG_DEBUG, "Got a password of ", password.size(), " bytes");
  return password.c_str();
}

// ---- Libarchive Read Callbacks

void update_g_archive_fd_position_hwm() {
  int64_t h = g_archive_fd_position_hwm;
  if (h < g_archive_fd_position_current) {
    g_archive_fd_position_hwm = g_archive_fd_position_current;
  }

  const auto period = std::chrono::seconds(1);
  static auto next = std::chrono::steady_clock::now() + period;
  const auto now = std::chrono::steady_clock::now();
  if (!g_options.quiet && now >= next) {
    next = now + period;
    const int percent = g_archive_file_size > 0
                            ? 100 *
                                  std::clamp<int64_t>(g_archive_fd_position_hwm,
                                                      0, g_archive_file_size) /
                                  g_archive_file_size
                            : 0;
    if (isatty(STDERR_FILENO)) {
      if (g_displayed_progress) {
        fprintf(stderr, "\e[F\e[K");
      }
      fprintf(stderr, "Loading %d%%\n", percent);
      fflush(stderr);
    } else {
      Log(LOG_INFO, "Loading ", percent, "%");
    }
    g_displayed_progress = true;
  }
}

// The callbacks below are only used during start-up, for the initial pass
// through the archive to build the node tree, based on the g_archive_fd file
// descriptor that stays open for the lifetime of the process. They are like
// libarchive's built-in "read from a file" callbacks but also update
// g_archive_fd_position_etc. The data arguments are ignored in favor of global
// variables.

int my_file_close(struct archive* a, void* /*data*/) {
  return ARCHIVE_OK;
}

int my_file_open(struct archive* a, void* /*data*/) {
  g_archive_fd_position_current = 0;
  g_archive_fd_position_hwm = 0;
  return ARCHIVE_OK;
}

ssize_t my_file_read(struct archive* a, void*, const void** out_dst_ptr) {
  uint8_t* dst_ptr = &g_side_buffer_data[SIDE_BUFFER_INDEX_COMPRESSED][0];
  while (true) {
    const ssize_t n = read(g_archive_fd, dst_ptr, SIDE_BUFFER_SIZE);
    if (n >= 0) {
      g_archive_fd_position_current += n;
      update_g_archive_fd_position_hwm();
      *out_dst_ptr = dst_ptr;
      return n;
    }

    if (errno == EINTR) {
      continue;
    }

    archive_set_error(a, errno, "could not read archive file: %s",
                      strerror(errno));
    break;
  }
  return ARCHIVE_FATAL;
}

int64_t my_file_seek(struct archive* a, void*, int64_t offset, int whence) {
  int64_t o = lseek64(g_archive_fd, offset, whence);
  if (o >= 0) {
    g_archive_fd_position_current = o;
    update_g_archive_fd_position_hwm();
    return o;
  }

  archive_set_error(a, errno, "could not seek in archive file: %s",
                    strerror(errno));
  return ARCHIVE_FATAL;
}

int64_t my_file_skip(struct archive* a, void* /*data*/, int64_t delta) {
  const int64_t o0 = lseek64(g_archive_fd, 0, SEEK_CUR);
  const int64_t o1 = lseek64(g_archive_fd, delta, SEEK_CUR);
  if (o1 >= 0 && o0 >= 0) {
    g_archive_fd_position_current = o1;
    update_g_archive_fd_position_hwm();
    return o1 - o0;
  }

  archive_set_error(a, errno, "could not seek in archive file: %s",
                    strerror(errno));
  return ARCHIVE_FATAL;
}

int my_file_switch(struct archive*, void* /*data0*/, void* /*data1*/) {
  return ARCHIVE_OK;
}

int my_archive_read_open(struct archive* a) {
  TRY(archive_read_set_callback_data(a, nullptr));
  TRY(archive_read_set_close_callback(a, my_file_close));
  TRY(archive_read_set_open_callback(a, my_file_open));
  TRY(archive_read_set_read_callback(a, my_file_read));
  TRY(archive_read_set_seek_callback(a, my_file_seek));
  TRY(archive_read_set_skip_callback(a, my_file_skip));
  TRY(archive_read_set_switch_callback(a, my_file_switch));
  return archive_read_open1(a);
}

// ---- Side Buffer

// acquire_side_buffer returns the index of the least recently used side
// buffer. This indexes g_side_buffer_data and g_side_buffer_metadata.
int acquire_side_buffer() {
  int oldest_i = 0;
  uint64_t oldest_lru_priority = g_side_buffer_metadata[0].lru_priority;
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

bool read_from_side_buffer(int64_t index_within_archive,
                           char* dst_ptr,
                           size_t dst_len,
                           int64_t offset_within_entry) {
  // Find the longest side buffer that contains (index_within_archive,
  // offset_within_entry, dst_len).
  int best_i = -1;
  int64_t best_length = -1;
  for (int i = 0; i < NUM_SIDE_BUFFERS; i++) {
    struct side_buffer_metadata* meta = &g_side_buffer_metadata[i];
    if (meta->length > best_length &&
        meta->contains(index_within_archive, offset_within_entry, dst_len)) {
      best_i = i;
      best_length = meta->length;
    }
  }

  if (best_i >= 0) {
    struct side_buffer_metadata* meta = &g_side_buffer_metadata[best_i];
    meta->lru_priority = ++side_buffer_metadata::next_lru_priority;
    int64_t o = offset_within_entry - meta->offset_within_entry;
    memcpy(dst_ptr, g_side_buffer_data[best_i] + o, dst_len);
    return true;
  }
  return false;
}

// ---- Reader

// Reader bundles libarchive concepts (an archive and an archive entry) and
// other state to point to a particular offset (in decompressed space) of a
// particular archive entry (identified by its index) in an archive.
//
// A Reader is backed by its own archive_read_open_filename call, managed by
// libarchive, so each can be positioned independently.
struct Reader {
  struct archive* archive;
  struct archive_entry* archive_entry = nullptr;
  int64_t index_within_archive = -1;
  int64_t offset_within_entry = 0;

  Reader(struct archive* _archive) : archive(_archive) {}

  ~Reader() {
    if (this->archive) {
      archive_read_free(this->archive);
    }
  }

  // advance_index walks forward until positioned at the want'th index. An
  // index identifies an archive entry. If this Reader wasn't already
  // positioned at that index, it also resets the Reader's offset to zero.
  //
  // It returns success (true) or failure (false).
  bool advance_index(int64_t want) {
    if (!this->archive) {
      return false;
    }

    while (this->index_within_archive < want) {
      const int status =
          archive_read_next_header(this->archive, &this->archive_entry);

      if (status == ARCHIVE_EOF) {
        Log(LOG_ERR, "Inconsistent archive");
        return false;
      }

      if (status != ARCHIVE_OK && status != ARCHIVE_WARN) {
        Log(LOG_ERR, "Invalid archive: %s",
            archive_error_string(this->archive));
        return false;
      }

      this->index_within_archive++;
      this->offset_within_entry = 0;
    }

    return true;
  }

  // advance_offset walks forward until positioned at the want'th offset. An
  // offset identifies a byte position relative to the start of an archive
  // entry's decompressed contents.
  //
  // The pathname is used for log messages.
  //
  // It returns success (true) or failure (false).
  bool advance_offset(int64_t want, const char* pathname) {
    if (!this->archive || !this->archive_entry) {
      return false;
    }

    if (want < this->offset_within_entry) {
      // We can't walk backwards.
      return false;
    }

    if (want == this->offset_within_entry) {
      // We are exactly where we want to be.
      return true;
    }

    // We are behind where we want to be. Advance (decompressing from the
    // archive entry into a side buffer) until we get there.
    const int sb = acquire_side_buffer();
    if (sb < 0 || NUM_SIDE_BUFFERS <= sb) {
      return false;
    }
    uint8_t* dst_ptr = g_side_buffer_data[sb];
    struct side_buffer_metadata* meta = &g_side_buffer_metadata[sb];
    while (want > this->offset_within_entry) {
      const int64_t original_owe = this->offset_within_entry;
      int64_t dst_len = want - original_owe;
      // If the amount we need to advance is greater than the SIDE_BUFFER_SIZE,
      // we need multiple this->read calls, but the total advance might not be
      // an exact multiple of SIDE_BUFFER_SIZE. Read that remainder amount
      // first, not last. For example, if advancing 260KiB with a 128KiB
      // SIDE_BUFFER_SIZE then read 4+128+128 instead of 128+128+4. This leaves
      // a full side buffer when we've finished advancing, maximizing later
      // requests' chances of side-buffer-as-cache hits.
      if (dst_len > SIDE_BUFFER_SIZE) {
        dst_len %= SIDE_BUFFER_SIZE;
        if (dst_len == 0) {
          dst_len = SIDE_BUFFER_SIZE;
        }
      }

      const ssize_t n = this->read(dst_ptr, dst_len, pathname);
      if (n < 0) {
        meta->index_within_archive = -1;
        meta->offset_within_entry = -1;
        meta->length = -1;
        meta->lru_priority = 0;
        return false;
      }

      meta->index_within_archive = this->index_within_archive;
      meta->offset_within_entry = original_owe;
      meta->length = n;
      meta->lru_priority = ++side_buffer_metadata::next_lru_priority;
    }

    return true;
  }

  // read copies from the archive entry's decompressed contents to the
  // destination buffer. It also advances the Reader's offset_within_entry.
  //
  // The path is used for log messages.
  ssize_t read(void* dst_ptr, size_t dst_len, const char* path) {
    const ssize_t n = archive_read_data(this->archive, dst_ptr, dst_len);
    if (n < 0) {
      Log(LOG_ERR,
          "Cannot read archive: ", archive_error_string(this->archive));
      return -EIO;
    }

    assert(n <= dst_len);
    this->offset_within_entry += n;
    return n;
  }
};

// Swaps fields of two Readers.
void swap(Reader& a, Reader& b) {
  std::swap(a.archive, b.archive);
  std::swap(a.archive_entry, b.archive_entry);
  std::swap(a.index_within_archive, b.index_within_archive);
  std::swap(a.offset_within_entry, b.offset_within_entry);
}

// Returns a Reader positioned at the start (offset == 0) of the given index'th
// entry of the archive.
std::unique_ptr<Reader> acquire_reader(int64_t want_index_within_archive) {
  assert(want_index_within_archive >= 0);

  int best_i = -1;
  int64_t best_index_within_archive = -1;
  int64_t best_offset_within_entry = -1;
  for (int i = 0; i < NUM_SAVED_READERS; i++) {
    const Reader* const sri = g_saved_readers[i].first.get();
    if (sri &&
        std::pair(best_index_within_archive, best_offset_within_entry) <
            std::pair(sri->index_within_archive, sri->offset_within_entry) &&
        std::pair(sri->index_within_archive, sri->offset_within_entry) <=
            std::pair(want_index_within_archive, int64_t(0))) {
      best_i = i;
      best_index_within_archive = sri->index_within_archive;
      best_offset_within_entry = sri->offset_within_entry;
    }
  }

  std::unique_ptr<Reader> r;
  if (best_i >= 0) {
    r = std::move(g_saved_readers[best_i].first);
    g_saved_readers[best_i].second = 0;
  } else {
    struct archive* const a = archive_read_new();
    if (!a) {
      Log(LOG_ERR, "Out of memory");
      return nullptr;
    }

    if (!password.empty()) {
      archive_read_add_passphrase(a, password.c_str());
    }

    archive_read_support_filter_all(a);
    archive_read_support_format_all(a);
    archive_read_support_format_raw(a);
    if (archive_read_open_filename(a, g_archive_realpath, 16384) !=
        ARCHIVE_OK) {
      Log(LOG_ERR, "Cannot read archive: ", archive_error_string(a));
      archive_read_free(a);
      return nullptr;
    }
    r = std::make_unique<Reader>(a);
  }

  if (!r->advance_index(want_index_within_archive)) {
    return nullptr;
  }

  return r;
}

// release_reader returns r to the reader cache.
void release_reader(std::unique_ptr<Reader> r) {
  int oldest_i = 0;
  uint64_t oldest_lru_priority = g_saved_readers[0].second;
  for (int i = 1; i < NUM_SAVED_READERS; i++) {
    if (oldest_lru_priority > g_saved_readers[i].second) {
      oldest_lru_priority = g_saved_readers[i].second;
      oldest_i = i;
    }
  }
  static uint64_t next_lru_priority = 0;
  g_saved_readers[oldest_i].first = std::move(r);
  g_saved_readers[oldest_i].second = ++next_lru_priority;
}

// ---- In-Memory Directory Tree

// normalize_pathname validates and returns e's pathname, prepending a leading
// "/" if it didn't already have one.
std::string normalize_pathname(struct archive_entry* e) {
  const char* const s =
      archive_entry_pathname_utf8(e) ?: archive_entry_pathname(e);
  if (!s) {
    Log(LOG_ERR, "entry has an empty path");
    return "";
  }

  // For 'raw' archives, libarchive defaults to "data" when the compression file
  // format doesn't contain the original file's name. For fuse-archive, we use
  // the archive filename's innername instead. Given an archive filename of
  // "/foo/bar.txt.bz2", the sole file within will be served as "bar.txt".
  if (g_archive_is_raw && !g_archive_innername.empty() &&
      std::string_view("data") == s) {
    return Path(g_archive_innername).Normalize();
  }

  return Path(s).Normalize();
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

void Attach(Node* const node) {
  assert(node);
  const auto [pos, ok] = g_nodes_by_path.try_emplace(node->path(), node);
  if (ok) {
    return;
  }

  // There is a name collision
  Log(LOG_DEBUG, *node, " conflicts with ", *pos->second);

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

    const auto [pos, ok] = g_nodes_by_path.try_emplace(node->path(), node);
    if (ok) {
      Log(LOG_DEBUG, "Resolved conflict for ", *node);
      return;
    }

    Log(LOG_DEBUG, *node, " conflicts with ", *pos->second);
    if (!i)
      i = &pos->second->collision_count;
  }
}

Node* CreateDir(std::string_view const path) {
  if (path == "/") {
    assert(g_root_node);
    assert(g_root_node->is_dir());
    return g_root_node;
  }

  const auto [parent_path, name] = Path(path).Split();
  Node* to_rename = nullptr;
  Node* parent = nullptr;

  Node*& node = g_nodes_by_path[std::string(path)];

  if (node) {
    if (node->is_dir())
      return node;

    // There is an existing node with the given name, but it's not a
    // directory.
    Log(LOG_DEBUG, "Found conflicting ", *node, " while creating Dir ",
        Path(path));
    parent = node->parent;

    // Remove it from g_nodes_by_path, in order to insert it again later with a
    // different name.
    to_rename = node;
    node = nullptr;
  } else {
    parent = CreateDir(parent_path);
  }

  assert(parent);
  assert(!node);

  // Create the Directory node.
  node =
      new Node{.name = std::string(name), .mode = S_IFDIR | 0777, .nlink = 1};
  parent->add_child(node);
  g_block_count += 1;
  assert(node->path() == path);

  if (to_rename) {
    Attach(to_rename);
  }

  return node;
}

void insert_leaf_node(std::string&& path,
                      std::string&& symlink,
                      int64_t const index_within_archive,
                      int64_t const size,
                      time_t const mtime,
                      mode_t mode) {
  const auto [parent_path, name] = Path(path).Split();

  Node* const parent = CreateDir(parent_path);
  assert(parent);
  assert(parent->is_dir());

  const bool executable = (mode & 0111) != 0;
  mode = !symlink.empty() ? (S_IFLNK | 0666)
                          : (S_IFREG | 0666 | (executable ? 0111 : 0));

  Node* const n = new Node{.name = std::string(name),
                           .symlink = std::move(symlink),
                           .mode = mode,
                           .index_within_archive = index_within_archive,
                           .size = size,
                           .mtime = mtime};
  parent->add_child(n);
  g_block_count += n->get_block_count();
  g_block_count += 1;

  // Add to g_nodes_by_path.
  Attach(n);

  // Add to g_nodes_by_index.
  assert(g_nodes_by_index.size() <= index_within_archive);
  g_nodes_by_index.resize(index_within_archive);
  g_nodes_by_index.push_back(n);
}

void insert_leaf(struct archive* a,
                 struct archive_entry* e,
                 int64_t index_within_archive) {
  const mode_t mode = archive_entry_mode(e);
  const FileType ft = GetFileType(mode);

  std::string path = normalize_pathname(e);
  if (path.empty()) {
    Log(LOG_DEBUG, "Skipped ", ft, " with invalid path ",
        Path(archive_entry_pathname_utf8(e)));
    return;
  }

  std::string symlink;

  switch (ft) {
    case FileType::Directory:
      CreateDir(path);
      return;

    case FileType::CharDevice:
    case FileType::BlockDevice:
    case FileType::Fifo:
    case FileType::Socket:
      Log(LOG_DEBUG, "Skipped ", ft, " ", Path(path));
      return;

    case FileType::Symlink:
      if (const char* const s =
              archive_entry_symlink_utf8(e) ?: archive_entry_symlink(e)) {
        symlink = std::string(s);
      }

      if (symlink.empty()) {
        Log(LOG_ERR, "Skipped empty link ", Path(path));
        return;
      }

    default:
      break;
  }

  int64_t size = archive_entry_size(e);
  // 'Raw' archives don't always explicitly record the decompressed size. We'll
  // have to decompress it to find out. Some 'cooked' archives also don't
  // explicitly record this (at the time archive_read_next_header returns). See
  // https://github.com/libarchive/libarchive/issues/1764
  if (!archive_entry_size_is_set(e)) {
    Log(LOG_INFO, "Extracting ", Path(path));

    size = 0;
    while (const ssize_t n = archive_read_data(
               a, g_side_buffer_data[SIDE_BUFFER_INDEX_DECOMPRESSED],
               SIDE_BUFFER_SIZE)) {
      if (n < 0) {
        Log(LOG_ERR, "Cannot extract ", Path(path), ": ",
            archive_error_string(a));
        throw ExitCode::INVALID_ARCHIVE_CONTENTS;
      }

      assert(n <= SIDE_BUFFER_SIZE);
      size += n;
    }
  }

  insert_leaf_node(std::move(path), std::move(symlink), index_within_archive,
                   size, archive_entry_mtime(e), mode);
}

void build_tree() {
  assert(g_initialize_index_within_archive >= 0);
  bool first = true;
  while (true) {
    if (first) {
      // The entry was already read by pre_initialize.
      first = false;
    } else {
      int status = archive_read_next_header(g_initialize_archive,
                                            &g_initialize_archive_entry);
      g_initialize_index_within_archive++;
      if (status == ARCHIVE_EOF) {
        break;
      }

      if (status == ARCHIVE_WARN) {
        Log(LOG_WARNING, archive_error_string(g_initialize_archive));
      } else if (status != ARCHIVE_OK) {
        Log(LOG_ERR,
            "Invalid archive: ", archive_error_string(g_initialize_archive));
        throw ExitCode::INVALID_ARCHIVE_CONTENTS;
      }
    }

    insert_leaf(g_initialize_archive, g_initialize_archive_entry,
                g_initialize_index_within_archive);
  }
}

// ---- Lazy Initialization

// This section (pre_initialize and post_initialize_etc) are the "two parts"
// described in the "Building is split into two parts" comment above.

void pre_initialize() {
  if (g_archive_filename.empty()) {
    Log(LOG_ERR, "Missing archive_filename argument");
    throw ExitCode::GENERIC_FAILURE;
  }

  g_archive_realpath = realpath(g_archive_filename.c_str(), nullptr);
  if (!g_archive_realpath) {
    Log(LOG_ERR, "Cannot get absolute path of ", Path(g_archive_filename), ": ",
        strerror(errno));
    throw ExitCode::CANNOT_OPEN_ARCHIVE;
  }

  g_archive_fd = open(g_archive_realpath, O_RDONLY);
  if (g_archive_fd < 0) {
    Log(LOG_ERR, "Cannot open ", Path(g_archive_filename), ": ",
        strerror(errno));
    throw ExitCode::CANNOT_OPEN_ARCHIVE;
  }

  struct stat z;
  if (fstat(g_archive_fd, &z) != 0) {
    Log(LOG_ERR, "Cannot stat ", Path(g_archive_filename), ": ",
        strerror(errno));
    throw ExitCode::CANNOT_OPEN_ARCHIVE;
  }
  g_archive_file_size = z.st_size;

  g_initialize_archive = archive_read_new();
  if (!g_initialize_archive) {
    Log(LOG_ERR, "Out of memory");
    throw std::bad_alloc();
  }

  archive_read_set_passphrase_callback(g_initialize_archive, nullptr,
                                       &read_password_from_stdin);
  archive_read_support_filter_all(g_initialize_archive);
  archive_read_support_format_all(g_initialize_archive);
  archive_read_support_format_raw(g_initialize_archive);
  if (my_archive_read_open(g_initialize_archive) != ARCHIVE_OK) {
    Log(LOG_ERR,
        "Cannot open archive: ", archive_error_string(g_initialize_archive));
    throw ExitCode::GENERIC_FAILURE;
  }

  while (true) {
    int status = archive_read_next_header(g_initialize_archive,
                                          &g_initialize_archive_entry);
    g_initialize_index_within_archive++;
    if (status == ARCHIVE_WARN) {
      Log(LOG_WARNING, archive_error_string(g_initialize_archive));
    } else if (status != ARCHIVE_OK) {
      if (status != ARCHIVE_EOF) {
        Log(LOG_ERR,
            "Invalid archive: ", archive_error_string(g_initialize_archive));
      }
      archive_read_free(g_initialize_archive);
      g_initialize_archive = nullptr;
      g_initialize_archive_entry = nullptr;
      g_initialize_index_within_archive = -1;
      if (status != ARCHIVE_EOF) {
        throw ExitCode::INVALID_ARCHIVE_HEADER;
      }
      // Building the tree for an empty archive is trivial.
      return;
    }

    if (S_ISDIR(archive_entry_mode(g_initialize_archive_entry))) {
      continue;
    }
    break;
  }

  // For 'raw' archives, check that at least one of the compression filters
  // (e.g. bzip2, gzip) actually triggered. We don't want to mount arbitrary
  // data (e.g. foo.jpeg).
  if (archive_format(g_initialize_archive) == ARCHIVE_FORMAT_RAW) {
    g_archive_is_raw = true;
    const int n = archive_filter_count(g_initialize_archive);
    for (int i = 0; true; i++) {
      if (i == n) {
        archive_read_free(g_initialize_archive);
        g_initialize_archive = nullptr;
        g_initialize_archive_entry = nullptr;
        g_initialize_index_within_archive = -1;
        Log(LOG_ERR, "Invalid raw archive");
        throw ExitCode::INVALID_RAW_ARCHIVE;
      }

      if (archive_filter_code(g_initialize_archive, i) != ARCHIVE_FILTER_NONE) {
        break;
      }
    }
  } else {
    // Otherwise, reading the first byte of the first non-directory entry will
    // reveal whether we also need a passphrase.
    ssize_t n = archive_read_data(
        g_initialize_archive,
        g_side_buffer_data[SIDE_BUFFER_INDEX_DECOMPRESSED], 1);
    if (n < 0) {
      const char* const e = archive_error_string(g_initialize_archive);
      Log(LOG_ERR, e);
      throw determine_passphrase_exit_code(e);
    }
  }
}

void post_initialize_sync() {
  build_tree();
  archive_read_free(g_initialize_archive);
  g_initialize_archive = nullptr;
  g_initialize_archive_entry = nullptr;
  g_initialize_index_within_archive = -1;
  if (g_archive_fd >= 0) {
    close(g_archive_fd);
    g_archive_fd = -1;
  }

  if (g_displayed_progress) {
    if (isatty(STDERR_FILENO)) {
      fprintf(stderr, "\e[F\e[K");
      fflush(stderr);
    } else {
      Log(LOG_INFO, "Loaded 100%");
    }
  }
}

// ---- FUSE Callbacks

int my_getattr(const char* const path, struct stat* const z) {
  const auto it = g_nodes_by_path.find(path);
  if (it == g_nodes_by_path.end()) {
    return -ENOENT;
  }

  assert(z);
  *z = it->second->get_stat();
  return 0;
}

int my_readlink(const char* const path,
                char* const dst_ptr,
                size_t const dst_len) {
  const auto it = g_nodes_by_path.find(path);
  if (it == g_nodes_by_path.end()) {
    return -ENOENT;
  }

  const Node* const n = it->second;
  assert(n);
  if (n->symlink.empty() || dst_len == 0) {
    return -ENOLINK;
  }

  snprintf(dst_ptr, dst_len, "%s", n->symlink.c_str());
  return 0;
}

int my_open(const char* const path, fuse_file_info* const ffi) {
  const auto it = g_nodes_by_path.find(path);
  if (it == g_nodes_by_path.end()) {
    return -ENOENT;
  }

  const Node* const n = it->second;
  assert(n);
  if (n->is_dir()) {
    return -EISDIR;
  }

  if (n->index_within_archive < 0 || !ffi) {
    return -EIO;
  }

  if ((ffi->flags & O_ACCMODE) != O_RDONLY) {
    return -EACCES;
  }

  std::unique_ptr<Reader> ur = acquire_reader(n->index_within_archive);
  if (!ur) {
    return -EIO;
  }

  ffi->keep_cache = 1;

  static_assert(sizeof(ffi->fh) >= sizeof(Reader*));
  ffi->fh = reinterpret_cast<uintptr_t>(ur.release());
  return 0;
}

int my_read(const char* const path,
            char* const dst_ptr,
            size_t dst_len,
            off_t const offset,
            fuse_file_info* const ffi) {
  if (offset < 0 || dst_len > INT_MAX) {
    return -EINVAL;
  }

  Reader* const r = reinterpret_cast<Reader*>(ffi->fh);
  if (!r || !r->archive || !r->archive_entry) {
    return -EIO;
  }

  const uint64_t i = r->index_within_archive;
  if (i >= g_nodes_by_index.size()) {
    return -EIO;
  }

  const Node* const n = g_nodes_by_index[i];
  if (!n) {
    return -EIO;
  }

  const int64_t size = n->size;
  if (size < 0) {
    return -EIO;
  }

  if (size <= offset) {
    return 0;
  }

  const uint64_t remaining = size - offset;
  if (dst_len > remaining) {
    dst_len = remaining;
  }

  if (dst_len == 0) {
    return 0;
  }

  if (read_from_side_buffer(r->index_within_archive, dst_ptr, dst_len,
                            offset)) {
    return dst_len;
  }

  // libarchive is designed for streaming access, not random access. If we
  // need to seek backwards, there's more work to do.
  if (offset < r->offset_within_entry) {
    // Acquire a new Reader, swap it with r and release the new Reader. We
    // swap (modify r in-place) instead of updating ffi->fh to point to the
    // new Reader, because libfuse ignores any changes to the ffi->fh value
    // after this function returns (this function is not an 'open' callback).
    std::unique_ptr<Reader> ur = acquire_reader(r->index_within_archive);
    if (!ur || !ur->archive || !ur->archive_entry) {
      return -EIO;
    }
    swap(*r, *ur);
    release_reader(std::move(ur));
  }

  if (!r->advance_offset(offset, path)) {
    return -EIO;
  }

  return r->read(dst_ptr, dst_len, path);
}

int my_release(const char*, fuse_file_info* const ffi) {
  Reader* const r = reinterpret_cast<Reader*>(ffi->fh);
  if (!r) {
    return -EIO;
  }
  release_reader(std::unique_ptr<Reader>(r));
  return 0;
}

int my_readdir(const char* path,
               void* const buf,
               fuse_fill_dir_t const filler,
               off_t,
               fuse_file_info*) {
  const auto it = g_nodes_by_path.find(path);
  if (it == g_nodes_by_path.end()) {
    return -ENOENT;
  }

  const Node* const n = it->second;
  if (!n->is_dir()) {
    return -ENOTDIR;
  }

  if (filler(buf, ".", nullptr, 0) || filler(buf, "..", nullptr, 0)) {
    return -ENOMEM;
  }

  for (const Node* p = n->first_child; p; p = p->next_sibling) {
    const struct stat z = p->get_stat();
    if (filler(buf, p->name.c_str(), &z, 0)) {
      return -ENOMEM;
    }
  }

  return 0;
}

int my_statfs(const char*, struct statvfs* const st) {
  assert(st);
  st->f_bsize = block_size;
  st->f_frsize = block_size;
  st->f_blocks = g_block_count;
  st->f_bfree = 0;
  st->f_bavail = 0;
  st->f_files = g_nodes_by_path.size();
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
      switch (++g_options.arg_count) {
        case 1:
          g_archive_filename = arg;
          g_archive_innername =
              Path(g_archive_filename).Split().second.WithoutFinalExtension();
          return DISCARD;

        case 2:
          g_mount_point = arg;
          return DISCARD;

        default:
          fprintf(stderr,
                  "%s: only two arguments allowed: filename and mountpoint\n",
                  PROGRAM_NAME);
          return ERROR;
      }

    case KEY_HELP:
      g_options.help = true;
      return DISCARD;

    case KEY_VERSION:
      g_options.version = true;
      return DISCARD;

    case KEY_QUIET:
      setlogmask(LOG_UPTO(LOG_ERR));
      g_options.quiet = true;
      return DISCARD;

    case KEY_VERBOSE:
      setlogmask(LOG_UPTO(LOG_DEBUG));
      return DISCARD;

    case KEY_REDACT:
      g_options.redact = true;
      return DISCARD;
  }

  return KEEP;
}

void ensure_utf_8_encoding() {
  // libarchive (especially for reading 7z) has locale-dependent behavior.
  // Non-ASCII pathnames can trigger "Pathname cannot be converted from
  // UTF-16LE to current locale" warnings from archive_read_next_header and
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

  Log(LOG_ERR, "Cannot ensure UTF-8 encoding");
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

}  // namespace

int main(int const argc, char** const argv) try {
  openlog(PROGRAM_NAME, LOG_PERROR, LOG_USER);
  setlogmask(LOG_UPTO(LOG_INFO));

  // Initialize side buffers as invalid.
  for (int i = 0; i < NUM_SIDE_BUFFERS; i++) {
    g_side_buffer_metadata[i].index_within_archive = -1;
    g_side_buffer_metadata[i].offset_within_entry = -1;
    g_side_buffer_metadata[i].length = -1;
    g_side_buffer_metadata[i].lru_priority = 0;
  }

  ensure_utf_8_encoding();

  fuse_args args = FUSE_ARGS_INIT(argc, argv);

  if (fuse_opt_parse(&args, nullptr, g_fuse_opts, &my_opt_proc) < 0) {
    Log(LOG_ERR, "Cannot parse command line arguments");
    throw ExitCode::GENERIC_FAILURE;
  }

  // Force single-threading. It's simpler.
  //
  // For example, there may be complications about acquiring an unused side
  // buffer if NUM_SIDE_BUFFERS is less than the number of threads.
  fuse_opt_add_arg(&args, "-s");

  // Mount read-only.
  fuse_opt_add_arg(&args, "-o");
  fuse_opt_add_arg(&args, "ro");

  if (g_options.help) {
    fprintf(stderr,
            R"(usage: %s [options] <archive_file> [mount_point]

general options:
    -o opt,[opt...]        mount options
    -h   --help            print help
    -V   --version         print version

%s options:
    -q   --quiet           do not print progress messages
    -v   --verbose         print more log messages
         --redact          redact pathnames from log messages
         -o redact         ditto

)",
            PROGRAM_NAME, PROGRAM_NAME);
    fuse_opt_add_arg(&args, "-ho");  // I think ho means "help output".
    fuse_main(args.argc, args.argv, &my_operations, nullptr);
    return EXIT_SUCCESS;
  }

  if (g_options.version) {
    fprintf(stderr, PROGRAM_NAME " version: %s\n", FUSE_ARCHIVE_VERSION);
    fuse_opt_add_arg(&args, "--version");
    fuse_main(args.argc, args.argv, &my_operations, nullptr);
    return EXIT_SUCCESS;
  }

  // Determine where the mount point should be.
  std::string mount_point_parent, mount_point_basename;
  const bool mount_point_specified_by_user = !g_mount_point.empty();
  if (!mount_point_specified_by_user) {
    g_mount_point =
        Path(g_archive_filename).WithoutTrailingSeparator().WithoutExtension();
  }

  std::tie(mount_point_parent, mount_point_basename) =
      Path(g_mount_point).WithoutTrailingSeparator().Split();

  if (mount_point_basename.empty()) {
    Log(LOG_ERR, "Cannot use ", Path(g_mount_point), " as a mount point");
    throw ExitCode::CANNOT_CREATE_MOUNT_POINT;
  }

  // Get a file descriptor to the parent directory of the mount point.
  const int mount_point_parent_fd =
      open(!mount_point_parent.empty() ? mount_point_parent.c_str() : ".",
           O_DIRECTORY | O_PATH);
  if (mount_point_parent_fd < 0) {
    Log(LOG_ERR, "Cannot access directory ", Path(mount_point_parent), ": ",
        strerror(errno));
    throw ExitCode::CANNOT_CREATE_MOUNT_POINT;
  }

  Log(LOG_DEBUG, "Opened directory ", Path(mount_point_parent));

  // Read archive and build tree.
  g_nodes_by_path[g_root_node->path()] = g_root_node;
  pre_initialize();
  post_initialize_sync();

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
        Log(LOG_INFO, "Created mount point ", Path(g_mount_point));

        // Set the cleanup function that will eventually remove this mount
        // point.
        cleanup.fn = [mount_point_parent_fd, mount_point_basename]() {
          if (unlinkat(mount_point_parent_fd, mount_point_basename.c_str(),
                       AT_REMOVEDIR) == 0) {
            Log(LOG_INFO, "Removed mount point ", Path(g_mount_point));
          } else {
            Log(LOG_ERR, "Cannot remove mount point ", Path(g_mount_point),
                ": ", strerror(errno));
          }
        };

        break;
      }

      if (errno != EEXIST) {
        Log(LOG_ERR, "Cannot create mount point ", Path(g_mount_point), ": ",
            strerror(errno));
        throw ExitCode::CANNOT_CREATE_MOUNT_POINT;
      }

      if (mount_point_specified_by_user) {
        Log(LOG_INFO, "Using existing mount point ", Path(g_mount_point));
        break;
      }

      Log(LOG_DEBUG, "Mount point ", Path(g_mount_point), " already exists");
      mount_point_basename.resize(n);
      mount_point_basename += StrCat(" (", ++i, ")");
    }
  }

  // The mount point is in place.
  fuse_opt_add_arg(&args, g_mount_point.c_str());

  return fuse_main(args.argc, args.argv, &my_operations, nullptr);
} catch (const ExitCode e) {
  return static_cast<int>(e);
} catch (const std::exception& e) {
  Log(LOG_ERR, e.what());
  return EXIT_FAILURE;
}
