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
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <climits>
#include <memory>
#include <string>
#include <unordered_map>

// fuse_file_info.fh is a uint64_t. Check that it can hold a pointer.
#if UINTPTR_MAX > UINT64_MAX
#error "fuse-archive requires that casting a uintptr_t to uint64_t is lossless"
#endif

#define TRY(operation)               \
  do {                               \
    int try_status_code = operation; \
    if (try_status_code) {           \
      return try_status_code;        \
    }                                \
  } while (false)

// ---- Compile-time Configuration

#ifndef BLOCK_SIZE
#define BLOCK_SIZE 16384
#endif

#ifndef NUM_SAVED_READERS
#define NUM_SAVED_READERS 8
#endif

// ---- Globals

enum {
  MY_KEY_IGNORE = 100,
  MY_KEY_HELP = 101,
  MY_KEY_REDACT = 102,
};

static struct fuse_opt g_opts[] = {
    FUSE_OPT_KEY("-h", MY_KEY_HELP),          //
    FUSE_OPT_KEY("--help", MY_KEY_HELP),      //
    FUSE_OPT_KEY("--redact", MY_KEY_REDACT),  //
    // The remaining options are listed for e.g. "-o formatraw" command line
    // compatibility with the https://github.com/cybernoid/archivemount program
    // but are otherwise ignored. For example, this program detects 'raw'
    // archives automatically and only supports read-only, not read-write.
    FUSE_OPT_KEY("formatraw", MY_KEY_IGNORE),  //
    FUSE_OPT_KEY("nobackup", MY_KEY_IGNORE),   //
    FUSE_OPT_KEY("nosave", MY_KEY_IGNORE),     //
    FUSE_OPT_KEY("readonly", MY_KEY_IGNORE),   //
    FUSE_OPT_END,
};
static bool g_key_help = false;
static bool g_key_redact = false;

// g_archive_filename is the command line argument naming the archive file.
static const char* g_archive_filename = NULL;

// g_proc_self_fd_filename holds the "/proc/self/fd/%d" filename of the file
// descriptor for the archive file. The command line argument may give a
// relative filename (one that doesn't start with a slash) and the fuse_main
// function may change the current working directory, so subsequent
// archive_read_open_filename calls use this "/proc/self/fd/%d" absolute
// filename instead. g_archive_filename is still used for logging.
static char g_proc_self_fd_filename[64] = {};

// g_archive_is_raw is whether the archive file is 'cooked' or 'raw'.
//
// We support 'cooked' archive files (e.g. foo.tar.gz or foo.zip) but also what
// libarchive calls 'raw' files (e.g. foo.gz), which are compressed but not
// explicitly an archive (a collection of files). libarchive can still present
// it as an implicit archive containing 1 file.
static bool g_archive_is_raw = false;

// g_raw_decompressed_size is the implicit size of the sole archive entry, for
// 'raw' archives (which don't always explicitly record the decompressed size).
static int64_t g_raw_decompressed_size = 0;

// g_uid and g_gid are the user/group IDs for the files we serve. They're the
// same as the current uid/gid.
static uid_t g_uid = 0;
static gid_t g_gid = 0;

// We serve ls and stat requests from an in-memory directory tree of nodes.
// Building that tree is one of the first things that we do.
//
// Building is split into two parts and the bulk of it is done in the second
// part, lazily, so that the main function can call fuse_main (to bind the
// mountpoint and daemonize) as fast as possible (although the main function
// still does a preliminary check that the archive_filename command line
// argument actually names an existing file that looks like a valid archive).
//
// These global variables connect those two parts.
static int g_initialize_status_code = 0;
static struct archive* g_initialize_archive = nullptr;
static struct archive_entry* g_initialize_archive_entry = nullptr;

// These global variables are the in-memory directory tree of nodes.
//
// g_root_node being non-nullptr means that initialization is complete.
static std::unordered_map<std::string, struct node*> g_nodes;
static struct node* g_root_node = nullptr;

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
//    (60 + 40 + 10) in total. The reader for "/bar" can be re-used for "/baz".
//
// Re-use eligibility is based on the archive entries' sequential numerical
// indexes within the archive, not on their string pathnames.
//
// When copying all of the files out of an archive (e.g. "cp -r" from the
// command line) and the files are accessed in the natural order, caching
// readers means that the overall time can be linear instead of quadratic.
//
// Each array element is a pair. The first half of the pair is a unique_ptr for
// the reader. The second half of the pair is a uint64_t LRU priority value.
// Higher/lower values are more/less recently used and the release_reader
// function evicts the array element with the lowest LRU priority value.
static std::pair<std::unique_ptr<struct reader>, uint64_t>
    g_saved_readers[NUM_SAVED_READERS] = {};

// ---- Logging

// redact replaces s with a placeholder string when the "--redact" command line
// option was given. This may prevent Personally Identifiable Information (PII)
// such as archive filenames or archive entry pathnames from being logged.
static const char*  //
redact(const char* s) {
  return g_key_redact ? "[REDACTED]" : s;
}

// ---- Reader

// reader bundles libarchive concepts (an archive and an archive entry) and
// other state to point to a particular offset (in decompressed space) of a
// particular archive entry (identified by its index) in an archive.
//
// A reader is backed by its own archive_read_open_filename call, managed by
// libarchive, so each can be positioned independently.
struct reader {
  struct archive* archive;
  struct archive_entry* archive_entry;
  int64_t index_within_archive;
  int64_t offset_within_entry;
  std::unique_ptr<char[]> discard_buffer;

  reader(struct archive* _archive)
      : archive(_archive),
        archive_entry(nullptr),
        index_within_archive(-1),
        offset_within_entry(0),
        discard_buffer(nullptr) {}

  ~reader() {
    if (this->archive) {
      archive_read_free(this->archive);
    }
  }

  // advance_index walks forward until positioned at the want'th index. An
  // index identifies an archive entry. If this reader wasn't already
  // positioned at that index, it also resets the reader's offset to zero.
  //
  // It returns success (true) or failure (false).
  bool advance_index(int64_t want) {
    if (!this->archive) {
      return false;
    }
    while (this->index_within_archive < want) {
      int status =
          archive_read_next_header(this->archive, &this->archive_entry);
      if (status == ARCHIVE_EOF) {
        fprintf(stderr, "fuse-archive: inconsistent archive: %s\n",
                redact(g_archive_filename));
        return false;
      } else if ((status != ARCHIVE_OK) && (status != ARCHIVE_WARN)) {
        fprintf(stderr, "fuse-archive: invalid archive: %s\n",
                redact(g_archive_filename));
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
    while (want > this->offset_within_entry) {
      static constexpr int64_t N = 4096;
      if (!this->discard_buffer) {
        this->discard_buffer = std::unique_ptr<char[]>(new char[N]);
        if (!this->discard_buffer) {
          return false;
        }
      }
      char* dst_ptr = this->discard_buffer.get();

      int64_t dst_len = want - this->offset_within_entry;
      if (dst_len > N) {
        dst_len = N;
      }

      if (this->read(dst_ptr, dst_len, pathname) < 0) {
        return false;
      }
    }
    return true;
  }

  // read copies from the archive entry's decompressed contents to the
  // destination buffer. It also advances the reader's offset_within_entry.
  //
  // The pathname is used for log messages.
  ssize_t read(void* dst_ptr, size_t dst_len, const char* pathname) {
    ssize_t n = archive_read_data(this->archive, dst_ptr, dst_len);
    if (n < 0) {
      fprintf(stderr, "fuse-archive: could not serve %s from %s: %s\n",
              redact(pathname), redact(g_archive_filename),
              archive_error_string(this->archive));
      return -EIO;
    } else if (static_cast<size_t>(n) > dst_len) {
      fprintf(stderr, "fuse-archive: too much data serving %s from %s\n",
              redact(pathname), redact(g_archive_filename));
      // Something has gone wrong, possibly a buffer overflow, so exit.
      exit(1);
    }
    this->offset_within_entry += n;
    return n;
  }

  // swap_libarchive_state swaps some fields with another reader.
  void swap_libarchive_state(struct reader* that) {
    std::swap(this->archive, that->archive);
    std::swap(this->archive_entry, that->archive_entry);
    std::swap(this->index_within_archive, that->index_within_archive);
    std::swap(this->offset_within_entry, that->offset_within_entry);
    // Ignore discard_buffer. It's not part of libarchive state.
  }
};

// compare does a lexicographic comparison of the pairs (i0, o0) and (i1, o1).
static int  //
compare(int64_t index_within_archive0,
        int64_t offset_within_entry0,
        int64_t index_within_archive1,
        int64_t offset_within_entry1) {
  if (index_within_archive0 < index_within_archive1) {
    return -1;
  } else if (index_within_archive0 > index_within_archive1) {
    return +1;
  } else if (offset_within_entry0 < offset_within_entry1) {
    return -1;
  } else if (offset_within_entry0 > offset_within_entry1) {
    return +1;
  }
  return 0;
}

// acquire_reader returns a reader positioned at the start (offset == 0) of the
// given index'th entry of the archive.
static std::unique_ptr<struct reader>  //
acquire_reader(int64_t want_index_within_archive) {
  if (want_index_within_archive < 0) {
    fprintf(stderr, "fuse-archive: negative index_within_archive\n");
    return nullptr;
  }

  int best_i = -1;
  int64_t best_index_within_archive = -1;
  int64_t best_offset_within_entry = -1;
  for (int i = 0; i < NUM_SAVED_READERS; i++) {
    struct reader* sri = g_saved_readers[i].first.get();
    if (sri &&
        (compare(best_index_within_archive, best_offset_within_entry,
                 sri->index_within_archive, sri->offset_within_entry) < 0) &&
        (compare(sri->index_within_archive, sri->offset_within_entry,
                 want_index_within_archive, 0) <= 0)) {
      best_i = i;
      best_index_within_archive = sri->index_within_archive;
      best_offset_within_entry = sri->offset_within_entry;
    }
  }

  std::unique_ptr<struct reader> r;
  if (best_i >= 0) {
    r = std::move(g_saved_readers[best_i].first);
    g_saved_readers[best_i].second = 0;
  } else {
    struct archive* a = archive_read_new();
    if (!a) {
      fprintf(stderr, "fuse-archive: out of memory\n");
      return nullptr;
    }
    archive_read_support_filter_all(a);
    archive_read_support_format_all(a);
    archive_read_support_format_raw(a);
    if (archive_read_open_filename(a, g_proc_self_fd_filename, BLOCK_SIZE) !=
        ARCHIVE_OK) {
      archive_read_free(a);
      fprintf(stderr, "fuse-archive: could not open %s\n",
              redact(g_archive_filename));
      return nullptr;
    }
    r = std::make_unique<struct reader>(a);
  }

  if (!r->advance_index(want_index_within_archive)) {
    return nullptr;
  }
  return r;
}

// release_reader returns r to the reader cache.
static void  //
release_reader(std::unique_ptr<struct reader> r) {
  if (NUM_SAVED_READERS <= 0) {
    return;
  }
  int oldest_i = 0;
  uint64_t oldest_lru_priority = g_saved_readers[0].second;
  for (int i = 1; i < NUM_SAVED_READERS; i++) {
    if (oldest_lru_priority > g_saved_readers[i].second) {
      oldest_lru_priority = g_saved_readers[i].second;
      oldest_i = i;
    }
  }
  static uint64_t next_lru_priority = 0;
  next_lru_priority++;
  g_saved_readers[oldest_i].first = std::move(r);
  g_saved_readers[oldest_i].second = next_lru_priority;
}

// ---- In-Memory Directory Tree

struct node {
  std::string rel_name;  // Relative (not absolute) pathname.
  int64_t index_within_archive;
  int64_t size;
  time_t mtime;
  mode_t mode;

  node* last_child;
  node* first_child;
  node* next_sibling;

  node(std::string&& _rel_name,
       int64_t _index_within_archive,
       int64_t _size,
       time_t _mtime,
       mode_t _mode)
      : rel_name(_rel_name),
        index_within_archive(_index_within_archive),
        size(_size),
        mtime(_mtime),
        mode(_mode),
        last_child(nullptr),
        first_child(nullptr),
        next_sibling(nullptr) {}

  void add_child(node* n) {
    if (this->last_child == nullptr) {
      this->last_child = n;
      this->first_child = n;
    } else {
      this->last_child->next_sibling = n;
      this->last_child = n;
    }
  }
};

// valid_pathname returns whether the C string p is neither "" or "/" and, when
// splitting on '/' into pathname fragments, no fragment is "", "." or ".."
// other than a possibly leading empty fragment when p starts with "/".
//
// When iterating over fragments, the p pointer does not move but the q and r
// pointers bracket each fragment:
//   "/an/example/pathname"
//    pq-r|      ||       |
//    p   q------r|       |
//    p           q-------r
static bool  //
valid_pathname(const char* p) {
  if (!p) {
    return false;
  }
  const char* q = p;
  if (*q == '/') {
    q++;
  }
  if (*q == 0) {
    return false;
  }
  while (true) {
    const char* r = q;
    while ((*r != 0) && (*r != '/')) {
      r++;
    }
    size_t len = r - q;
    if (len == 0) {
      return false;
    } else if ((len == 1) && (q[0] == '.')) {
      return false;
    } else if ((len == 2) && (q[0] == '.') && (q[1] == '.')) {
      return false;
    }
    if (*r == 0) {
      break;
    }
    q = r + 1;
  }
  return true;
}

// normalize_pathname validates and returns e's pathname, prepending a leading
// "/" if it didn't already have one.
static std::string  //
normalize_pathname(struct archive_entry* e) {
  const char* s = archive_entry_pathname_utf8(e);
  if (!s) {
    s = archive_entry_pathname(e);
    if (!s) {
      fprintf(stderr, "fuse-archive: archive entry in %s has empty pathname\n",
              redact(g_archive_filename));
      return "";
    }
  }
  if (!valid_pathname(s)) {
    fprintf(stderr,
            "fuse-archive: archive entry in %s has invalid pathname: %s\n",
            redact(g_archive_filename), redact(s));
    return "";
  }
  if (*s == '/') {
    return std::string(s);
  }
  return std::string("/") + std::string(s);
}

static int  //
insert_leaf_node(std::string&& pathname,
                 int64_t index_within_archive,
                 int64_t size,
                 time_t mtime,
                 mode_t mode) {
  if (g_nodes.find(pathname) != g_nodes.end()) {
    fprintf(stderr, "fuse-archive: duplicate pathname in %s: %s\n",
            redact(g_archive_filename), redact(pathname.c_str()));
    return -EIO;
  }
  node* parent = g_root_node;

  mode_t rwx = mode & 0777;
  mode_t rwx_r_bits = rwx & 0444;
  mode_t branch_mode = rwx | (rwx_r_bits >> 2) | S_IFDIR;
  mode_t leaf_mode = rwx | S_IFREG;

  // p, q and r point to pathname fragments per the valid_pathname comment.
  const char* p = pathname.c_str();
  if ((*p == 0) || (*p != '/')) {
    return 0;
  }
  const char* q = p + 1;
  while (true) {
    // A directory's mtime is the oldest of its leaves' mtimes.
    if (parent->mtime < mtime) {
      parent->mtime = mtime;
    }
    parent->mode |= branch_mode;

    const char* r = q;
    while ((*r != 0) && (*r != '/')) {
      r++;
    }
    std::string abs_pathname(p, r - p);
    std::string rel_pathname(q, r - q);
    if (*r == 0) {
      // Insert an explicit leaf node (a regular file).
      node* n = new node(std::move(rel_pathname), index_within_archive, size,
                         mtime, leaf_mode);
      parent->add_child(n);
      g_nodes.insert({std::move(abs_pathname), n});
      break;
    }
    q = r + 1;

    // Insert an implicit branch node (a directory).
    auto iter = g_nodes.find(abs_pathname);
    if (iter == g_nodes.end()) {
      node* n = new node(std::move(rel_pathname), -1, 0, mtime, branch_mode);
      parent->add_child(n);
      g_nodes.insert(iter, {std::move(abs_pathname), n});
      parent = n;
    } else if (!S_ISDIR(iter->second->mode)) {
      fprintf(
          stderr,
          "fuse-archive: simultaneous directory and regular file in %s: %s\n",
          redact(g_archive_filename), redact(abs_pathname.c_str()));
      return -EIO;
    } else {
      parent = iter->second;
    }
  }
  return 0;
}

static int  //
insert_leaf(struct archive* a,
            struct archive_entry* e,
            int64_t index_within_archive) {
  std::string pathname = normalize_pathname(e);
  if (pathname.empty()) {
    // normalize_pathname already printed a log message.
    return 0;
  } else if (!S_ISREG(archive_entry_mode(e))) {
    fprintf(stderr, "fuse-archive: irregular file in %s: %s\n",
            redact(g_archive_filename), redact(pathname.c_str()));
    return 0;
  }

  int64_t size = archive_entry_size(e);
  if (g_archive_is_raw && (size == 0)) {
    // 'Raw' archives don't always explicitly record the decompressed size.
    // We'll have to decompress it to find out.
    static char discard_buffer[65536];
    while (true) {
      ssize_t n = archive_read_data(a, discard_buffer, sizeof discard_buffer);
      if (n == 0) {
        break;
      } else if (n < 0) {
        fprintf(stderr, "fuse-archive: could not decompress %s: %s\n",
                redact(g_archive_filename), archive_error_string(a));
        return -EIO;
      } else if (static_cast<size_t>(n) > sizeof discard_buffer) {
        fprintf(stderr, "fuse-archive: too much data decompressing %s\n",
                redact(g_archive_filename));
        // Something has gone wrong, possibly a buffer overflow, so exit.
        exit(1);
      }
      size += n;
    }
    g_raw_decompressed_size = size;
  }

  return insert_leaf_node(std::move(pathname), index_within_archive, size,
                          archive_entry_mtime(e), archive_entry_mode(e));
}

static int  //
build_tree() {
  for (int64_t index_within_archive = 0; true; index_within_archive++) {
    if (index_within_archive == 0) {
      // No-op. The entry was already read by pre_initialize.
    } else {
      int status = archive_read_next_header(g_initialize_archive,
                                            &g_initialize_archive_entry);
      if (status == ARCHIVE_EOF) {
        break;
      } else if (status == ARCHIVE_WARN) {
        fprintf(stderr, "fuse-archive: libarchive warning for %s: %s\n",
                redact(g_archive_filename),
                archive_error_string(g_initialize_archive));
      } else if (status != ARCHIVE_OK) {
        fprintf(stderr, "fuse-archive: invalid archive: %s\n",
                redact(g_archive_filename));
        return -EIO;
      }
    }

    if (S_ISDIR(archive_entry_mode(g_initialize_archive_entry))) {
      continue;
    }

    TRY(insert_leaf(g_initialize_archive, g_initialize_archive_entry,
                    index_within_archive));
  }
  return 0;
}

// ---- Lazy Initialization

// This section (pre_initialize and post_initialize) are the "two parts"
// described in the "Building is split into two parts" comment above.

static void  //
insert_root_node() {
  static constexpr int64_t index_within_archive = -1;
  g_root_node = new node("", index_within_archive, 0, 0, S_IFDIR);
  g_nodes["/"] = g_root_node;
}

static int  //
pre_initialize() {
  if (!g_archive_filename) {
    fprintf(stderr, "fuse-archive: missing archive_filename argument\n");
    return 1;
  }

  // fd is the file descriptor for the command line archive_filename argument.
  // We never close this file. It's used to repeatedly re-open the file (with
  // an independent seek position) under the "/proc/self/fd/%d" name.
  int fd = open(g_archive_filename, O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "fuse-archive: could not open %s\n",
            redact(g_archive_filename));
    return 1;
  }
  sprintf(g_proc_self_fd_filename, "/proc/self/fd/%d", fd);

  g_initialize_archive = archive_read_new();
  if (!g_initialize_archive) {
    fprintf(stderr, "fuse-archive: out of memory\n");
    return 1;
  }
  archive_read_support_filter_all(g_initialize_archive);
  archive_read_support_format_all(g_initialize_archive);
  archive_read_support_format_raw(g_initialize_archive);
  if (archive_read_open_fd(g_initialize_archive, fd, BLOCK_SIZE) !=
      ARCHIVE_OK) {
    archive_read_free(g_initialize_archive);
    g_initialize_archive = nullptr;
    g_initialize_archive_entry = nullptr;
    fprintf(stderr, "fuse-archive: could not open %s\n",
            redact(g_archive_filename));
    return 1;
  }

  int status = archive_read_next_header(g_initialize_archive,
                                        &g_initialize_archive_entry);
  if (status == ARCHIVE_WARN) {
    fprintf(stderr, "fuse-archive: libarchive warning for %s: %s\n",
            redact(g_archive_filename),
            archive_error_string(g_initialize_archive));
  } else if (status != ARCHIVE_OK) {
    archive_read_free(g_initialize_archive);
    g_initialize_archive = nullptr;
    g_initialize_archive_entry = nullptr;
    if (status != ARCHIVE_EOF) {
      fprintf(stderr, "fuse-archive: invalid archive: %s\n",
              redact(g_archive_filename));
      return 1;
    }
    // Building the tree for an empty archive is trivial.
    insert_root_node();
    return 0;
  }

  // For 'raw' archives, check that at least one of the compression filters
  // (e.g. bzip2, gzip) actually triggered. We don't want to mount arbitrary
  // data (e.g. foo.jpeg).
  if (archive_format(g_initialize_archive) == ARCHIVE_FORMAT_RAW) {
    g_archive_is_raw = true;
    int n = archive_filter_count(g_initialize_archive);
    for (int i = 0; true; i++) {
      if (i == n) {
        archive_read_free(g_initialize_archive);
        g_initialize_archive = nullptr;
        g_initialize_archive_entry = nullptr;
        fprintf(stderr, "fuse-archive: invalid raw archive: %s\n",
                redact(g_archive_filename));
        return 1;
      } else if (archive_filter_code(g_initialize_archive, i) !=
                 ARCHIVE_FILTER_NONE) {
        break;
      }
    }
  }
  return 0;
}

static int  //
post_initialize() {
  if (g_initialize_status_code) {
    return g_initialize_status_code;
  } else if (g_root_node != nullptr) {
    return 0;
  }
  insert_root_node();
  g_initialize_status_code = build_tree();
  archive_read_free(g_initialize_archive);
  g_initialize_archive = nullptr;
  g_initialize_archive_entry = nullptr;
  return g_initialize_status_code;
}

// ---- FUSE Callbacks

static int  //
my_getattr(const char* pathname, struct stat* z) {
  TRY(post_initialize());
  auto iter = g_nodes.find(pathname);
  if (iter == g_nodes.end()) {
    return -ENOENT;
  }
  node* n = iter->second;
  memset(z, 0, sizeof(*z));
  z->st_mode = n->mode;
  z->st_nlink = 1;
  z->st_uid = g_uid;
  z->st_gid = g_gid;
  z->st_size = n->size;
  z->st_mtime = n->mtime;
  return 0;
}

static int  //
my_open(const char* pathname, struct fuse_file_info* ffi) {
  TRY(post_initialize());
  auto iter = g_nodes.find(pathname);
  if (iter == g_nodes.end()) {
    return -ENOENT;
  } else if (S_ISDIR(iter->second->mode)) {
    return -EISDIR;
  } else if ((iter->second->index_within_archive < 0) || !ffi) {
    return -EIO;
  } else if ((ffi->flags & O_ACCMODE) != O_RDONLY) {
    return -EACCES;
  }
  std::unique_ptr<struct reader> ur =
      acquire_reader(iter->second->index_within_archive);
  if (!ur) {
    return -EIO;
  }
  ffi->keep_cache = 1;
  ffi->fh = reinterpret_cast<uintptr_t>(ur.release());
  return 0;
}

static int  //
my_read(const char* pathname,
        char* dst_ptr,
        size_t dst_len,
        off_t offset,
        struct fuse_file_info* ffi) {
  TRY(post_initialize());
  if ((offset < 0) || (dst_len > INT_MAX)) {
    return -EINVAL;
  }
  struct reader* r = reinterpret_cast<struct reader*>(ffi->fh);
  if (!r || !r->archive || !r->archive_entry) {
    return -EIO;
  }

  // libarchive is designed for streaming access, not random access. If we
  // need to seek backwards, there's more work to do.
  if (offset < r->offset_within_entry) {
    // Acquire a new reader, swap it with r and release the new reader. We
    // swap (modify r in-place) instead of updating ffi->fh to point to the
    // new reader, because libfuse ignores any changes to the ffi->fh value
    // after this function returns (this function is not an 'open' callback).
    std::unique_ptr<struct reader> ur = acquire_reader(r->index_within_archive);
    if (!ur || !ur->archive || !ur->archive_entry) {
      return -EIO;
    }
    r->swap_libarchive_state(ur.get());
    release_reader(std::move(ur));
  }

  int64_t size = g_archive_is_raw ? g_raw_decompressed_size
                                  : archive_entry_size(r->archive_entry);
  if (size < 0) {
    return -EIO;
  } else if ((size <= offset) || (dst_len == 0)) {
    return 0;
  } else if (!r->advance_offset(offset, pathname)) {
    return -EIO;
  } else if (dst_len > static_cast<uint64_t>(size - offset)) {
    dst_len = static_cast<uint64_t>(size - offset);
  }
  return r->read(dst_ptr, dst_len, pathname);
}

static int  //
my_release(const char* pathname, struct fuse_file_info* ffi) {
  TRY(post_initialize());
  struct reader* r = reinterpret_cast<struct reader*>(ffi->fh);
  if (!r) {
    return -EIO;
  }
  release_reader(std::unique_ptr<struct reader>(r));
  return 0;
}

static int  //
my_readdir(const char* pathname,
           void* buf,
           fuse_fill_dir_t filler,
           off_t offset,
           struct fuse_file_info* ffi) {
  TRY(post_initialize());
  auto iter = g_nodes.find(pathname);
  if (iter == g_nodes.end()) {
    return -ENOENT;
  }
  node* n = iter->second;
  if (!S_ISDIR(n->mode)) {
    return -ENOTDIR;
  } else if (filler(buf, ".", NULL, 0) || filler(buf, "..", NULL, 0)) {
    return -ENOMEM;
  }
  for (n = n->first_child; n; n = n->next_sibling) {
    if (filler(buf, n->rel_name.c_str(), NULL, 0)) {
      return -ENOMEM;
    }
  }
  return 0;
}

static struct fuse_operations my_operations = {
    .getattr = my_getattr,
    .open = my_open,
    .read = my_read,
    .release = my_release,
    .readdir = my_readdir,
};

// ---- Main

static int  //
my_opt_proc(void* private_data,
            const char* arg,
            int key,
            struct fuse_args* out_args) {
  static constexpr int discard = 0;
  static constexpr int keep = 1;

  switch (key) {
    case FUSE_OPT_KEY_NONOPT:
      if (!g_archive_filename) {
        g_archive_filename = arg;
        return discard;
      }
      break;
    case MY_KEY_IGNORE:
      return discard;
    case MY_KEY_HELP:
      g_key_help = true;
      return discard;
    case MY_KEY_REDACT:
      g_key_redact = true;
      return discard;
  }
  return keep;
}

int  //
main(int argc, char** argv) {
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
  if ((argc <= 0) || !argv) {
    fprintf(stderr, "fuse-archive: missing command line arguments\n");
    return 1;
  } else if (fuse_opt_parse(&args, NULL, g_opts, &my_opt_proc) < 0) {
    fprintf(stderr, "fuse-archive: could not parse command line arguments\n");
    return 1;
  }

  // Force single-threading. It's simpler.
  fuse_opt_add_arg(&args, "-s");

  // Mount read-only.
  fuse_opt_add_arg(&args, "-o");
  fuse_opt_add_arg(&args, "ro");

  if (g_key_help) {
    g_initialize_status_code = -EIO;
    fprintf(stderr,
            "usage: %s archive_filename mountpoint [options]\n"
            "\n"
            "general options:\n"
            "    -o opt,[opt...]        mount options\n"
            "    -h   --help            print help\n"
            "    -V   --version         print version\n"
            "\n"
            "%s options:\n"
            "         --redact          redact pathnames from log messages\n"
            "\n",
            argv[0], argv[0]);
    fuse_opt_add_arg(&args, "-ho");  // I think ho means "help output".
  } else {
    TRY(pre_initialize());
    g_uid = getuid();
    g_gid = getgid();
  }
  return fuse_main(args.argc, args.argv, &my_operations, NULL);
}
