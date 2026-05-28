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

#include "lib/common.h"
#include "lib/file_descriptor.h"
#include "lib/fuse_ops.h"
#include "lib/hashed_string.h"
#include "lib/node.h"
#include "lib/path.h"
#include "lib/reader.h"
#include "lib/tree.h"
#include "lib/util.h"

#define PROGRAM_NAME "fuse-archive"
#define PROGRAM_VERSION "1.23"

// ---- Compile-time Configuration

namespace {

using namespace ::fuse_archive;

// ---- Context

struct Context {
  static_assert(sizeof(Cache) == sizeof(int));
  static_assert(sizeof(LogLevel) == sizeof(int));

  Options options;
  LogLevel log_level = LogLevel::INFO;
  int help = 0;
  int version = 0;
  int can_use_external_filters = 1;
  int unsafe_path = 0;
  std::vector<std::string> archives;
};

// ---- Globals

fuse_opt const g_fuse_opts[] = {
    {"--help", offsetof(Context, help), 1},
    {"-h", offsetof(Context, help), 1},
    {"--version", offsetof(Context, version), 1},
    {"-V", offsetof(Context, version), 1},
    {"--verbose", offsetof(Context, log_level), int(LogLevel::DEBUG)},
    {"verbose", offsetof(Context, log_level), int(LogLevel::DEBUG)},
    {"-v", offsetof(Context, log_level), int(LogLevel::DEBUG)},
    {"--quiet", offsetof(Context, log_level), int(LogLevel::ERROR)},
    {"quiet", offsetof(Context, log_level), int(LogLevel::ERROR)},
    {"-q", offsetof(Context, log_level), int(LogLevel::ERROR)},
    {"--redact", offsetof(Context, options.redact), 1},
    {"redact", offsetof(Context, options.redact), 1},
    {"force", offsetof(Context, options.force), 1},
    {"unsafe_path", offsetof(Context, unsafe_path), 1},
    {"precache", offsetof(Context, options.cache), int(Cache::Full)},
    {"lazycache", offsetof(Context, options.cache), int(Cache::Lazy)},
    {"nocache", offsetof(Context, options.cache), int(Cache::None)},
    {"memcache", offsetof(Context, options.memcache), 1},
    {"nomerge", offsetof(Context, options.merge), 0},
    {"notrim", offsetof(Context, options.trim), 0},
    {"nodirs", offsetof(Context, options.dirs), 0},
    {"nospecials", offsetof(Context, options.specials), 0},
    {"nosymlinks", offsetof(Context, options.symlinks), 0},
    {"noholes", offsetof(Context, options.holes), 0},
    {"nohardlinks", offsetof(Context, options.hardlinks), 0},
    {"noxattrs", offsetof(Context, options.xattrs), 0},
    {"nobidding", offsetof(Context, options.bidding), 0},
    {"noexternal", offsetof(Context, can_use_external_filters), 0},
    {"enforce_permissions", offsetof(Context, options.enforce_permissions), 1},
    {"default_permissions", offsetof(Context, options.enforce_permissions), 1},
#if FUSE_USE_VERSION >= 30
    {"direct_io", offsetof(Context, options.direct_io), 1},
#endif
    {"dmask=%o", offsetof(Context, options.dmask)},
    {"fmask=%o", offsetof(Context, options.fmask)},
    {"maxfilters=%d", offsetof(Context, options.max_filter_count)},
    FUSE_OPT_END,
};

// Path of the mount point.

// Processes one command line argument.
int ProcessArg(void* data, const char* const arg, int const key, fuse_args*) {
  assert(data);
  Context& ctx = *static_cast<Context*>(data);
  constexpr int KEEP = 1;
  constexpr int DISCARD = 0;

  switch (key) {
    case FUSE_OPT_KEY_NONOPT:
      ctx.archives.push_back(arg);
      return DISCARD;
  }

  return KEEP;
}

// Ensures that the default encoding is UTF-8.
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

// Guard that executes the given function upon destruction.
struct Cleanup {
  std::function<void()> fn;

  ~Cleanup() {
    if (fn) {
      fn();
    }
  }
};

// Formatter for numbers using thousand separators.
class NumPunct : public std::numpunct<char> {
 private:
  char do_thousands_sep() const override { return ','; }
  std::string do_grouping() const override { return "\3"; }
};

// Prints usage on standard output.
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
    -o unsafe_path         do not sanitize PATH for external programs
    -o maxfilters=N        max number of filters (default 1)
    -o precache            pre-emptive caching of uncompressed data (default)
    -o lazycache           incremental caching of uncompressed data
    -o nocache             no caching of uncompressed data
    -o memcache            caching in memory
    -o nomerge             don't merge multiple archives in the same directory
    -o notrim              don't trim the base of the tree
    -o nodirs              no directories
    -o nospecials          no special files (FIFOs, sockets, devices)
    -o nosymlinks          no symlinks
    -o noholes             no sparse files
    -o nohardlinks         no hard links
    -o noxattrs            no extended attributes
    -o nobidding           rely on file extension to detect archive format
    -o noexternal          do not use external programs for decompression
    -o enforce_permissions enforce standard UNIX permissions
    -o dmask=M             directory permission mask in octal (default 0022)
    -o fmask=M             file permission mask in octal (default 0022))"
#if FUSE_USE_VERSION >= 30
         R"(
    -o direct_io           use direct I/O)"
#endif
         "\n\n"
      << std::flush;
}

// Value to use for PATH when it should be empty or disabled. Using "/dev/null"
// ensures that any attempt to execute an external program via PATH will fail
// with ENOTDIR, avoiding unintended fallbacks to system defaults or the
// current directory.
static const char safe_empty_path[] = "/dev/null";

// Limits the PATH environment variable to a predefined set of safe system
// directories. This prevents the execution of untrusted external filters from
// non-standard locations while allowing those necessary for archive processing.
void SetSafePath() {
  std::string out;

  if (const char* const p = getenv("PATH")) {
    for (std::string_view in = p; !in.empty();) {
      // Split PATH by ':' and normalize each directory.
      size_t const i = in.find(':');
      std::string_view const dir =
          Path(in.substr(0, i)).WithoutTrailingSeparator();

      // Recognized safe system locations.
      static const std::unordered_set<std::string_view> safe_dirs = {
          "/usr/bin",          "/bin",           "/usr/local/bin",
#ifdef __APPLE__
          "/opt/homebrew/bin", "/opt/local/bin",
#endif
      };

      // Only keep directories that are in the safe list.
      if (safe_dirs.contains(dir)) {
        if (!out.empty()) {
          out += ':';
        }
        out += dir;
      }

      if (i == std::string_view::npos) {
        break;
      }

      in.remove_prefix(i + 1);
    }
  }

  if (out.empty()) {
    out = safe_empty_path;
  }

  LOG(DEBUG) << "Setting PATH to " << Path(out);
  if (setenv("PATH", out.c_str(), true) < 0) {
    PLOG(ERROR) << "Cannot set PATH to " << Path(out);
    throw ExitCode::GENERIC_FAILURE;
  }
}

}  // namespace

// Formats command line arguments.
std::ostream& operator<<(std::ostream& out, const fuse_args& args) {
  std::string_view sep;
  for (int i = 0; i < args.argc; ++i) {
    out << sep << std::quoted(args.argv[i]);
    sep = " ";
  }

  assert(!args.argv[args.argc]);
  return out;
}

// ---- Main

int main(int const argc, char** const argv) try {
  // Ensure that numbers in debug messages have thousands separators.
  // It makes big numbers much easier to read (eg sizes expressed in bytes).
  std::locale::global(std::locale(std::locale::classic(), new NumPunct));
  openlog(PROGRAM_NAME, LOG_PERROR, LOG_USER);
  SetLogLevel(LogLevel::INFO);

  EnsureUtf8();

  Tree* tree = nullptr;

  fuse_args args = FUSE_ARGS_INIT(argc, argv);

#ifdef __SANITIZE_ADDRESS__
  // When running with ASAN, clean up everything at exit so that we can verify
  // that no memory has leaked.
  Cleanup const global_cleanup_guard([&tree, &args] {
    Timer const timer;
    LOG(INFO) << "Cleaning up";
    delete tree;
    tree = nullptr;
    delete g_unique_strings;
    g_unique_strings = nullptr;
    fuse_opt_free_args(&args);
    LOG(INFO) << "Cleaned up in " << timer;
  });
#endif

  Context ctx;
  if (fuse_opt_parse(&args, &ctx, g_fuse_opts, &ProcessArg) < 0) {
    LOG(ERROR) << "Cannot parse command line arguments";
    throw ExitCode::GENERIC_FAILURE;
  }

  g_redact = ctx.options.redact;
  SetLogLevel(ctx.log_level);

  if (!ctx.options.dirs) {
    ctx.options.hardlinks = false;
  }

  const fuse_operations ops = GetFuseOperations();

  if (ctx.help) {
    PrintUsage();

#if FUSE_USE_VERSION >= 30
    // Forward --help to libfuse so that it can print its own help.
    fuse_opt_add_arg(&args, "--help");

    // Pass an empty program name to libfuse's help output so that it doesn't
    // print the "Usage: " line again.
    char empty_argv0[] = "";
    char* const old_argv0 = args.argv[0];
    args.argv[0] = empty_argv0;

    fuse_main(args.argc, args.argv, &ops, tree);

    args.argv[0] = old_argv0;
    return EXIT_SUCCESS;
#else
    dup2(STDOUT_FILENO, STDERR_FILENO);
    fuse_opt_add_arg(&args, "-ho");  // I think ho means "help output".
    fuse_main(args.argc, args.argv, &ops, tree);
    _exit(EXIT_SUCCESS);
#endif
  }

  if (ctx.version) {
    std::cout << PROGRAM_NAME " " PROGRAM_VERSION "\n";
    std::cout << archive_version_details() << "\n";
    std::cout.flush();

    // Forward --version to libfuse so that it can print its own version.
    fuse_opt_add_arg(&args, "--version");

#if FUSE_USE_VERSION >= 30
    fuse_main(args.argc, args.argv, &ops, tree);
    return EXIT_SUCCESS;
#else
    dup2(STDOUT_FILENO, STDERR_FILENO);
    fuse_main(args.argc, args.argv, &ops, tree);
    _exit(EXIT_SUCCESS);
#endif
  }

  if (ctx.archives.empty()) {
    PrintUsage();
    return EXIT_FAILURE;
  }

  // Sanitize PATH.
  if (ctx.can_use_external_filters) {
    if (ctx.unsafe_path) {
      LOG(DEBUG) << "Keeping unsafe path " << Path(getenv("PATH") ?: "");
    } else {
      SetSafePath();
    }
  } else if (setenv("PATH", safe_empty_path, 1) < 0) {
    PLOG(ERROR) << "Cannot reset PATH";
    throw ExitCode::GENERIC_FAILURE;
  }

  // Determine where the mount point should be.
  // The last non-option argument is the mount point, unless only one such
  // argument was provided, in which case it is both the archive and the base
  // for the mount point name.
  std::string mount_point;
  bool const mount_point_specified_by_user = ctx.archives.size() > 1;
  if (mount_point_specified_by_user) {
    mount_point = std::move(ctx.archives.back());
    ctx.archives.pop_back();
  } else {
    mount_point = Path(ctx.archives.front())
                      .WithoutTrailingSeparator()
                      .Split()
                      .second.WithoutExtension();
  }

  std::string mount_point_parent, mount_point_basename;
  std::tie(mount_point_parent, mount_point_basename) =
      Path(mount_point).WithoutTrailingSeparator().Split();

  if (mount_point_basename.empty()) {
    LOG(ERROR) << "Cannot use " << Path(mount_point) << " as a mount point";
    throw ExitCode::CANNOT_CREATE_MOUNT_POINT;
  }

  // Get a file descriptor to the parent directory of the mount point.
  FileDescriptor mount_point_parent_fd(
      open(!mount_point_parent.empty() ? mount_point_parent.c_str() : ".",
#if defined(O_PATH)
           O_DIRECTORY | O_PATH));  // Linux, FreeBSD >= 13
#elif defined(O_EXEC)
           O_DIRECTORY | O_EXEC));  // FreeBSD <= 12
#else
           O_DIRECTORY | O_RDONLY));  // OpenBSD, macOS
#endif

  if (!mount_point_parent_fd.IsValid()) {
    PLOG(ERROR) << "Cannot access directory " << Path(mount_point_parent);
    throw ExitCode::CANNOT_CREATE_MOUNT_POINT;
  }

  // Force single-threading if not fully cached.
  // When using lazy cache or no cache, we should only use one FUSE thread
  // because libarchive is not thread-safe.
  if (ctx.options.cache != Cache::Full) {
    fuse_opt_add_arg(&args, "-s");
  }

  // Mount the file system in read-only mode.
  fuse_opt_add_arg(&args, "-r");

#if FUSE_USE_VERSION < 30
  // Respect inode numbers.
  fuse_opt_add_arg(&args, "-o");
  fuse_opt_add_arg(&args, "use_ino");
#endif

  if (ctx.options.enforce_permissions) {
    fuse_opt_add_arg(&args, "-o");
    fuse_opt_add_arg(&args, "default_permissions");
  }

  // Read archive and build tree.
  Timer timer;

  tree = new Tree();
  tree->SetOptions(ctx.options);

  // Create cache file if necessary.
  if (ctx.options.cache != Cache::None) {
    tree->SetCacheFd(CreateCacheFile(ctx.options.memcache));
  }

  tree->Load(ctx.archives);

  // Log some debug messages.
  if (LOG_IS_ON(DEBUG)) {
    if (ctx.archives.size() > 1) {
      LOG(DEBUG) << "Loaded " << ctx.archives.size() << " archives in "
                 << timer;
    } else {
      LOG(DEBUG) << "Loaded " << Path(ctx.archives.front()) << " in " << timer;
    }

    LOG(DEBUG) << "The file system contains " << tree->GetNodeCount() - 1
               << " items totalling " << i64(tree->GetBlockCount()) * block_size
               << " bytes";

    if (Stat z; ctx.options.cache == Cache::Full &&
                fstat(tree->GetCacheFd(), &z) == 0) {
      LOG(DEBUG) << "The cache takes " << i64(z.st_blocks) * block_size
                 << " bytes of disk space";
      assert(z.st_size == tree->GetCacheSize());
    }
  }

  // Create the mount point if it does not already exist.
  Cleanup mount_point_guard;
  {
    auto const n = mount_point_basename.size();
    int i = 0;
    while (true) {
      mount_point = mount_point_parent;
      Path::Append(&mount_point, mount_point_basename);

      if (mkdirat(mount_point_parent_fd, mount_point_basename.c_str(), 0777) ==
          0) {
        LOG(INFO) << "Created mount point " << Path(mount_point);

        // Set the cleanup function that will eventually remove this mount
        // point.
        mount_point_guard.fn = [&mount_point_parent_fd, mount_point_basename,
                                mount_point]() {
          if (unlinkat(mount_point_parent_fd, mount_point_basename.c_str(),
                       AT_REMOVEDIR) == 0) {
            LOG(INFO) << "Removed mount point " << Path(mount_point);
          } else {
            PLOG(ERROR) << "Cannot remove mount point " << Path(mount_point);
          }
        };

        break;
      }

      if (errno != EEXIST) {
        PLOG(ERROR) << "Cannot create mount point " << Path(mount_point);
        throw ExitCode::CANNOT_CREATE_MOUNT_POINT;
      }

      if (mount_point_specified_by_user) {
        LOG(DEBUG) << "Using existing mount point " << Path(mount_point);
        mount_point_parent_fd.Close();
        break;
      }

      LOG(DEBUG) << "Mount point " << Path(mount_point) << " already exists";

      mount_point_basename.resize(n);
      mount_point_basename += StrCat(" (", ++i, ")");
    }
  }

  // The mount point is in place.
  if (mount_point.starts_with('-')) {
    // If the mount point name starts with a '-', libfuse will think it is an
    // option. Prepended "./" to avoid this.
    fuse_opt_add_arg(&args, StrCat("./", mount_point).c_str());
  } else {
    fuse_opt_add_arg(&args, mount_point.c_str());
  }

  // Start serving the filesystem.
  LOG(DEBUG) << "Calling fuse_main() with " << args;
  int const res = fuse_main(args.argc, args.argv, &ops, tree);

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
