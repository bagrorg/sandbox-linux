#include <filesystem>
#include <stdint.h>
#include <sys/resource.h>

#define MAX_RLIMITS 16          // TODO: is maximum equals 16?

namespace fs = std::filesystem;

using milliseconds = uint64_t;
using bytes = uint64_t;

struct sandbox_rlimit {
    __rlimit_resource resource;
    rlimit rlim;
};

struct sandbox_data {
    pid_t pid;

    fs::path executable_path;
    fs::path rootfs_path;
    int perm_flags;
    milliseconds time_execution_limit_ms;
    bytes ram_limit_bytes;
    bytes stack_size;

    sandbox_rlimit rlimits[MAX_RLIMITS];
    size_t rlimits_size = 0;
};

void run_sandbox(const struct sandbox_data& data);