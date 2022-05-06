#include "sandbox/sandbox.h"

int main(int argc, char* argv[]) {
    struct sandbox_data data = {};
    data.executable_path = argv[1];
    data.rootfs_path = argv[2];
    data.perm_flags = 0;
    data.ram_limit_bytes = 0;
    data.stack_size = 10240;
    data.time_execution_limit_ms = 0;

    data.rlimits_size = 1;
    rlimit r;
    getrlimit(RLIMIT_AS, &r);

    data.rlimits[0] = {
            .resource = RLIMIT_AS,
            .rlim = {
                    .rlim_cur = 1024,
                    .rlim_max = r.rlim_max,
            }
    };

    run_sandbox(data);
}