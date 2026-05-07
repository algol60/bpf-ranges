#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <string.h>

#define CGROUP_PATH "/sys/fs/cgroup"

int main() {
    int cgroup_fd = open(CGROUP_PATH, O_RDONLY);
    if (cgroup_fd < 0) {
        fprintf(stderr, "Failed to open cgroup %s: %s\n", CGROUP_PATH, strerror(errno));

        return 1;
    }

    __u32 id = 0;
    int fd, err;

    __u32 next_id = 0;

    while (1) {
        union bpf_attr attr = {};

        __u32 start_id = next_id;
        err = bpf_prog_get_next_id(start_id, &next_id);
        if (err < 0) {
            if (errno == ENOENT) break; // No more programs
            perror("BPF_PROG_GET_NEXT_ID");
            return 1;
        }

        fd = bpf_prog_get_fd_by_id(next_id);
        if (fd < 0) {
            // The program might have been unloaded.
            //
            continue;
        }

        // Get program info.
        //
        struct bpf_prog_info info = {0};
        __u32 info_len = sizeof(info);
        if ((err = bpf_obj_get_info_by_fd(fd, &info, &info_len))) {
            fprintf(stderr, "Getting info by fd: %s", strerror(err));
            return 1;
        }
        // printf("%s\n", info.name);

        enum bpf_attach_type attach_type = -1;
        if (strcmp(info.name, "bind4_prog") == 0) {
            attach_type = BPF_CGROUP_INET4_BIND;
        } else if (strcmp(info.name, "bind6_prog") == 0) {
            attach_type = BPF_CGROUP_INET6_BIND;
        } else if (strcmp(info.name, "connect4_prog") == 0) {
            attach_type = BPF_CGROUP_INET4_CONNECT;
        } else if (strcmp(info.name, "connect6_prog") == 0) {
            attach_type = BPF_CGROUP_INET6_CONNECT;
        }

        if (attach_type != -1) {
            printf("Detach %s\n", info.name);
            if ((err = bpf_prog_detach(cgroup_fd, attach_type))) {
                fprintf(stderr, "detach %d %s\n", err, strerror(err));
            }
        }

        close(fd);
    }

    close(cgroup_fd);

    return 0;
}
