/*

clang -O2 port_restrict_loader.c -o port_restrict_loader -lbpf
*/

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define CGROUP_PATH "/sys/fs/cgroup"
#define BPF_OBJ_PATH "port_restrict.o"

// Map to store UID -> port range mappings.
//
struct port_range {
    __u16 min_port;
    __u16 max_port;
};

struct user_config {
    const char *username;
    __u16 min_port;
    __u16 max_port;
};

static struct user_config users[] = {
    {"dev98", 9000, 9009},
    {"dev99", 9010, 9019},
};

static int populate_user_map(int map_fd) {
    const int num_users = sizeof(users) / sizeof(struct user_config);

    for (int i=0; i<num_users; i++) {
        struct passwd *pw = getpwnam(users[i].username);
        if (!pw) {
            fprintf(stderr, "User %s not found, skipping\n", users[i].username);
            continue;
        }

        __u32 uid = pw->pw_uid;
        struct port_range range = {
            .min_port = users[i].min_port,
            .max_port = users[i].max_port,
        };

        if (bpf_map_update_elem(map_fd, &uid, &range, BPF_ANY) != 0) {
            fprintf(stderr, "Failed to update map for %s (uid %u)\n", users[i].username, uid);

            return -1;
        }

        printf("%s (uid %u): %u-%u\n", users[i].username, uid, range.min_port, range.max_port);
    }

    return 0;
}

static int attach_progs(const struct bpf_object *obj, const int cgroup_fd) {
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        const char *prog_name = bpf_program__name(prog);
        const int prog_fd = bpf_program__fd(prog);
        if (prog_fd < 0) {
            fprintf(stderr, "Failed to get fd for %s\n", prog_name);
            return -1;
        }

        enum bpf_attach_type attach_type;
        if (strcmp(prog_name, "bind4_prog") == 0) {
            attach_type = BPF_CGROUP_INET4_BIND;
        } else if (strcmp(prog_name, "bind6_prog") == 0) {
            attach_type = BPF_CGROUP_INET6_BIND;
        } else if (strcmp(prog_name, "connect4_prog") == 0) {
            attach_type = BPF_CGROUP_INET4_CONNECT;
        } else if (strcmp(prog_name, "connect6_prog") == 0) {
            attach_type = BPF_CGROUP_INET6_CONNECT;
        } else {
            fprintf(stderr, "Program %s not found\n", prog_name);
            // TODO make this a return.
            continue;
        }

        // TODO Use bpf_program__attach()?
        if (bpf_prog_attach(prog_fd, cgroup_fd, attach_type, 0) != 0) {
            fprintf(stderr, "Failed to attach %s: %s\n", prog_name, strerror(errno));

            return -1;
        }

        printf("  * Attached program %s (type %d)\n", prog_name, attach_type);
    }

    return 0;
}

int main(int argc, char**argv) {
    if (geteuid() != 0) {
        fprintf(stderr, "This program must be run as root.\n");

        return 1;
    }

    printf("* open\n");
    struct bpf_object *obj = bpf_object__open(BPF_OBJ_PATH);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object: %s\n", strerror(errno));

        return 2;
    }

    printf("* load\n");
    int err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(-err));

        return 3;
    }

    printf("* map\n");
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "user_port_map");
    if (!map) {
        fprintf(stderr, "Fail to find user_port_map\n");
        err = -1;
        goto cleanup;
    }

    printf("* populate\n");
    int map_fd = bpf_map__fd(map);
    if (populate_user_map(map_fd) != 0) {
        err = -1;
        goto cleanup;
    }

    printf("* cgroup\n");
    int cgroup_fd = open(CGROUP_PATH, O_RDONLY);
    if (cgroup_fd < 0) {
        fprintf(stderr, "Failed to open cgroup %s: %s\n", CGROUP_PATH, strerror(errno));
        err = -1;
        goto cleanup;
    }

    printf("* attach\n");
    if (attach_progs(obj, cgroup_fd) != 0) {
        close(cgroup_fd);
        err = -1;
        goto cleanup;
    }

    printf("* Ports are now restricted.\n");

    while (1) {
        sleep(86400);
    }

cleanup:
    bpf_object__close(obj);

    return err ? 1 : 0;
}