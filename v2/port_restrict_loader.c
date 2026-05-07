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
    // const char *username;
    __u32 uid;
    __u16 min_port;
    __u16 max_port;
};

// static struct user_config users[] = {
//     {"dev98", 9000, 9009},
//     {"dev99", 9010, 9019},
// };

// Big enough for our purposes.
//
static struct user_config users[100];

static int read_file(char *fnam) {
    FILE *fp = fopen(fnam, "r");
    if (!fp) {
        fprintf(stderr, "Failed to open file %s: %s\n", fnam, strerror(errno));
        return -1;
    }

    char buf[1024];
    int ix = 1;
    while (fgets(buf, sizeof(buf), fp)) {
        // Remove trailing newline character.
        //
        buf[strcspn(buf, "\n")] = 0;
        char *token = strtok(buf, ",");
        const char *username = token;
        token = strtok(NULL, ",");
        unsigned long min_port = strtoul(token, NULL, 0);
        token = strtok(NULL, ",");
        unsigned long max_port = strtoul(token, NULL, 0);

        if ((min_port < 1024) || (max_port < 1024) || (min_port > 65535) || (max_port > 65535)) {
            fprintf(stderr, "Bad port at line %d\n", ix+1);

            return -1;
        }

        struct passwd *pw = getpwnam(username);
        if (!pw) {
            fprintf(stderr, "User %s not found, skipping\n", username);
            continue;
        }

        users[ix] = (struct user_config){
            .uid = pw->pw_uid,
            .min_port = min_port,
            .max_port = max_port
        };
        printf("User %-8s (uid %5u) | %5lu | %5lu\n", username, pw->pw_uid, min_port, max_port);

        ix++;
    }

    return ix;
}

static int update_user_map(int map_fd, int num_users) {
    for (int i=0; i<num_users; i++) {
        struct port_range range = {
            .min_port = users[i].min_port,
            .max_port = users[i].max_port,
        };

        if (bpf_map_update_elem(map_fd, &users[i].uid, &range, BPF_ANY) != 0) {
            fprintf(stderr, "Failed to update map for uid %u\n", users[i].uid);

            return -1;
        }
    }

    return 0;
}

// static int populate_user_map(int map_fd, int num_users) {
//     const int num_users = sizeof(users) / sizeof(struct user_config);

//     for (int i=0; i<num_users; i++) {
//         struct passwd *pw = getpwnam(users[i].username);
//         if (!pw) {
//             fprintf(stderr, "User %s not found, skipping\n", users[i].username);
//             continue;
//         }

//         __u32 uid = pw->pw_uid;
//         struct port_range range = {
//             .min_port = users[i].min_port,
//             .max_port = users[i].max_port,
//         };

//         if (bpf_map_update_elem(map_fd, &uid, &range, BPF_ANY) != 0) {
//             fprintf(stderr, "Failed to update map for %s (uid %u)\n", users[i].username, uid);

//             return -1;
//         }

//         printf("%s (uid %u): %u-%u\n", users[i].username, uid, range.min_port, range.max_port);
//     }

//     return 0;
// }

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

        // TODO Use bpf_program__attach()? bpf_program__pin?
        if (bpf_prog_attach(prog_fd, cgroup_fd, attach_type, 0) != 0) {
            fprintf(stderr, "Failed to attach %s: %s\n", prog_name, strerror(errno));

            return -1;
        }

        // char path[100];
        // sprintf(path, "/sys/fs/bpf/port_restrict/%s", prog_name);
        // int e = bpf_program__pin(prog, path);
        // if (e) {
        //     printf("pin %d %s\n", e, strerror(errno));
        // }

        printf("  * Attached program %s (type %d)\n", prog_name, attach_type);
    }

    return 0;
}

int main(int argc, char**argv) {

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <user,min_port,max_port file>", argv[0]);
        return 1;
    }

    int num_users = read_file(argv[1]);
    if (num_users <= 0) {
        return 1;
    }

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
    // if (populate_user_map(map_fd) != 0) {
    //     err = -1;
    //     goto cleanup;
    // }
    if (update_user_map(map_fd, num_users) != 0) {
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

    // while (1) {
    //     sleep(86400);
    // }

cleanup:
    bpf_object__close(obj);

    return err ? 1 : 0;
}