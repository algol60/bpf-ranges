#include <stdint.h>          // Standard integer definitions (e.g., uint64_t)
#include <linux/types.h>     // Linux-specific types (e.g., __u32, __u64)
#include <linux/bpf.h>       // eBPF map and program type definitions (e.g., BPF_MAP_TYPE_RINGBUF)
#include <bpf/bpf_helpers.h> // Helper functions provided by eBPF (e.g., bpf_get_current_pid_tgid)
#include <bpf/bpf_tracing.h> // For working with tracepoints
#include <linux/limits.h>    // For PATH_MAX (maximum file path length)

// Define a ring buffer map to transfer events from kernel space to user space
// This map will live in the ".maps" ELF section and is required for event streaming
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF); // Specify that this is a ring buffer map
    __uint(max_entries, 32768);         // Maximum size (in bytes) of the buffer
} exec_ringbuf SEC(".maps");            // SEC macro tells the loader this is a BPF map

// A license declaration is mandatory for eBPF programs
// "Dual BSD/GPL" ensures compatibility with all helper functions
char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Define the structure of the event we will send to user space
// This includes metadata (pid, uid, timestamp) and the executed filename
struct event_t {
    int pid;                          // Process ID
    int uid;                          // User ID
    long int timestamp;               // Timestamp in nanoseconds
    char filename[PATH_MAX];          // Executed filename (full path)
};

// This struct matches the tracepoint argument format for sys_enter_execve
// To find the exact layout of any syscall tracepoint, inspect:
// /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format
struct sys_enter_execve_args {
    char _[16];         // Padding for internal tracepoint fields (not used)
    uint64_t filename_ptr; // Pointer to the filename string
    uint64_t argv;         // Pointer to argv
    uint64_t envp;         // Pointer to envp
};

// Define the eBPF program that will run on the tracepoint "sys_enter_execve"
// This tracepoint is triggered whenever a process calls execve()
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct sys_enter_execve_args *ctx)
{
    struct event_t *event;

    // Reserve space in the ring buffer for our event
    // If the reservation fails (e.g., buffer is full), exit early
    event = bpf_ringbuf_reserve(&exec_ringbuf, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    // Capture metadata: current process ID, user ID, and timestamp
    event->pid = bpf_get_current_pid_tgid() >> 32; // Upper 32 bits = PID
    event->uid = bpf_get_current_uid_gid() >> 32;  // Upper 32 bits = UID
    event->timestamp = bpf_ktime_get_ns();         // Nanosecond-resolution timestamp

    // Read the filename pointer from tracepoint arguments
    char *filename_ptr = (char *)ctx->filename_ptr;

    // Safely copy the filename string from user space into our event struct
    // If the read fails (e.g., invalid pointer), discard the event and return
    if (bpf_probe_read_user_str(event->filename, PATH_MAX, filename_ptr) < 0) {
        bpf_ringbuf_discard(event, 0); // Release reserved space in the ringbuf
        return -1;
    }

    // Print to kernel debug trace buffer for quick testing/logging
    // You can view this with: sudo cat /sys/kernel/debug/tracing/trace_pipe
    bpf_printk("%d %d %s\n", event->pid, event->uid, event->filename);

    // Submit the event to the ring buffer so it can be consumed in user space
    bpf_ringbuf_submit(event, 0);

    return 0;
}
