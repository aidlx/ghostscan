#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct ghostscan_task_value {
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct ghostscan_task_value);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ghostscan_task_pids SEC(".maps");

SEC("iter/task")
int ghostscan_iter_task(struct bpf_iter__task *ctx)
{
    struct task_struct *task = ctx->task;
    if (!task) {
        return 0;
    }

    pid_t tgid = BPF_CORE_READ(task, tgid);
    if (tgid <= 0) {
        return 0;
    }

    struct ghostscan_task_value entry = {};
    if (BPF_CORE_READ_STR_INTO(&entry.comm, task, comm) < 0) {
        entry.comm[0] = '\0';
    }

    __u32 key = tgid;
    bpf_map_update_elem(&ghostscan_task_pids, &key, &entry, BPF_ANY);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
