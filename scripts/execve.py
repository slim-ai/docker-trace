#!/usr/bin/python -u

from bcc import BPF
from bcc.containers import filter_by_containers
from collections import defaultdict
import sys
import os

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#define ARGSIZE  128
enum event_type {
    EVENT_ARG,
    EVENT_RET,
};
struct data_t {
    u32 pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    enum event_type type;
    char argv[ARGSIZE];
};
BPF_PERF_OUTPUT(events);
static int __submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data) {
    bpf_probe_read(data->argv, sizeof(data->argv), ptr);
    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 1;
}
static int submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data) {
    const char *argp = NULL;
    bpf_probe_read(&argp, sizeof(argp), ptr);
    if (argp) {
        return __submit_arg(ctx, (void *)(argp), data);
    }
    return 0;
}
int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    // create data here and pass to submit_arg to save stack space (#555)
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.type = EVENT_ARG;
    __submit_arg(ctx, (void *)filename, &data);
    // skip first arg, as we submitted filename
    #pragma unroll
    for (int i = 1; i < 16; i++) {
        if (submit_arg(ctx, (void *)&__argv[i], &data) == 0)
             goto out;
    }
    // handle truncated argument list
    char ellipsis[] = "...";
    __submit_arg(ctx, (void *)ellipsis, &data);
out:
    return 0;
}
int do_ret_sys_execve(struct pt_regs *ctx) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.type = EVENT_RET;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

bpf = BPF(text=bpf_text)
execve_fnname = bpf.get_syscall_fnname("execve")
bpf.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
bpf.attach_kretprobe(event=execve_fnname, fn_name="do_ret_sys_execve")

EVENT_ARG = 0
EVENT_RET = 1
argv = defaultdict(list)

def print_event(cpu, data, size):
    event = bpf["events"].event(data)
    if event.type == EVENT_ARG:
        argv[event.pid].append(event.argv)
    elif event.type == EVENT_RET:
        argv_text = b' '.join(argv[event.pid]).replace(b'\n', b' ')
        # cwd = os.readlink(f'/proc/{event.pid}/cwd')
        sys.stdout.buffer.write(b'%d %s\n' % (event.pid, argv_text))
        argv.pop(event.pid, None)

if __name__ == '__main__':
    bpf["events"].open_perf_buffer(print_event)
    while 1:
        try:
            bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()
