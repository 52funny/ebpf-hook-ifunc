// clang-format off
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
// clang-format on

struct data_t {
  int pid;
  int uid;
  int size;
  u8 comm[32];
  u8 str[256];
};

struct data_t _data = {};
const u8 cmd[16] = {};
const int cmd_len = 0;

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
  __uint(max_entries, 10);
} resolve_addr SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
  __uint(max_entries, 10);
} impl_addr SEC(".maps");

SEC("uprobe")
int BPF_UPROBE(resolve_trace) {
  u64 addr = PT_REGS_IP(ctx);
  bpf_perf_event_output(ctx, &resolve_addr, BPF_F_CURRENT_CPU, &addr,
                        sizeof(addr));
  // bpf_ringbuf_output(&resolve_addr, &addr, sizeof(addr), 0);
  return 0;
}

SEC("uretprobe")
int BPF_URETPROBE(impl_trace) {
  u64 addr = PT_REGS_RC(ctx);
  bpf_perf_event_output(ctx, &impl_addr, BPF_F_CURRENT_CPU, &addr,
                        sizeof(addr));
  // bpf_ringbuf_output(&impl_addr, &addr, sizeof(addr), 0);
  return 0;
}

SEC("uretprobe")
int BPF_URETPROBE(ifunc_trace, int size) {
  struct data_t t = {};

  t.pid = bpf_get_current_pid_tgid() >> 32;
  t.uid = bpf_get_current_uid_gid();

  bpf_get_current_comm(t.comm, sizeof(t.comm));
  if (__builtin_memcmp(t.comm, (void *)cmd, __builtin_strlen((void *)cmd))) {
    return 0;
  };

  char *s = (void *)PT_REGS_PARM1(ctx);
  t.size = size;
  bpf_probe_read_user(t.str, sizeof(t.str), s);

  bpf_ringbuf_output(&rb, &t, sizeof(t), 0);

  return 0;
}
char _license[] SEC("license") = "Dual BSD/GPL";
