// Some uprobed test code for a simple hello world program
#include <linux/bpf.h>
#include <stdio.h>
//#include <linux/ptrace.h>

#include <bpf/bpf_helpers.h>

int probe_hello(struct pt_regs *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;

  printf("In probe_hello.  pid: %u", pid);

  return 0;
}

SEC("uprobe/hello:main")
int BPF_KRETPROBE(malloc_out, void *addr) // addr returned by malloc
{
  return alloc_out(EV_MALLOC, addr);
}

SEC("uprobe/hello:main")
int hello_probe(struct pt_regs *ctx) { return probe_hello(ctx); }

char _license[] SEC("license") = "GPL";