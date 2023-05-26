#include <linux/bpf.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_helpers.h>

SEC("classifer/pipe")
int pipe(struct __sk_buff *skb)
{
	bpf_printk("Returning TC_ACT_PIPE");
	return TC_ACT_PIPE;
}

char _license[] SEC("license") = "GPL";
