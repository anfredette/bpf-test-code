#include <linux/bpf.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_helpers.h>

SEC("classifier/drop")
int drop(struct __sk_buff *skb)
{
	bpf_printk("Returning TC_ACT_SHOT");
	return TC_ACT_SHOT;
}

char _license[] SEC("license") = "GPL";
