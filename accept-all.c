#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

SEC("classifier/accept")
int accept(struct __sk_buff *skb) {
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";

