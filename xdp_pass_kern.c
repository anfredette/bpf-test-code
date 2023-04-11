/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

volatile const __u32 GLOBAL_1 = 0;
volatile const __u32 GLOBAL_2 = 0;

SEC("xdp")
int  xdp_prog_simple(struct xdp_md *ctx)
{
        bpf_printk("XDP: GLOBAL_1: %d / 0x%08X, GLOBAL_2: %d / 0x%08X", GLOBAL_1, GLOBAL_1, GLOBAL_2, GLOBAL_2);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
