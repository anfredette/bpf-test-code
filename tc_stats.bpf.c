//#include <linux/types.h>
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>

#include <bpf/bpf_helpers.h>

struct key {
	__u32 dstip;
};

struct value {
	__u64 packets;
	__u64 bytes;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 32);
	__type(key, struct key);
	__type(value, struct value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} packet_stats SEC(".maps");

// Updates the packet statistics map.
// Use dstip == 0 for non-ip packets
static void update_stats(__u32 dstip, int bytes)
{
	struct key key = {
	    .dstip = dstip,
	};
	struct value *value = bpf_map_lookup_elem(&packet_stats, &key);

	if (value) {
		__sync_fetch_and_add(&value->packets, 1);
		__sync_fetch_and_add(&value->bytes, bytes);
	} else {
		struct value newval = {1, bytes};

		bpf_map_update_elem(&packet_stats, &key, &newval, BPF_NOEXIST);
	}
}

SEC("classifier/stats")
int stats(struct __sk_buff *skb)
{
	const int l3_off = ETH_HLEN;			  // IP header offset
	const int l4_off = l3_off + sizeof(struct iphdr); // L4 header offset

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	if (data_end < data + l4_off) {
		bpf_printk("Packet received with invalid data pointers");
		return TC_ACT_UNSPEC;
	}

	struct ethhdr *eth = data;
	if (eth->h_proto != htons(ETH_P_IP)) {
		bpf_printk("Non-ip packet received. proto: 0x%04X",
			   ntohs(eth->h_proto));
		update_stats(0, 0);
		return TC_ACT_PIPE;
	}

	struct iphdr *ip = (struct iphdr *)(data + l3_off);
	bpf_printk(
	    "IP packet received.  proto: 0x%04X, daddr: 0x%08X, length: %d",
	    ntohs(ip->protocol), ntohl(ip->daddr), ntohs(ip->tot_len));
	update_stats(ntohl(ip->daddr), ntohs(ip->tot_len));
	return TC_ACT_PIPE;
}

char _license[] SEC("license") = "GPL";
