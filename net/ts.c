#include "../inc/ts.h"

uint32_t create_conn_key(struct rte_mbuf *m, struct rte_ipv4_hdr *iphdr, struct valinor_ts_hdr *valinor_hdr, struct timestamp_entry *entry)
{
    struct l4_hdr *l4hdr;
	struct netaddr laddr, raddr;
	uint32_t hash;

	l4hdr = (struct l4_hdr *)((char *)valinor_hdr + VALINOR_TS_HDR_LENGTH);

	laddr.ip = rte_be_to_cpu_32(iphdr->dst_addr);
	laddr.port = rte_be_to_cpu_16(l4hdr->dport);
	raddr.ip = rte_be_to_cpu_32(iphdr->src_addr);
	raddr.port = rte_be_to_cpu_16(l4hdr->sport);

    entry->dport = laddr.port;
    entry->sport = raddr.port;
    entry->daddr = laddr.ip;
    entry->saddr = raddr.ip;

	/* attempt to find a 5-tuple match */
	hash = trans_hash_5tuple(valinor_hdr->protocol, laddr, raddr);
    log_debug("TS: RSS hash for ts packet = %X", hash);
	return hash;
}

void process_valinor_ts(struct rte_mbuf *m, struct rte_ether_hdr *ethhdr, struct rte_ipv4_hdr *iphdr, struct rte_ring *ts_ring)
{
    int ret;
    struct timestamp_entry *entry = rte_malloc(NULL, sizeof(struct timestamp_entry), 0);
    struct valinor_ts_hdr *valinorhdr;
    valinorhdr = (struct valinor_ts_hdr *)((char *)iphdr + sizeof(*iphdr));
    log_debug("Extracting valinor timestamp header");
    entry->key = create_conn_key(m, iphdr, valinorhdr, entry);

    entry->ingress_mac = rte_be_to_cpu_64(valinorhdr->ingress_mac) >> 16;
    entry->ingress_global = rte_be_to_cpu_64(valinorhdr->ingress_global) >> 16;
    entry->enqueue = rte_be_to_cpu_32(valinorhdr->enqueue);
    entry->enqueue_delta = rte_be_to_cpu_32(valinorhdr->enqueue_delta);
    entry->egress_global = rte_be_to_cpu_64(valinorhdr->egress_global) >> 16;
    entry->egress_tx = rte_be_to_cpu_64(valinorhdr->egress_tx) >> 16;
    entry->packet_length = rte_be_to_cpu_16(valinorhdr->packet_length);

    ret = rte_ring_enqueue_burst(ts_ring,
										 (void *)&entry, 1, NULL);
    if (unlikely(ret < 1))
    {
        log_error("Failed to enqueue timestamp entry");
    }
}