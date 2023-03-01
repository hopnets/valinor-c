#ifndef UDP_H
#define UDP_H

#include "valinor.h"
#include "core.h"
#include "flowinfo.h"

#define UDP_MAX_PAYLOAD 1472 // 1450?

unsigned int net_rx_udp(struct rte_mbuf *m, struct rte_ether_hdr *ethhdr, struct rte_ipv4_hdr *iphdr, void **payload_offset, struct udp_flow_id *udp_flow);

int udp_send_dgram(struct udp_flow_id *udp_flow, char *tx_data, unsigned int len);

static inline struct rte_udp_hdr *get_udp_offset(struct rte_mbuf *m, int flowinfo_status)
{
	uint32_t l3_len;
	struct rte_ether_hdr *ethhdr;
	struct rte_udp_hdr *udphdr;

	ethhdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	udphdr = (struct rte_udp_hdr *) ((char *) ethhdr + m->l2_len + m->l3_len);
	return udphdr;
}

#endif // UDP_H