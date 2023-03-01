#include <string.h>

#include "valinor.h"
#include "core.h"

#define is_multicast_ipv4_addr(ipv4_addr) \
	(((rte_be_to_cpu_32((ipv4_addr)) >> 24) & 0x000000FF) == 0xE0)

void net_rx_icmp(struct rte_mbuf *m, struct rte_ether_hdr *eth_h, struct rte_ipv4_hdr *iphdr);
