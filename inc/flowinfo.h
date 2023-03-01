#ifndef FLOWINFO_H
#define FLOWINFO_H

#include "valinor.h"

#define FLOWINFO_HEADER_PRESENT 1
#define FLOWINFO_HEADER_ABSENT 0

#define ETHER_TYPE_FLOWINFO 0x1111

#define FLOWINFO_HEADER_LENGTH 7
struct flowinfo_hdr {
    uint32_t seq;
    uint8_t retcnt;
    uint16_t ethertype;
} __attribute__((__packed__));

static inline struct rte_ipv4_hdr *get_ipv4_offset(struct rte_mbuf *m)
{
	struct rte_ether_hdr *ethhdr;
	struct rte_ipv4_hdr *iphdr;

	ethhdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	iphdr = (struct rte_ipv4_hdr *) ((char *) ethhdr + m->l2_len);
	return iphdr;
}

static inline struct flowinfo_hdr *get_flowinfo_offset(struct rte_mbuf *m)
{
	uint32_t l2_len;
	struct rte_ether_hdr *ethhdr;
	struct flowinfo_hdr *flowinfo;

	ethhdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	l2_len = sizeof(*ethhdr);

	flowinfo = (struct flowinfo_hdr *) ((char *) ethhdr + l2_len);
	return flowinfo;
}

#endif // FLOWINFO_H