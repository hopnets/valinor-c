#ifndef NET_CORE_H
#define NET_CORE_H

#include "valinor.h"
#include "icmp.h"
#include "udp.h"
#include "arp.h"
#include "tcp.h"
#include "net_tx.h"
#include "app.h"
#include "ts.h"
#include "flowinfo.h"


#define IP_ID_SEED	0x97856428
#define IPPROTO_VALINOR_TS 0xFD
#define IPPROTO_VALINOR_TS2 0xFF

void net_rx_trans(struct rte_mbuf **ms, const unsigned int nr, struct rte_ring *ts_ring);
void net_rx_arp(struct rte_mbuf *m, struct rte_ether_hdr *ethhdr);
void rx_send_completion(struct rte_mbuf *pkt, struct rte_ring *completion_ring);
void net_rcv(struct rte_mbuf *pkts[], unsigned int nr, struct rte_mempool *mp, struct rte_ring *completion_ring, struct rte_ring *ts_ring);
int arp_add_entry(char *IP, char *MAC);

static void copy_udp_payload_to_app(struct udp_flow_id *udp_flow, void *offset, unsigned int payload_len)
{
    app_receive_udp_callback(udp_flow, offset, payload_len);
}

static inline int
is_valid_ipv4_pkt(struct rte_ipv4_hdr *pkt, uint32_t link_len)
{
	/* From http://www.rfc-editor.org/rfc/rfc1812.txt section 5.2.2 */
	/*
	 * 1. The packet length reported by the Link Layer must be large
	 * enough to hold the minimum length legal IP datagram (20 bytes).
	 */
	if (link_len < sizeof(struct rte_ipv4_hdr))
		return -1;

	/* 2. The IP checksum must be correct. */
	/* this is checked in H/W */

	/*
	 * 3. The IP version number must be 4. If the version number is not 4
	 * then the packet may be another version of IP, such as IPng or
	 * ST-II.
	 */
	if (((pkt->version_ihl) >> 4) != 4)
		return -3;
	/*
	 * 4. The IP header length field must be large enough to hold the
	 * minimum length legal IP datagram (20 bytes = 5 words).
	 */
	if ((pkt->version_ihl & 0xf) < 5)
		return -4;

	/*
	 * 5. The IP total length field must be large enough to hold the IP
	 * datagram header, whose length is specified in the IP header length
	 * field.
	 */
	if (rte_be_to_cpu_16(pkt->total_length) < sizeof(struct rte_ipv4_hdr))
		return -5;

	return 0;
}

static const char *
arp_op_name(uint16_t arp_op)
{
	switch (arp_op) {
	case RTE_ARP_OP_REQUEST:
		return "ARP Request";
	case RTE_ARP_OP_REPLY:
		return "ARP Reply";
	case RTE_ARP_OP_REVREQUEST:
		return "Reverse ARP Request";
	case RTE_ARP_OP_REVREPLY:
		return "Reverse ARP Reply";
	case RTE_ARP_OP_INVREQUEST:
		return "Peer Identify Request";
	case RTE_ARP_OP_INVREPLY:
		return "Peer Identify Reply";
	default:
		break;
	}
	return "Unkwown ARP op";
}

static void
ipv4_addr_to_dot(uint32_t be_ipv4_addr, char *buf)
{
	uint32_t ipv4_addr;

	ipv4_addr = rte_be_to_cpu_32(be_ipv4_addr);
	sprintf(buf, "%d.%d.%d.%d", (ipv4_addr >> 24) & 0xFF,
		(ipv4_addr >> 16) & 0xFF, (ipv4_addr >> 8) & 0xFF,
		ipv4_addr & 0xFF);
}

static void
ether_addr_dump(const char *what, const struct rte_ether_addr *ea)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];

	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, ea);
	if (what)
		printf("%s", what);
	printf("%s", buf);
}

static void
ipv4_addr_dump(const char *what, uint32_t be_ipv4_addr)
{
	char buf[16];

	ipv4_addr_to_dot(be_ipv4_addr, buf);
	if (what)
		printf("%s", what);
	printf("%s", buf);
}

#endif // NET_CORE_H