/*
 * icmp.c - support for Internet Control Message Protocol (ICMP)
 */

#include "../inc/icmp.h"

void net_rx_icmp(struct rte_mbuf *m, struct rte_ether_hdr *eth_h, struct rte_ipv4_hdr *iphdr)
{
	struct rte_icmp_hdr *icmp_h;
	struct rte_ether_addr eth_addr;
    struct rte_mbuf *pkts_burst[MAX_PKTS_BURST];
    uint32_t ip_addr;
    uint32_t cksum;
    uint16_t nb_tx, nb_replies = 0;

	/*
    * Check if packet is a ICMP echo request.
    */
    icmp_h = (struct rte_icmp_hdr *) ((char *)iphdr +
                        sizeof(struct rte_ipv4_hdr));
    if (! ((iphdr->next_proto_id == IPPROTO_ICMP) &&
            (icmp_h->icmp_type == RTE_IP_ICMP_ECHO_REQUEST) &&
            (icmp_h->icmp_code == 0))) {
        rte_pktmbuf_free(m);
        return;
    }

    log_debug("ICMP: echo request seq id=%d\n",
            rte_be_to_cpu_16(icmp_h->icmp_seq_nb));

    /*
        * Prepare ICMP echo reply to be sent back.
        * - switch ethernet source and destinations addresses,
        * - use the request IP source address as the reply IP
        *    destination address,
        * - if the request IP destination address is a multicast
        *   address:
        *     - choose a reply IP source address different from the
        *       request IP source address,
        *     - re-compute the IP header checksum.
        *   Otherwise:
        *     - switch the request IP source and destination
        *       addresses in the reply IP header,
        *     - keep the IP header checksum unchanged.
        * - set RTE_IP_ICMP_ECHO_REPLY in ICMP header.
        * ICMP checksum is computed by assuming it is valid in the
        * echo request and not verified.
        */
    rte_ether_addr_copy(&eth_h->s_addr, &eth_addr);
    rte_ether_addr_copy(&eth_h->d_addr, &eth_h->s_addr);
    rte_ether_addr_copy(&eth_addr, &eth_h->d_addr);
    ip_addr = iphdr->src_addr;
    if (is_multicast_ipv4_addr(iphdr->dst_addr)) {
        uint32_t ip_src;

        ip_src = rte_be_to_cpu_32(ip_addr);
        if ((ip_src & 0x00000003) == 1)
            ip_src = (ip_src & 0xFFFFFFFC) | 0x00000002;
        else
            ip_src = (ip_src & 0xFFFFFFFC) | 0x00000001;
        iphdr->src_addr = rte_cpu_to_be_32(ip_src);
        iphdr->dst_addr = ip_addr;
        iphdr->hdr_checksum = ipv4_hdr_cksum(iphdr);
    } else {
        iphdr->src_addr = iphdr->dst_addr;
        iphdr->dst_addr = ip_addr;
    }
    icmp_h->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
    cksum = ~icmp_h->icmp_cksum & 0xffff;
    cksum += ~htons(RTE_IP_ICMP_ECHO_REQUEST << 8) & 0xffff;
    cksum += htons(RTE_IP_ICMP_ECHO_REPLY << 8);
    cksum = (cksum & 0xffff) + (cksum >> 16);
    cksum = (cksum & 0xffff) + (cksum >> 16);
    icmp_h->icmp_cksum = ~cksum;
    pkts_burst[nb_replies++] = m;

    /* Send back ICMP echo replies, if any. */
	if (nb_replies > 0) {
		nb_tx = net_tx_mbuf_burst(pkts_burst, nb_replies, 0);

		if (unlikely(nb_tx < nb_replies)) {
			log_error("Failed to send ICMP reply to the TX worker");
			do {
				rte_pktmbuf_free(pkts_burst[nb_tx]);
			} while (++nb_tx < nb_replies);
		}
	}
}