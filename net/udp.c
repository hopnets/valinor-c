#include "../inc/udp.h"

extern struct net_conf conf;

unsigned int net_rx_udp(struct rte_mbuf *m, struct rte_ether_hdr *ethhdr, struct rte_ipv4_hdr *iphdr, 
        void **payload_offset, struct udp_flow_id *udp_flow)
{
    struct rte_udp_hdr *udphdr;
    u_int16_t udp_dgram_size, payload_size;
    udphdr = (struct rte_udp_hdr *)((char *)iphdr + sizeof(*iphdr));
    udp_dgram_size = rte_be_to_cpu_16(udphdr->dgram_len);
    udp_flow->source.port = rte_be_to_cpu_16(udphdr->src_port);
    udp_flow->destination.port = rte_be_to_cpu_16(udphdr->dst_port);
    payload_size = udp_dgram_size - sizeof(*udphdr);
   
    *payload_offset = (void *) ((char *)udphdr + sizeof(*udphdr));

    // skip the UDP checksum for now!
    return (udp_dgram_size - sizeof(*udphdr));
}

static int udp_append_payload(struct rte_mbuf *m, void *data, unsigned int payload_len, uint32_t i)
{
    rte_memcpy(rte_pktmbuf_mtod_offset(m, char *, m->l2_len + m->l3_len + sizeof(struct rte_udp_hdr)), data, (size_t) payload_len);
    return payload_len;
}

static int udp_send_raw(struct rte_mbuf *m, size_t len,
			struct udp_flow_id *udp_flow)
{
	struct rte_udp_hdr *udphdr;

	/* write UDP header */
    udphdr = get_udp_offset(m, 0);
	udphdr->src_port = rte_cpu_to_be_16(udp_flow->destination.port);
	udphdr->dst_port = rte_cpu_to_be_16(udp_flow->source.port);
	udphdr->dgram_len = rte_cpu_to_be_16(len + sizeof(*udphdr));
	udphdr->dgram_cksum = 0;

	/* send the IP packet */
    return net_tx_ip(m, IPPROTO_UDP, udp_flow->source.ip);
    
}


int udp_send_dgram(struct udp_flow_id *udp_flow, char *tx_data, unsigned int len)
{
    struct netaddr addr;
    struct rte_mbuf **mbuf;
	ssize_t ret, count = 0;
    uint32_t i, l2_length;
    uint64_t tsc;
    unsigned int payload_len, remaining_bytes = len;

    count = (len / UDP_MAX_PAYLOAD) + 1;
	
    mbuf = (struct rte_mbuf **) rte_malloc(NULL, count * sizeof(struct rte_mbuf *), 0);

    for(i=0; i < count;i++)
    {
        mbuf[i] = rte_pktmbuf_alloc(get_worker_mempool());
        if (mbuf[i] == NULL)
        {
            log_warn("Not enough memory to allocate mbufs.");
            goto done;
        }
        payload_len = min(remaining_bytes, UDP_MAX_PAYLOAD);
        l2_length = sizeof(struct rte_ether_hdr);

        mbuf[i]->data_len = l2_length + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + payload_len;
        mbuf[i]->next = NULL;
        mbuf[i]->nb_segs		= 1;
        mbuf[i]->pkt_len		= mbuf[i]->data_len;
        mbuf[i]->ol_flags		= 0;
        mbuf[i]->vlan_tci		= 0;
        mbuf[i]->vlan_tci_outer	= 0;
        mbuf[i]->l2_len		= l2_length;
        mbuf[i]->l3_len		= sizeof(struct rte_ipv4_hdr);
        // rte_put payload
        // tsc = rte_cpu_to_be_64(rte_rdtsc());
        // rte_memcpy(tx_data+(len - remaining_bytes), &tsc, 8);
        ret = udp_append_payload(mbuf[i], tx_data+(len - remaining_bytes), payload_len, i);
        if(ret < 0)
        {
            log_warn("failed to copy udp payload");
            rte_pktmbuf_free(mbuf[i]);
        }
        ret = udp_send_raw(mbuf[i], payload_len, udp_flow);
        if (unlikely(ret)) {
            log_warn("Failed to send raw UDP dgram");
		    rte_pktmbuf_free(mbuf[i]);
	    }
        remaining_bytes -= payload_len;
    }

done:
    rte_free(mbuf);
    return len - remaining_bytes;
}