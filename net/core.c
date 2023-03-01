#include "../inc/core.h"

extern struct net_conf conf;

int arp_add_entry(char *IP, char *MAC)
{
	return arp_table_add(IP, MAC);
}

static uint32_t net_get_ip_route(uint32_t daddr)
{
	/* simple IP routing */
	if ((daddr & conf.netmask) != (conf.addr & conf.netmask))
		daddr = conf.gateway;
	return daddr;
}

static struct trans_entry *trans_lookup(struct rte_mbuf *m, struct rte_ipv4_hdr *iphdr)
{
	const struct l4_hdr *l4hdr;
	struct trans_entry *e;
	struct netaddr laddr, raddr;
	uint32_t hash, l3_len;
	int ret;
	unsigned int core_id = 0;

	/* set up the network header pointers */
	if (unlikely(iphdr->next_proto_id != IPPROTO_UDP &&
				 iphdr->next_proto_id != IPPROTO_TCP))
		return NULL;
	l3_len = sizeof(*iphdr);

	l4hdr = (struct l4_hdr *)((char *)iphdr + l3_len);

	/* parse the source and destination network address */
	laddr.ip = rte_be_to_cpu_32(iphdr->dst_addr);
	laddr.port = rte_be_to_cpu_16(l4hdr->dport);
	raddr.ip = rte_be_to_cpu_32(iphdr->src_addr);
	raddr.port = rte_be_to_cpu_16(l4hdr->sport);

	/* attempt to find a 5-tuple match */
	hash = trans_hash_5tuple(iphdr->next_proto_id, laddr, raddr);
	ret = rte_hash_lookup_data(transport_hash[core_id], &hash, (void **)&e);
	if (ret >= 0)
	{
		if (e->proto == iphdr->next_proto_id &&
			e->laddr.ip == laddr.ip && e->laddr.port == laddr.port &&
			e->raddr.ip == raddr.ip && e->raddr.port == raddr.port)
		{
			return e;
		}
	}

	/* attempt to find a 3-tuple match */
	hash = trans_hash_3tuple(iphdr->next_proto_id, laddr);
	ret = rte_hash_lookup_data(transport_hash[core_id], &hash, (void **)&e);
	if (ret >= 0)
	{
		if (e->proto == iphdr->next_proto_id &&
			e->laddr.ip == laddr.ip && e->laddr.port == laddr.port)
		{
			return e;
		}
	}
	log_debug("TCP entry not found!");
	return NULL;
}

/**
 * net_rx_trans - receive L4 packets
 * @ms: an array of mbufs to process
 * @nr: the size of the @ms array
 */
void net_rx_trans(struct rte_mbuf **ms, const unsigned int nr, struct rte_ring *ts_ring)
{
	unsigned int i;
	struct rte_ether_hdr *ethhdr;
	struct rte_ipv4_hdr *iphdr;
	struct trans_entry *e;
	void *payload_offset;
	size_t payload_len;
	struct udp_flow_id udp_flow;

	log_debug("Proceeding to Transport processing!, l2 %u l3 %u", ms[i]->l2_len, ms[i]->l3_len);

	/* deliver each packet to a L4 protocol handler */
	for (i = 0; i < nr; i++)
	{
		log_debug("Packet is VALINOR TS!");
		ethhdr = rte_pktmbuf_mtod(ms[i], struct rte_ether_hdr *);
		iphdr = (struct rte_ipv4_hdr *)((char *)ethhdr + ms[i]->l2_len);
		if (iphdr->next_proto_id == IPPROTO_VALINOR_TS || iphdr->next_proto_id == IPPROTO_VALINOR_TS2 ) {
			process_valinor_ts(ms[i], ethhdr, iphdr, ts_ring);
			rte_pktmbuf_free(ms[i]);
		}
		else if (iphdr->next_proto_id == IPPROTO_UDP)
		{
			log_debug("Packet is UDP!");
			payload_len = net_rx_udp(ms[i], ethhdr, iphdr, &payload_offset, &udp_flow);
			udp_flow.destination.ip = rte_be_to_cpu_32(iphdr->dst_addr);
			udp_flow.source.ip = rte_be_to_cpu_32(iphdr->src_addr);
			copy_udp_payload_to_app(&udp_flow, payload_offset, payload_len);
			rte_pktmbuf_free(ms[i]);
		}
		else if (iphdr->next_proto_id == IPPROTO_TCP)
		{
			log_debug("Packet is TCP!");
			e = trans_lookup(ms[i], iphdr);
			if (unlikely(!e))
			{
				tcp_rx_closed(ms[i]);
				rte_pktmbuf_free(ms[i]);
				continue;
			}
			if (e->ops == NULL)
			{
				log_warn("Trans entry ops undefined!!!!");
				rte_pktmbuf_free(ms[i]);
			}
			else
				e->ops->recv(e, ms[i]);
		}
		else
		{
			log_warn("Unsupported transport protocol: %x", iphdr->next_proto_id);
			rte_pktmbuf_free(ms[i]);
		}
	}
}

void net_rx_arp(struct rte_mbuf *m, struct rte_ether_hdr *ethhdr)
{
	struct rte_arp_hdr *arphdr;
	struct rte_ether_addr eth_addr;
	u_int32_t ip_addr;
	u_int16_t arp_op, arp_pro;
	int nb_tx;
	log_error("Proceeding to ARP processing!");
	/* Reply to ARP requests */
	arphdr = (struct rte_arp_hdr *)((char *)ethhdr + sizeof(*ethhdr));
	arp_op = rte_be_to_cpu_16(arphdr->arp_opcode);
	arp_pro = rte_be_to_cpu_16(arphdr->arp_protocol);
	log_debug("ARP:  hrd=%d proto=0x%04x hln=%d pln=%d op=%u (%s)", rte_be_to_cpu_16(arphdr->arp_hardware),
			  arp_pro, arphdr->arp_hlen, arphdr->arp_plen, arp_op, arp_op_name(arp_op));
	if ((rte_be_to_cpu_16(arphdr->arp_hardware) != RTE_ARP_HRD_ETHER) || (arp_pro != RTE_ETHER_TYPE_IPV4) ||
		(arphdr->arp_hlen != 6) || (arphdr->arp_plen != 4))
	{
		rte_pktmbuf_free(m);
		return;
	}
	log_debug("ARP packet info:");
	rte_ether_addr_copy(&arphdr->arp_data.arp_sha, &eth_addr);
	ether_addr_dump("        sha=", &eth_addr);
	ip_addr = arphdr->arp_data.arp_sip;
	ipv4_addr_dump(" sip=", ip_addr);
	printf("\n");
	rte_ether_addr_copy(&arphdr->arp_data.arp_tha,
						&eth_addr);
	ether_addr_dump("        tha=", &eth_addr);
	ip_addr = arphdr->arp_data.arp_tip;
	ipv4_addr_dump(" tip=", ip_addr);
	printf("\n");
	if (arp_op != RTE_ARP_OP_REQUEST)
	{
		rte_pktmbuf_free(m);
		return;
	}

	/*
	* Build ARP reply.
	*/

	/* Use source MAC address as destination MAC address. */
	rte_ether_addr_copy(&ethhdr->s_addr, &ethhdr->d_addr);
	/* Set source MAC address with MAC address of TX port */
	rte_ether_addr_copy(&port_addr,
						&ethhdr->s_addr);

	arphdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
	rte_ether_addr_copy(&arphdr->arp_data.arp_tha,
						&eth_addr);
	rte_ether_addr_copy(&arphdr->arp_data.arp_sha,
						&arphdr->arp_data.arp_tha);
	rte_ether_addr_copy(&ethhdr->s_addr,
						&arphdr->arp_data.arp_sha);

	/* Swap IP addresses in ARP payload */
	ip_addr = arphdr->arp_data.arp_sip;
	arphdr->arp_data.arp_sip = arphdr->arp_data.arp_tip;
	arphdr->arp_data.arp_tip = ip_addr;
	nb_tx = net_tx_mbuf_burst(&m, 1, 0);
	if (unlikely(nb_tx < 1))
	{
		log_error("Failed to send ARP reply to the TX worker");
		rte_pktmbuf_free(m);
	}
}

void rx_send_completion(struct rte_mbuf *pkt, struct rte_ring *completion_ring)
{
	unsigned ret;
	ret = rte_ring_enqueue_burst(completion_ring, (void *)&pkt, 1, NULL);
	if (unlikely(ret < 1))
	{
		log_error("Failed to send completion to the RX dataplane!");
		rte_pktmbuf_free(pkt);
	}
}

static struct rte_mbuf *net_rx_alloc_mbuf(struct rte_mbuf *pkt, struct rte_mempool *mp)
{
	struct rte_mbuf *m;

	/* allocate the buffer to store the payload */
	log_debug("Cloning packet %X of size %u", pkt->hash.rss, pkt->pkt_len);
	if (pkt == NULL)
		log_error("pkt is null!!");
	if (mp == NULL)
		log_error("mp is null!!");
	m = rte_pktmbuf_clone(pkt, mp);
	log_debug("Cloned packet");
	return m;
}

static struct rte_mbuf *net_rx_one(struct rte_mbuf *pkt, struct rte_mempool *mp, struct rte_ring *completion_ring)
{
	struct rte_mbuf *m;
	struct rte_ether_hdr *ethhdr;
	struct rte_ipv4_hdr *iphdr;
	int ret;

	m = net_rx_alloc_mbuf(pkt, mp);
	rx_send_completion(pkt, completion_ring);
	if (unlikely(!m))
		return NULL;

	/*
	 * Link Layer Processing
	 */

	ethhdr = (struct rte_ether_hdr *)rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	if (unlikely(!ethhdr))
		goto drop;

	/* handle ARP requests */
	if (unlikely(rte_be_to_cpu_16(ethhdr->ether_type) == RTE_ETHER_TYPE_ARP))
	{
		net_rx_arp(m, ethhdr);
		return NULL;
	}

	m->l2_len = sizeof(*ethhdr);

	/*
	 * Network Layer Processing (IPv4)
	 */
	if(rte_be_to_cpu_16(ethhdr->ether_type) == ETHER_TYPE_FLOWINFO){
		m->l2_len+= FLOWINFO_HEADER_LENGTH;
	}

	iphdr = get_ipv4_offset(m);

	ret = is_valid_ipv4_pkt(iphdr, m->pkt_len);
	if (unlikely(ret < 0))
	{
		log_debug("Packet is not a valid IPv4 packet: %d", ret);
		goto drop;
	}

	m->l3_len = sizeof(struct rte_ipv4_hdr);

	// /* Did HW checksum verification pass? */ // TODO: do it later
	// if ((m->ol_flags & PKT_RX_IP_CKSUM_MASK) != PKT_RX_IP_CKSUM_GOOD) {
	// 	log_debug("Performing software checksum verification");
	// 	if (chksum_internet(iphdr, sizeof(*iphdr)))
	// 		goto drop;
	// }

	switch (iphdr->next_proto_id)
	{
	case IPPROTO_ICMP:
		net_rx_icmp(m, ethhdr, iphdr);
		break;

	case IPPROTO_UDP:
	case IPPROTO_TCP:
	case IPPROTO_VALINOR_TS:
	case IPPROTO_VALINOR_TS2:
		return m;

	default:
		goto drop;
	}

	return NULL;

drop:
	log_debug("Dropping the packet in the worker!");
	rte_pktmbuf_free(m);
	return NULL;
}

/**
 * start processing unicast packets
 * @pkts: an array of ingress packets (mbufs)
 * @nr: the size of the @pkts array
 */
void net_rcv(struct rte_mbuf *pkts[], unsigned int nr, struct rte_mempool *mp, struct rte_ring *completion_ring, struct rte_ring *ts_ring)
{
	struct rte_mbuf *l4_reqs[MAX_PKTS_BURST];
	unsigned int i, l4idx = 0;

	// log_debug("Net receive");

	for (i = 0; i < nr; i++)
	{
		l4_reqs[l4idx] = net_rx_one(pkts[i], mp, completion_ring);
		if (l4_reqs[l4idx] != NULL)
			l4idx++;
	}

	/* handle transport protocol layer */
	if (l4idx > 0)
		net_rx_trans(l4_reqs, l4idx, ts_ring);
}

static void net_tx_raw(struct rte_mbuf *m)
{
	int nb_tx;
	log_debug("Net sending packet to TX thread.");
	nb_tx = net_tx_mbuf_burst(&m, 1, 0);
	if (unlikely(nb_tx < 1))
	{
		log_error("Failed to send raw IP packets to the TX worker");
		rte_pktmbuf_free(m);
	}
}

/**
 * net_tx_eth - transmits an ethernet packet
 * @m: the mbuf to transmit
 * @type: the ethernet type (in native byte order)
 * @dhost: the destination MAC address
 *
 * The payload must start with the network (L3) header. The ethernet (L2)
 * header will be prepended by this function.
 *
 * @m must have been allocated with net_tx_alloc_mbuf().
 *
 * Returns 0 if successful. If successful, the mbuf will be freed when the
 * transmit completes. Otherwise, the mbuf still belongs to the caller.
 */
int net_tx_eth(struct rte_mbuf *m, uint16_t type, struct rte_ether_addr *dhost)
{
	struct rte_ether_hdr *ethhdr;

	log_debug("Eth TX received packet for transmission.");

	ethhdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	rte_memcpy(&(ethhdr->s_addr), conf.mac, 6);
	rte_ether_addr_copy((struct rte_ether_addr *)&conf.mac, &ethhdr->s_addr);
	rte_ether_addr_copy(dhost, &ethhdr->d_addr);
	ethhdr->ether_type = rte_cpu_to_be_16(type);
	net_tx_raw(m);
	return 0;
}

/**
 * net_tx_ip - transmits an IP packet
 * @m: the mbuf to transmit
 * @proto: the transport protocol
 * @daddr: the destination IP address (in native byte order)
 *
 * The payload must start with the transport (L4) header. The IPv4 (L3) and
 * ethernet (L2) headers will be prepended by this function.
 *
 * @m must have been allocated with net_tx_alloc_mbuf().
 *
 * Returns 0 if successful. If successful, the mbuf will be freed when the
 * transmit completes. Otherwise, the mbuf still belongs to the caller.
 */
int net_tx_ip(struct rte_mbuf *m, uint8_t proto, uint32_t daddr)
{
	struct rte_ether_addr dhost;
	struct rte_ipv4_hdr *iphdr;
	struct rte_tcp_hdr *tcphdr;
	int ret;

	log_debug("NET TX IP, l2l2n=%d", m->l2_len);
	iphdr = get_ipv4_offset(m);
	iphdr->version_ihl = RTE_IPV4_VHL_DEF;
	iphdr->type_of_service = 0x0; //  IPTOS_DSCP_CS0 | IPTOS_ECN_NOTECT;
	iphdr->total_length = rte_cpu_to_be_16(m->pkt_len - m->l2_len);
	/* This must be unique across datagrams within a flow, see RFC 6864 */
	// iphdr->packet_id = hash_crc32c_two(IP_ID_SEED, rdtsc() ^ proto,
	// 								   (uint64_t)daddr |
	// 									   ((uint64_t)conf.addr << 32));
	iphdr->packet_id = 0;
	iphdr->fragment_offset = rte_cpu_to_be_16(0x4000);
	iphdr->time_to_live = 64;
	iphdr->next_proto_id = proto;
	iphdr->hdr_checksum = 0;
	iphdr->src_addr = rte_cpu_to_be_32(conf.addr);
	iphdr->dst_addr = rte_cpu_to_be_32(daddr);

	iphdr->hdr_checksum = rte_ipv4_cksum(iphdr);
	if(proto == IPPROTO_TCP)
	{
		tcphdr = get_tcp_offset(m);
		tcphdr->cksum = rte_ipv4_udptcp_cksum(iphdr, tcphdr);
	}

	/* ask NIC to calculate IP checksum */
	// m->txflags |= OLFLAG_IP_CHKSUM | OLFLAG_IPV4;

	/* apply IP routing */
	daddr = net_get_ip_route(daddr);
	/* need to use ARP to resolve dhost */
	ret = arp_lookup(daddr, &dhost, m);
	if (unlikely(ret < 0))
	{
		if (ret == -EINPROGRESS)
		{
			/* ARP code now owns the mbuf */
			log_debug("Started ARP resolution");
			return 0;
		}
		else
		{
			/* An unrecoverable error occurred */
			log_debug("Failed to fetch ARP entry. Exitting.");
			rte_pktmbuf_free(m);
			return ret;
		}
	}

	ret = net_tx_eth(m, RTE_ETHER_TYPE_IPV4, &dhost);
	assert(!ret); /* can't fail as implemented so far */
	return 0;
}


int net_tx_mbuf_burst(struct rte_mbuf **burst_buffer, u_int32_t burst_size, u_int8_t free_if_fail)
{
	unsigned int ret, i;
	struct rte_ring *ring_out = get_worker_tx_ring();
	ret = rte_ring_enqueue_burst(ring_out, (void *)burst_buffer,
								 burst_size, NULL);
	if (free_if_fail && ret < burst_size)
	{
		log_error("failed to send %u packets. Freeing...", burst_size - ret);
		for (i = ret; i < burst_size; i++)
			rte_pktmbuf_free(burst_buffer[i]);
	}
	return ret;
}