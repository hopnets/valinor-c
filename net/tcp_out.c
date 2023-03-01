/*
 * tcp_out.c - the egress datapath for TCP
 */

#include <string.h>

#include "chksum.h"

#include "../inc/tcp.h"
#include "../inc/ip.h"



static struct rte_tcp_hdr *
tcp_push_tcphdr(struct tcp_mbuf *m, tcpconn_t *c, uint8_t flags, uint16_t l4len)
{
	struct rte_tcp_hdr *tcphdr;
	uint64_t rcv_nxt_wnd = c->pcb.rcv_nxt_wnd;
	tcp_seq ack = c->tx_last_ack = (uint32_t)rcv_nxt_wnd;
	uint16_t win = c->tx_last_win = rcv_nxt_wnd >> 32;

	/* write the tcp header */
	tcphdr = get_tcp_offset(m->mbuf);
	tcphdr->src_port = rte_cpu_to_be_16(c->e.laddr.port);
	tcphdr->dst_port = rte_cpu_to_be_16(c->e.raddr.port);
	tcphdr->recv_ack = rte_cpu_to_be_32(ack);
	tcphdr->data_off = 0x50;	// 20 bytes
	tcphdr->tcp_flags = flags;
	tcphdr->rx_win = rte_cpu_to_be_16(win);
	tcphdr->sent_seq = rte_cpu_to_be_32(m->seg_seq);
	tcphdr->cksum = 0;
	return tcphdr;
}

/**
 * tcp_tx_raw_rst - send a RST without an established connection
 * @laddr: the local address
 * @raddr: the remote address
 * @seq: the segement's sequence number
 *
 * Returns 0 if successful, otherwise fail.
 */
int tcp_tx_raw_rst(struct netaddr laddr, struct netaddr raddr, tcp_seq seq)
{
	struct rte_tcp_hdr *tcphdr;
	struct rte_mbuf *m;
	struct rte_mempool *mp;
	uint32_t l2_length;
	int ret;
	
	mp = get_worker_mempool();
	m = rte_mbuf_raw_alloc(mp);
	if (unlikely((!m)))
		return -ENOMEM;
	l2_length = sizeof(struct rte_ether_hdr);
	
	m->next = NULL;
	m->nb_segs		= 1;
	m->pkt_len		= m->data_len;
	m->ol_flags		= 0;
	m->vlan_tci		= 0;
	m->vlan_tci_outer	= 0;
	m->l2_len		= l2_length;
	m->l3_len		= sizeof(struct rte_ipv4_hdr);
	m->data_len = l2_length + m->l3_len + sizeof(struct rte_tcp_hdr);
	m->pkt_len		= m->data_len;

	tcphdr = get_tcp_offset(m);


	tcphdr->src_port = rte_cpu_to_be_16(laddr.port);
	tcphdr->dst_port = rte_cpu_to_be_16(raddr.port);
	tcphdr->sent_seq = rte_cpu_to_be_32(seq);
	tcphdr->recv_ack = rte_cpu_to_be_32(0);
	tcphdr->data_off = 0x50;	// 20 bytes
	tcphdr->tcp_flags = TCP_RST;
	tcphdr->rx_win = rte_cpu_to_be_16(0);
	tcphdr->cksum = ipv4_phdr_cksum(IPPROTO_TCP, laddr.ip, raddr.ip,
				      sizeof(struct rte_tcp_hdr));

	/* transmit packet */
	ret = net_tx_ip(m, IPPROTO_TCP, raddr.ip);
	if (unlikely(ret))
		rte_pktmbuf_free(m);
	return ret;
}

/**
 * tcp_tx_raw_rst_ack - send a RST/ACK without an established connection
 * @laddr: the local address
 * @raddr: the remote address
 * @seq: the segment's sequence number
 * @ack: the segment's acknowledgement number
 *
 * Returns 0 if successful, otherwise fail.
 */
int tcp_tx_raw_rst_ack(struct netaddr laddr, struct netaddr raddr,
		       tcp_seq seq, tcp_seq ack)
{
	struct rte_tcp_hdr *tcphdr;
	struct rte_mbuf *m;
	struct rte_mempool *mp;
	uint32_t l2_length;
	int ret;

	mp = get_worker_mempool();
	m = rte_mbuf_raw_alloc(mp);
	if (unlikely((!m)))
		return -ENOMEM;

	l2_length = sizeof(struct rte_ether_hdr);
	
	m->next = NULL;
	m->nb_segs		= 1;
	m->pkt_len		= m->data_len;
	m->ol_flags		= 0;
	m->vlan_tci		= 0;
	m->vlan_tci_outer	= 0;
	m->l2_len		= l2_length;
	m->l3_len		= sizeof(struct rte_ipv4_hdr);
	m->data_len = l2_length + m->l3_len + sizeof(struct rte_tcp_hdr);
	m->pkt_len		= m->data_len;

	/* write the tcp header */
	tcphdr = get_tcp_offset(m);
	tcphdr->src_port = rte_cpu_to_be_16(laddr.port);
	tcphdr->dst_port = rte_cpu_to_be_16(raddr.port);
	tcphdr->sent_seq = rte_cpu_to_be_32(seq);
	tcphdr->recv_ack = rte_cpu_to_be_32(ack);
	tcphdr->data_off = 0x50;	// 20 bytes
	tcphdr->tcp_flags = TCP_RST | TCP_ACK;
	tcphdr->rx_win = rte_cpu_to_be_16(0);
	tcphdr->cksum = ipv4_phdr_cksum(IPPROTO_TCP, laddr.ip, raddr.ip,
				      sizeof(struct rte_tcp_hdr));

	/* transmit packet */
	ret = net_tx_ip(m, IPPROTO_TCP, raddr.ip);
	if (unlikely(ret))
		rte_pktmbuf_free(m);
	return ret;
}

/**
 * tcp_tx_ack - send an acknowledgement and window update packet
 * @c: the connection to send the ACK
 *
 * Returns 0 if succesful, otherwise fail.
 */
int tcp_tx_ack(tcpconn_t *c)
{
	struct tcp_mbuf *m;
	int ret;

	m = net_tx_alloc_mbuf(1);
	if (unlikely(!m))
		return -ENOMEM;

	m->seg_seq = c->pcb.snd_nxt;
	tcp_push_tcphdr(m, c, TCP_ACK, 0);

	/* transmit packet */
	tcp_debug_egress_pkt(c, m);
	ret = net_tx_ip(m->mbuf, IPPROTO_TCP, c->e.raddr.ip);
	if (unlikely(ret)){
		rte_pktmbuf_free(m->mbuf);
		rte_free(m);
	}
	return ret;
}

/**
 * tcp_tx_ctl - sends a control message without data
 * @c: the TCP connection
 * @flags: the control flags (e.g. TCP_SYN, TCP_FIN, etc.)
 *
 * WARNING: The caller must have write exclusive access to the socket or hold
 * @c->lock while write exclusion isn't taken.
 *
 * Returns 0 if successful, -ENOMEM if out memory.
 */
int tcp_tx_ctl(tcpconn_t *c, uint8_t flags)
{
	struct tcp_mbuf *m;
	int ret;

	m = net_tx_alloc_mbuf(1);
	if (unlikely(!m))
		return -ENOMEM;
	m->seg_seq = c->pcb.snd_nxt;
	m->seg_end = c->pcb.snd_nxt + 1;
	m->flags = flags;
	tcp_push_tcphdr(m, c, flags, 0);
	c->pcb.snd_nxt = c->pcb.snd_nxt + 1;
	list_add_tail(&c->txq, &m->link);
	m->timestamp = microtime();
	tcp_debug_egress_pkt(c, m);
	ret = net_tx_ip(m->mbuf, IPPROTO_TCP, c->e.raddr.ip);

	return ret;
}

void mbuf_push_payload(struct rte_mbuf *mbuf, size_t len, const void *buf)
{
	struct rte_tcp_hdr *tcphdr;
	tcphdr = get_tcp_offset(mbuf);
	rte_memcpy(rte_pktmbuf_mtod_offset(mbuf, char *, mbuf->l2_len + mbuf->l3_len + sizeof(struct rte_tcp_hdr)), buf, len);
	mbuf->data_len += len;
	mbuf->pkt_len += len;
}

/**
 * tcp_tx_send - transmit a buffer on a TCP connection
 * @c: the TCP connection
 * @buf: the buffer to transmit
 * @len: the length of the buffer to transmit
 * @push: indicates the data is ready for consumption by the receiver
 *
 * If @push is false, the implementation may buffer some or all of the data for
 * future transmission.
 *
 * WARNING: The caller is responsible for respecting the TCP window size limit.
 * WARNING: The caller must have write exclusive access to the socket or hold
 * @c->lock while write exclusion isn't taken.
 *
 * Returns the number of bytes transmitted, or < 0 if there was an error.
 */
ssize_t tcp_tx_send(tcpconn_t *c, const void *buf, size_t len, bool push)
{
	struct tcp_mbuf *m;
	const char *pos = buf;
	const char *end = pos + len;
	ssize_t ret = 0;
	size_t seglen;
	size_t tcp_effective_mss = TCP_MSS;

	assert(c->pcb.state >= TCP_STATE_ESTABLISHED);
	// assert((c->tx_exclusive == true) || spin_lock_held(&c->lock));

	log_debug("TCP TX send");

	pos = buf;
	end = pos + len;

	/* the main TCP segmenter loop */
	while (pos < end) {
		/* allocate a buffer and copy payload data */
		if (c->tx_pending != NULL) {
			log_warn("TCP TX send: tx pending");
			m = c->tx_pending;
			c->tx_pending = NULL;
			seglen = min((size_t)(end - pos), (size_t)(tcp_effective_mss - m->mbuf->pkt_len)); // TODO: check pkt len
			m->seg_end += seglen;
		} else {
			log_debug("TCP TX send: allocating mbuf");
			m = net_tx_alloc_mbuf(1);
			if (unlikely(!m)) {
				ret = -ENOBUFS;
				break;
			}
			// log_info("TCP TX send: seqlen %u, %u", (unsigned)(end - pos), tcp_effective_mss);
			seglen = min((unsigned)(end - pos), tcp_effective_mss);
			m->seg_seq = c->pcb.snd_nxt;
			m->seg_end = c->pcb.snd_nxt + seglen;
			m->flags = TCP_ACK;

		}

		mbuf_push_payload(m->mbuf, seglen, pos);  // TODO: copy the tcp segment
		c->pcb.snd_nxt = c->pcb.snd_nxt + seglen;
		pos += seglen;

		/* if not pushing, keep the last buffer for later */
		if (!push && pos == end && m->mbuf->pkt_len -
		    sizeof(struct rte_tcp_hdr) < tcp_effective_mss) {    // TODO: check
			log_warn("TCP TX send: not pushing, check this condidion, pos=%d, end=%d, pkt=%u, MSS=%u", pos, end, m->mbuf->pkt_len -
		    					sizeof(struct rte_tcp_hdr), tcp_effective_mss);
			c->tx_pending = m;
			break;
		}

		/* initialize TCP header */
		if (push && pos == end)
			m->flags |= TCP_PUSH;
		tcp_push_tcphdr(m, c, m->flags, m->seg_end - m->seg_seq);

		/* transmit the packet */
		list_add_tail(&c->txq, &m->link);
		// tcp_debug_egress_pkt(c, m);
		m->timestamp = microtime();
		// m->txflags = OLFLAG_TCP_CHKSUM;
		ret = net_tx_ip(m->mbuf, IPPROTO_TCP, c->e.raddr.ip);
	}

	/* if we sent anything return the length we sent instead of an error */
	if (pos - (const char *)buf > 0)
		ret = pos - (const char *)buf;
	return ret;
}

static int tcp_tx_retransmit_one(tcpconn_t *c, struct tcp_mbuf *m)
{
	int ret;
	uint16_t l4len;

	l4len = m->seg_end - m->seg_seq;
	if (m->flags & (TCP_SYN | TCP_FIN))
		l4len--;
	/* handle a partially acknowledged packet */
	uint32_t una = c->pcb.snd_una;
	if (unlikely(wraps_lte(m->seg_end, una))) {
		rte_pktmbuf_free(m->mbuf);
		rte_free(m);
		return 0;
	} else if (unlikely(wraps_lt(m->seg_seq, una))) {
		// mbuf_pull(m, una - m->seg_seq); //TODO
		m->seg_seq = una;
	}

	/* push the TCP header back on (now with fresher ack) */
	tcp_push_tcphdr(m, c, m->flags, l4len);

	/* transmit the packet */
	tcp_debug_egress_pkt(c, m);
	ret = net_tx_ip(m->mbuf, IPPROTO_TCP, c->e.raddr.ip);
	if (unlikely(ret)){
		rte_pktmbuf_free(m->mbuf);
		rte_free(m);
	}
	return ret;
}

/**
 * tcp_tx_fast_retransmit - resend the first pending egress packet
 * @c: the TCP connection in which to send retransmissions
 */
struct tcp_mbuf *tcp_tx_fast_retransmit_start(tcpconn_t *c)
{
	struct tcp_mbuf *m;

	if (c->tx_exclusive)
		return NULL;

	m = list_top(&c->txq, struct tcp_mbuf, link);
	if (m) {
		m->timestamp = microtime();
	}

	return m;
}

void tcp_tx_fast_retransmit_finish(tcpconn_t *c, struct tcp_mbuf *m)
{
	if (m) {
		tcp_tx_retransmit_one(c, m);
		rte_pktmbuf_free(m->mbuf);
		rte_free(m);
	}
}

/**
 * tcp_tx_retransmit - resend any pending egress packets that timed out
 * @c: the TCP connection in which to send retransmissions
 */
void tcp_tx_retransmit(tcpconn_t *c)
{
	struct tcp_mbuf *m;
	uint64_t now = microtime();

	// assert(spin_lock_held(&c->lock) || c->tx_exclusive);

	int ret;

	int count = 0;
	list_for_each(&c->txq, m, link) {
		/* check if the timeout expired */
		if (now - m->timestamp < TCP_RETRANSMIT_TIMEOUT)
			break;

		if (wraps_gte(c->pcb.snd_una, m->seg_end))
			continue;

		m->timestamp = now;
		ret = tcp_tx_retransmit_one(c, m);
		if (ret)
			break;

		if (++count >= TCP_RETRANSMIT_BATCH)
			break;
	}
}
