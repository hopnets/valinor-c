/*
 * tcp_in.c - the ingress datapath for TCP
 *
 * Based on RFC 793 and RFC 1122 (errata).
 *
 * FIXME: We do too little to prevent heavy fragmentation in the out-of-order
 * RX queue.
 */

#include "../inc/ip.h"
#include "../inc/tcp.h"

/* four cases for the acceptability test for an incoming segment */
static bool is_acceptable(tcpconn_t *c, uint32_t len, uint32_t seq)
{
	if (len == 0 && c->pcb.rcv_wnd == 0) {
		return seq == c->pcb.rcv_nxt;
	} else if (len == 0 && c->pcb.rcv_wnd > 0) {
		return wraps_lte(c->pcb.rcv_nxt, seq) &&
		       wraps_lt(seq, c->pcb.rcv_nxt + c->pcb.rcv_wnd);
	} else if (len > 0 && c->pcb.rcv_wnd == 0) {
		return false;
	}

	/* (len > 0 && c->rcv_wnd > 0) */
	return (wraps_lte(c->pcb.rcv_nxt, seq) &&
		wraps_lt(seq, c->pcb.rcv_nxt + c->pcb.rcv_wnd)) ||
	       (wraps_lte(c->pcb.rcv_nxt, seq + len - 1) &&
		wraps_lt(seq + len - 1, c->pcb.rcv_nxt + c->pcb.rcv_wnd));
}

/* is the TX window full? */
static bool is_snd_full(tcpconn_t *c)
{
	return wraps_lte(c->pcb.snd_una + c->pcb.snd_wnd, c->pcb.snd_nxt);
}

/* see reset generation (RFC 793) */
static void send_rst(tcpconn_t *c, bool acked, uint32_t seq, uint32_t ack,
		     uint32_t len)
{
	if (acked) {
		tcp_tx_raw_rst(c->e.laddr, c->e.raddr, ack);
		return;
	}
	tcp_tx_raw_rst_ack(c->e.laddr, c->e.raddr, 0, seq + len);
}

static void tcp_rx_append_text(tcpconn_t *c, struct tcp_mbuf *m)
{
	uint32_t len;
	void  *payload_offset;

	/* verify assumptions enforced by acceptability testing */
	assert(wraps_lte(m->seg_seq, c->pcb.rcv_nxt));
	assert(wraps_gt(m->seg_end, c->pcb.rcv_nxt));

	/* does the next receive octet clip the head of the text? */
	if (wraps_lt(m->seg_seq, c->pcb.rcv_nxt)) {
		len = c->pcb.rcv_nxt - m->seg_seq;
		// mbuf_pull(m, len); // TODO: get data somehow from the begining of the mbuf
		m->seg_seq += len;
	}

	

	/* does the receive window clip the tail of the text? */
	if (wraps_lt(c->pcb.rcv_nxt + c->pcb.rcv_wnd, m->seg_end)) {
		log_warn("MBUF_TRIM needed!");
		len = m->seg_end - (c->pcb.rcv_nxt + c->pcb.rcv_wnd);
		// mbuf_trim(m, len); // // TODO: get data somehow from the end of the mbuf
		m->seg_end = c->pcb.rcv_nxt + c->pcb.rcv_wnd;
	}
	log_debug("Pulling the data offset");
	m->payload_len = mbuf_pull_data(m, &payload_offset);
	/* enqueue the text */
	assert(c->pcb.rcv_wnd >= m->seg_end - m->seg_seq);
	uint64_t nxt_wnd =  (uint64_t)m->seg_end | ((uint64_t)(c->pcb.rcv_wnd - (m->seg_end - m->seg_seq)) << 32);
	c->pcb.rcv_nxt_wnd = nxt_wnd;
	if (c->pcb.rcv_wnd == 0)
		c->rcv_wnd_full = true;
	list_add_tail(&c->rxq, &m->link);
}

/* process RX text segments, returning true if @m is used for text */
static bool tcp_rx_text(tcpconn_t *c, struct tcp_mbuf *m, bool *wake)
{
	struct tcp_mbuf *pos;

	/* don't accept any text if the receive window is zero */
	if (c->pcb.rcv_wnd == 0)
		return false;

	if (wraps_lte(m->seg_seq, c->pcb.rcv_nxt)) {
		/* we got the next in-order segment */
		if ((m->flags & (TCP_PUSH | TCP_FIN)) > 0)
			*wake = true;
		tcp_rx_append_text(c, m);
	} else {
		/* we got an out-of-order segment */
		int size = 0;
		list_for_each(&c->rxq_ooo, pos, link) {
			if (wraps_lt(m->seg_seq, pos->seg_seq)) {
				list_add_before(&pos->link, &m->link);
				goto drain;
			} else if (wraps_lte(m->seg_end, pos->seg_end)) {
				return false;
			}
			size++;
		}

		if (size >= TCP_OOO_MAX_SIZE)
			 return false;

 		list_add_tail(&c->rxq_ooo, &m->link);
	}

drain:
	/* attempt to drain the out-of-order RX queue */
	while (true) {
		pos = list_top(&c->rxq_ooo, struct tcp_mbuf, link);
		if (!pos)
			break;

		/* has the segment been fully received already? */
		if (wraps_lte(pos->seg_end, c->pcb.rcv_nxt)) {
			list_del(&pos->link);
			rte_pktmbuf_free(pos->mbuf);
			rte_free(pos);
			continue;
		}

		/* is the segment still out-of-order? */
		if (wraps_gt(pos->seg_seq, c->pcb.rcv_nxt))
			break;

		/* we got the next in-order segment */
		list_del(&pos->link);
		if ((m->flags & (TCP_PUSH | TCP_FIN)) > 0)
			*wake = true;
		tcp_rx_append_text(c, pos);
	}

	if (c->pcb.rcv_wnd == 0)
		*wake = true;

	return true;
}

/* handles ingress packets for TCP connections */
void tcp_rx_conn(struct trans_entry *e, struct rte_mbuf *m)
{
	tcpconn_t *c = container_of(e, tcpconn_t, e);
	struct list_head q;
	// thread_t *rx_th = NULL;
	struct tcp_mbuf *retransmit = NULL;
	struct tcp_mbuf *tcp_m;
	const struct rte_ipv4_hdr *iphdr;
	const struct rte_tcp_hdr *tcphdr;
	uint32_t seq, ack, len, snd_nxt, hdr_len;
	uint16_t win;
	bool do_ack = false, do_drop = true;
	int ret;

	list_head_init(&q);
	snd_nxt = c->pcb.snd_nxt;

	/* find header offsets */
	iphdr = get_ipv4_offset(m);
	tcphdr = get_tcp_offset(m);
	if (unlikely(!tcphdr)) {
		log_warn("Couldn't find TCP header for the packet. Dropping...");
		rte_pktmbuf_free(m);
		return;
	}

	/* parse header */
	seq = rte_be_to_cpu_32(tcphdr->sent_seq);
	ack = rte_be_to_cpu_32(tcphdr->recv_ack);
	win = rte_be_to_cpu_16(tcphdr->rx_win);

	hdr_len = tcphdr->data_off / 4;
	if (unlikely(hdr_len < sizeof(struct rte_tcp_hdr))) {
		log_warn("Wrong TCP header length. Dropping...");
		rte_pktmbuf_free(m);
		return;
	}
	len = rte_be_to_cpu_16(iphdr->total_length) - sizeof(*iphdr) - hdr_len;
	if (unlikely(len > m->pkt_len)) {
		log_warn("Wrong payload length (%u) - (%u) - (%u) vs (%u)(%u). Dropping...", rte_be_to_cpu_16(iphdr->total_length), sizeof(*iphdr), hdr_len, m->data_len, m->pkt_len);
		rte_pktmbuf_dump(stdout, m, m->pkt_len);
		rte_pktmbuf_free(m);
		return;
	}
	if (unlikely((tcphdr->tcp_flags & TCP_FIN) > 0))
		len++;
	// mbuf_pull(m, hdr_len - sizeof(struct rte_tcp_hdr)); /* strip off options */
	// TODO: not supporting options for now

	rte_spinlock_lock(&c->lock);

	if (c->pcb.state == TCP_STATE_CLOSED) {
		if ((tcphdr->tcp_flags & TCP_RST) == 0)
			send_rst(c, false, seq, ack, len);
		goto done;
	}

	if (c->pcb.state == TCP_STATE_SYN_SENT) {
		if ((tcphdr->tcp_flags & TCP_ACK) > 0) {
			if (wraps_lte(ack, c->pcb.iss) ||
			    wraps_gt(ack, snd_nxt)) {
				send_rst(c, false, seq, ack, len);
				goto done;
			}
			if ((tcphdr->tcp_flags & TCP_RST) > 0) {
				/* check if the ack is valid */
				if (wraps_lte(c->pcb.snd_una, ack) &&
				    wraps_lte(ack, snd_nxt)) {
					tcp_conn_fail(c, ECONNRESET);
					goto done;
				}
			}
		} else if ((tcphdr->tcp_flags & TCP_RST) > 0) {
			goto done;
		}
		if ((tcphdr->tcp_flags & TCP_SYN) > 0) {
			c->pcb.rcv_nxt = seq + 1;
			c->pcb.irs = seq;
			if ((tcphdr->tcp_flags & TCP_ACK) > 0) {
				c->pcb.snd_una = ack;
				tcp_conn_ack(c, &q);
			}
			if (wraps_gt(c->pcb.snd_una, c->pcb.iss)) {
				do_ack = true;
				c->pcb.snd_wnd = win > 1 ? win - 2 : 0; // reserve 1 byte for FIN and one byte for the sequence number on an RST packet
				c->pcb.snd_wl1 = seq;
				c->pcb.snd_wl2 = ack;
				tcp_conn_set_state(c, TCP_STATE_ESTABLISHED);
			} else {
				ret = tcp_tx_ctl(c, TCP_SYN | TCP_ACK);
				if (unlikely(ret)) {
					goto done; /* feign packet loss */
				}
				tcp_conn_set_state(c, TCP_STATE_SYN_RECEIVED);
			}
		}
		goto done;
	}

	/*
	 * TCP_STATE_SYN_RECEIVED || TCP_STATE_ESTABLISHED ||
	 * TCP_STATE_FIN_WAIT1 || TCP_STATE_FIN_WAIT2 ||
	 * TCP_STATE_CLOSE_WAIT || TCP_STATE_CLOSING ||
	 * TCP_STATE_LAST_ACK || TCP_STATE_TIME_WAIT
	 */

	/* step 1 - acceptability testing */
	if (!is_acceptable(c, len, seq)) {
		do_ack = (tcphdr->tcp_flags & TCP_RST) == 0;
		goto done;
	}

	/* step 2 - RST */
	if ((tcphdr->tcp_flags & TCP_RST) > 0) {
		tcp_conn_fail(c, ECONNRESET);
		goto done;
	}

	/* step 3 - security checks skipped */

	/* step 4 - SYN */
	if ((tcphdr->tcp_flags & TCP_SYN) > 0) {
		send_rst(c, (tcphdr->tcp_flags & TCP_ACK) > 0, seq, ack, len);
		tcp_conn_fail(c, ECONNRESET);
		goto done;
	}

	/* step 5 - ACK */
	if ((tcphdr->tcp_flags & TCP_ACK) == 0) {
		goto done;
	}
	if (c->pcb.state == TCP_STATE_SYN_RECEIVED) {
		if (!(wraps_lte(c->pcb.snd_una, ack) &&
		      wraps_lte(ack, snd_nxt))) {
			send_rst(c, true, seq, ack, len);
			do_drop = true;
			goto done;
		}
		c->pcb.snd_wnd = win > 1 ? win - 2 : 0; // reserve 1 byte for FIN and one byte for the sequence number on an RST packet
		c->pcb.snd_wl1 = seq;
		c->pcb.snd_wl2 = ack;
		log_debug("TCP conn transitioning to ESTABLISHED");
		tcp_conn_set_state(c, TCP_STATE_ESTABLISHED);
	}
	/*
	 * Detect a duplicate ACK if:
	 * 1. The ACK number is the same as the largest seen.
	 * 2. There is unacknowledged data pending.
	 * 3. There is no data payload included with the ACK.
	 * 4. There is no window update.
	 */
	if (ack == c->pcb.snd_una &&
	    c->pcb.snd_una != c->pcb.snd_nxt &&
	    len == 0) {
		c->rep_acks++;
		if (c->rep_acks >= TCP_FAST_RETRANSMIT_THRESH) {
			if (c->tx_exclusive) {
				c->do_fast_retransmit = true;
				c->fast_retransmit_last_ack = ack;
			} else {
				retransmit = tcp_tx_fast_retransmit_start(c);
			}
			c->rep_acks = 0;
		}
	}
	bool snd_was_full = is_snd_full(c);
	if (wraps_lte(c->pcb.snd_una, ack) &&
	    wraps_lte(ack, snd_nxt)) {
		if (c->pcb.snd_una != ack)
			c->rep_acks = 0;
		c->pcb.snd_una = ack;
		tcp_conn_ack(c, &q);
	} else if (wraps_gt(ack, snd_nxt)) {
		do_ack = true;
		goto done;
	}
	/* should we update the send window? */
	if (wraps_lt(c->pcb.snd_wl1, seq) ||
	    (c->pcb.snd_wl1 == seq &&
	     wraps_lte(c->pcb.snd_wl2, ack))) {
		c->pcb.snd_wnd = win > 1 ? win - 2 : 0; // reserve 1 byte for FIN and one byte for the sequence number on an RST packet
		c->pcb.snd_wl1 = seq;
		c->pcb.snd_wl2 = ack;
		c->rep_acks = 0;
	}
	// if (snd_was_full && !is_snd_full(c))
	// 	waitq_release_start(&c->tx_wq, &waiters);

	if (c->pcb.state == TCP_STATE_FIN_WAIT1 &&
	    c->pcb.snd_una == snd_nxt) {
		tcp_conn_set_state(c, TCP_STATE_FIN_WAIT2);
	} else if (c->pcb.state == TCP_STATE_CLOSING &&
		   c->pcb.snd_una == snd_nxt) {
		c->time_wait_ts = microtime();
		tcp_conn_set_state(c, TCP_STATE_TIME_WAIT);
	} else if (c->pcb.state == TCP_STATE_LAST_ACK &&
		   c->pcb.snd_una == snd_nxt) {
		tcp_conn_set_state(c, TCP_STATE_CLOSED);
		tcp_conn_put(c); /* safe because RCU + preempt is disabled */
		goto done;
	}

	/* step 6 - URG support skipped */

	/* step 7 - segment text */
	tcp_m = net_tx_alloc_mbuf(0);
	tcp_m->mbuf = m;
	if (len > 0 &&
	    (c->pcb.state == TCP_STATE_ESTABLISHED ||
	     c->pcb.state == TCP_STATE_FIN_WAIT1 ||
	     c->pcb.state == TCP_STATE_FIN_WAIT2)) {
		bool wake = false;
		tcp_m->seg_seq = seq;
		tcp_m->seg_end = seq + len;
		tcp_m->flags = tcphdr->tcp_flags;

#ifdef TCP_RX_STATS
		uint64_t before_tsc = rdtsc();
		do_drop = !tcp_rx_text(c, m, &wake);
		STAT(RX_TCP_TEXT_CYCLES) += rdtsc() - before_tsc;
#else
		do_drop = !tcp_rx_text(c, tcp_m, &wake);
#endif

		if (!c->ack_delayed) {
			c->ack_delayed = true;
			c->ack_ts = microtime();
		}
		do_ack |= !list_empty(&c->rxq_ooo);
	}

	/* step 8 - FIN */
	if (likely((tcphdr->tcp_flags & TCP_FIN) == 0))
		goto done;
	if (c->pcb.state == TCP_STATE_SYN_RECEIVED ||
	    c->pcb.state == TCP_STATE_ESTABLISHED) {
		tcp_conn_set_state(c, TCP_STATE_CLOSE_WAIT);
	} else if (c->pcb.state == TCP_STATE_FIN_WAIT1) {
		assert(c->pcb.snd_una != snd_nxt);
		tcp_conn_set_state(c, TCP_STATE_CLOSING);
	} else if (c->pcb.state == TCP_STATE_FIN_WAIT2) {
		c->time_wait_ts = microtime();
		do_ack = true;
		tcp_conn_set_state(c, TCP_STATE_TIME_WAIT);
	}

done:
	tcp_timer_update(c);
	tcp_debug_ingress_pkt(c, m);
	rte_spinlock_unlock(&c->lock);

	/* deferred work (delayed until after the lock was dropped) */
	mbuf_list_free(&q);
	tcp_tx_fast_retransmit_finish(c, retransmit);
	if (do_ack)
		tcp_tx_ack(c);
	if (do_drop)
		rte_pktmbuf_free(m);
}

/* handles ingress packets for TCP listener queues */
tcpconn_t *tcp_rx_listener(struct netaddr laddr, struct rte_mbuf *m)
{
	struct netaddr raddr;
	const struct rte_ipv4_hdr *iphdr;
	const struct rte_tcp_hdr *tcphdr;
	tcpconn_t *c;
	int ret;

	/* find header offsets */
	iphdr = get_ipv4_offset(m);
	if (unlikely(!iphdr))
		return NULL;
	tcphdr = get_tcp_offset(m);
	if (unlikely(!tcphdr))
		return NULL;

	/* calculate local and remote network addresses */
	raddr.ip = rte_cpu_to_be_32(iphdr->src_addr);
	raddr.port = rte_cpu_to_be_16(tcphdr->src_port);
	/* do exactly what RFC 793 says */
	if ((tcphdr->tcp_flags & TCP_RST) > 0)
		return NULL;
	if ((tcphdr->tcp_flags & TCP_ACK) > 0) {
		tcp_tx_raw_rst(laddr, raddr, rte_cpu_to_be_32(tcphdr->recv_ack));
		return NULL;
	}
	if ((tcphdr->tcp_flags & TCP_SYN) == 0)
		return NULL;

	/* TODO: the spec requires us to enqueue but not post any data */
	if (rte_be_to_cpu_16(iphdr->total_length) - sizeof(*iphdr) != tcphdr->data_off / 4)
		return NULL;

	/* we have a valid SYN packet, initialize a new connection */
	c = tcp_conn_alloc();
	if (unlikely(!c))
		return NULL;
	c->pcb.irs = rte_be_to_cpu_32(tcphdr->sent_seq);
	c->pcb.rcv_nxt = c->pcb.irs + 1;

	/*
	 * attach the connection to the transport layer. From this point onward
	 * ingress packets can be dispatched to the connection.
	 */
	ret = tcp_conn_attach(c, laddr, raddr);
	if (unlikely(ret)) {
		free(c);
		return NULL;
	}
	tcp_debug_ingress_pkt(c, m);
	/* finally, send a SYN/ACK to the remote host */
	rte_spinlock_lock(&c->lock);
	ret = tcp_tx_ctl(c, TCP_SYN | TCP_ACK);
	if (unlikely(ret)) {
		rte_spinlock_unlock(&c->lock);
		tcp_conn_destroy(c);
		return NULL;
	}

	tcp_conn_get(c); /* take a ref for the state machine */
	tcp_conn_set_state(c, TCP_STATE_SYN_RECEIVED);
	rte_spinlock_unlock(&c->lock);

	return c;
}

void tcp_rx_closed(struct rte_mbuf *m)
{
	struct netaddr l, r;
	uint32_t len, l2_len, l3_len;
	const struct rte_ether_hdr *ethhdr;
	const struct rte_ipv4_hdr *iphdr;
	const struct rte_tcp_hdr *tcphdr;

	ethhdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	l2_len = sizeof(*ethhdr);

	iphdr = (struct rte_ipv4_hdr *) ((char *) ethhdr + l2_len);
	l3_len = sizeof(*iphdr);
	tcphdr = (struct rte_tcp_hdr *) ((char *) iphdr + l3_len);
	if (!tcphdr)
		return;

	if ((tcphdr->tcp_flags & TCP_RST) > 0)
		return;

	l.ip = rte_cpu_to_be_32(iphdr->dst_addr);
	l.port = rte_cpu_to_be_16(tcphdr->dst_port);

	r.ip = rte_cpu_to_be_32(iphdr->src_addr);
	r.port = rte_cpu_to_be_16(tcphdr->src_port);

	if ((tcphdr->tcp_flags & TCP_ACK) > 0) {
		tcp_tx_raw_rst(l, r, rte_cpu_to_be_32(tcphdr->recv_ack));
	} else {
		len = rte_cpu_to_be_16(iphdr->total_length) - sizeof(*iphdr) - tcphdr->data_off * 4;
		tcp_tx_raw_rst_ack(l, r, 0, rte_cpu_to_be_32(tcphdr->sent_seq) + len);
	}
}
