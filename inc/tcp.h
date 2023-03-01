#ifndef TCP_H
#define TCP_H
/*
 * tcp.h - local header for TCP support
 */

// #include <base/stddef.h>
// #include <base/list.h>
// #include <base/kref.h>
// #include <base/time.h>
// #include <runtime/sync.h>
// #include <runtime/tcp.h>
// #include <net/tcp.h>
// #include <net/mbuf.h>
// #include <net/mbufq.h>
#include "valinor.h"
// #include "core.h"
#include "lock.h"
#include "kref.h"
#include "net_tx.h"
#include "../util/time.h"
#include "../net/chksum.h"
#include "flowinfo.h"
#include "crc.h"


// #include "defs.h"
// #include "waitq.h"

/* adjustable constants */

#define ONE_SECOND	1000000
#define ONE_MS		1000
#define ONE_US		1

#define ETH_MTU			1500
#define TCP_MSS	(ETH_MTU - sizeof(struct rte_ipv4_hdr) - sizeof(struct rte_tcp_hdr))
#define TCP_WIN	((65535 / TCP_MSS) * TCP_MSS)
#define TCP_ACK_TIMEOUT (10 * ONE_MS)
#define TCP_OOQ_ACK_TIMEOUT (300 * ONE_MS)
#define TCP_TIME_WAIT_TIMEOUT (1 * ONE_SECOND) /* FIXME: should be 8 minutes */
#define TCP_RETRANSMIT_TIMEOUT (300 * ONE_MS) /* FIXME: should be dynamic */
#define TCP_FAST_RETRANSMIT_THRESH 3
#define TCP_OOO_MAX_SIZE 2048
#define TCP_RETRANSMIT_BATCH 16


// =e
#define	TCP_FIN		0x01
#define	TCP_SYN		0x02
#define	TCP_RST		0x04
#define	TCP_PUSH	0x08
#define	TCP_ACK		0x10
#define	TCP_URG		0x20
#define	TCP_ECE		0x40
#define	TCP_CWR		0x80
#define	TCP_FLAGS \
	(TCP_FIN|TCP_SYN|TCP_RST|TCP_PUSH|TCP_ACK|TCP_URG|TCP_ECE|TCP_CWR)
#define	PRINT_TCP_FLAGS	"\20\1FIN\2SYN\3RST\4PUSH\5ACK\6URG\7ECE\10CWR"

typedef	uint32_t tcp_seq;
typedef struct tcpqueue tcpqueue_t;

/* connecion states (RFC 793 Section 3.2) */
enum {
	TCP_STATE_SYN_SENT = 0,
	TCP_STATE_SYN_RECEIVED,
	TCP_STATE_ESTABLISHED,
	TCP_STATE_FIN_WAIT1,
	TCP_STATE_FIN_WAIT2,
	TCP_STATE_CLOSE_WAIT,
	TCP_STATE_CLOSING,
	TCP_STATE_LAST_ACK,
	TCP_STATE_TIME_WAIT,
	TCP_STATE_CLOSED,
};

/*
 * Transport protocol layer
 */

enum {
	/* match on protocol, source IP and port */
	TRANS_MATCH_3TUPLE = 0,
	/* match on protocol, source IP and port + dest IP and port */
	TRANS_MATCH_5TUPLE,
};

struct tcp_mbuf {
	struct rte_mbuf *mbuf;
	struct list_node link;
	uint64_t	timestamp;  /* the time the packet was last sent */
	uint32_t	seg_seq;    /* the first seg number */
	uint32_t	seg_end;    /* the last seg number (noninclusive) */
	uint8_t		flags;	    /* which flags were set? */
	atomic_t	ref;	    /* a reference count for the mbuf */
	u_int32_t	payload_len;
};

/* TCP protocol control block (PCB) */
struct tcp_pcb {
	int		state;		/* the connection state */

	/* send sequence variables (RFC 793 Section 3.2) */
	uint32_t	snd_una;	/* send unacknowledged */
	uint32_t	snd_nxt;	/* send next */
	uint32_t	snd_wnd;	/* send window */
	uint32_t	snd_up;		/* send urgent pointer */
	uint32_t	snd_wl1;	/* last window update - seq number */
	uint32_t	snd_wl2;	/* last window update - ack number */
	uint32_t	iss;		/* initial send sequence number */

	/* receive sequence variables (RFC 793 Section 3.2) */
	union {
		struct {
			uint32_t	rcv_nxt;	/* receive next */
			uint32_t	rcv_wnd;	/* receive window */
		};
		uint64_t	rcv_nxt_wnd;
	};
	uint32_t	rcv_up;		/* receive urgent pointer */
	uint32_t	irs;		/* initial receive sequence number */
};

struct trans_entry {
	int			match;
	uint8_t			proto;
	struct netaddr		laddr;
	struct netaddr		raddr;
	const struct trans_ops	*ops;
};

/* the TCP connection struct */
struct tcpconn {
	struct trans_entry	e;
	struct tcp_pcb		pcb;
	struct list_node	global_link;
	struct list_node	queue_link;
	struct list_node	app_link;
	rte_spinlock_t		lock;
	struct kref		ref;
	int			err; /* error code for read(), write(), etc. */

	/* ingress path */
	unsigned int		rx_closed:1;
	unsigned int		rx_exclusive:1;
	// waitq_t			rx_wq;
	struct list_head	rxq_ooo;
	struct list_head	rxq;

	/* egress path */
	unsigned int		tx_closed:1;
	unsigned int		tx_exclusive:1;
	// waitq_t			tx_wq;
	uint32_t		tx_last_ack;
	uint16_t		tx_last_win;
	struct tcp_mbuf		*tx_pending;
	struct list_head	txq;
	bool			do_fast_retransmit;
	uint32_t		fast_retransmit_last_ack;

	/* timeouts */
	uint64_t next_timeout;
	bool			ack_delayed;
	bool			rcv_wnd_full;
	uint64_t		ack_ts;
	uint64_t		time_wait_ts;
	int			rep_acks;
};

typedef struct tcpconn tcpconn_t;

extern tcpconn_t *tcp_conn_alloc(void);
extern int tcp_conn_attach(tcpconn_t *c, struct netaddr laddr,
			   struct netaddr raddr);
extern void tcp_conn_ack(tcpconn_t *c, struct list_head *freeq);
extern void tcp_conn_set_state(tcpconn_t *c, int new_state);
extern void tcp_conn_fail(tcpconn_t *c, int err);
extern void tcp_conn_shutdown_rx(tcpconn_t *c);
extern void tcp_conn_destroy(tcpconn_t *c);

extern void tcp_timer_update(tcpconn_t *c);

int trans_table_add(struct trans_entry *entry);
int trans_table_remove(struct trans_entry *entry);

/**
 * tcp_conn_get - increments the connection ref count
 * @c: the connection to increment
 *
 * Returns @c.
 */
static inline tcpconn_t *tcp_conn_get(tcpconn_t *c)
{
	kref_get(&c->ref);
	return c;
}

extern void tcp_conn_release_ref(struct kref *r);

/**
 * tcp_conn_put - decrements the connection ref count
 * @c: the connection to decrement
 */
static inline void tcp_conn_put(tcpconn_t *c)
{
	// kref_put(&c->ref, tcp_conn_release_ref);
	tcp_conn_destroy(c);
}


/*
 * ingress path
 */

extern void tcp_rx_conn(struct trans_entry *e, struct rte_mbuf *m);
extern tcpconn_t *tcp_rx_listener(struct netaddr laddr, struct rte_mbuf *m);


/*
 * egress path
 */

extern int tcp_tx_raw_rst(struct netaddr laddr, struct netaddr raddr,
			  tcp_seq seq);
extern int tcp_tx_raw_rst_ack(struct netaddr laddr, struct netaddr raddr,
			      tcp_seq seq, tcp_seq ack);
extern int tcp_tx_ack(tcpconn_t *c);
extern int tcp_tx_ctl(tcpconn_t *c, uint8_t flags);
extern ssize_t tcp_tx_send(tcpconn_t *c, const void *buf, size_t len,
			   bool push);
extern void tcp_tx_retransmit(tcpconn_t *c);
extern struct tcp_mbuf *tcp_tx_fast_retransmit_start(tcpconn_t *c);
extern void tcp_tx_fast_retransmit_finish(tcpconn_t *c, struct tcp_mbuf *m);

/*
 * utilities
 */

static inline unsigned int mbuf_length(struct tcp_mbuf *m)
{
	return m->payload_len;
}

static inline struct rte_tcp_hdr *get_tcp_offset(struct rte_mbuf *m)
{
	struct rte_tcp_hdr *tcphdr;
	struct rte_ether_hdr *ethhdr;

	ethhdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	tcphdr = (struct rte_tcp_hdr *) ((char *) ethhdr + m->l2_len + m->l3_len);
	return tcphdr;
}


static inline unsigned int mbuf_pull_data(struct tcp_mbuf *m, void **payload_offset)
{
	struct rte_tcp_hdr *tcphdr;
	struct rte_ipv4_hdr *iphdr;
	u_int16_t udp_dgram_size, payload_size;
	u_int8_t tcp_header_len;
	// rte_pktmbuf_dump(stdout, m->mbuf, 100);
	iphdr = get_ipv4_offset(m->mbuf);
	tcphdr = get_tcp_offset(m->mbuf);
	tcp_header_len = (tcphdr->data_off / 4);
	payload_size = rte_be_to_cpu_16(iphdr->total_length) - m->mbuf->l3_len - tcp_header_len;
	log_debug("Mbuf pull data: tcp_header_len = %u, payload size = %u", tcp_header_len, payload_size);
	*payload_offset = (void *) ((char *)tcphdr + tcp_header_len);
	return payload_size;
}

/* free all mbufs in a linked list */
static inline void mbuf_list_free(struct list_head *h)
{
	struct tcp_mbuf *m;

	while (true) {
		m = list_pop(h, struct tcp_mbuf, link);
		if (!m)
			break;

		rte_pktmbuf_free(m->mbuf);
		rte_free(m);
	}
}

static inline struct tcp_mbuf *net_tx_alloc_mbuf(bool alloc_rte_buf)
{
	struct tcp_mbuf *m;
	struct rte_mempool *mp = get_worker_mempool();

	uint32_t l2_length = sizeof(struct rte_ether_hdr);

	m = (struct tcp_mbuf *) rte_malloc("TCP_MBUF", sizeof(struct tcp_mbuf), 0);
	if (unlikely(!m)) {
		log_warn("net: out of tx buffers");
		return NULL;
	}
	if(alloc_rte_buf){
		m->mbuf = (struct rte_mbuf *) rte_mbuf_raw_alloc(mp);
		if (unlikely(!m->mbuf)) {
			log_warn("net: out of rte_mbufs for tx buffers");
			return NULL;
		}
		m->mbuf->next = NULL;
		m->mbuf->nb_segs		= 1;
		m->mbuf->ol_flags		= 0;
		m->mbuf->vlan_tci		= 0;
		m->mbuf->vlan_tci_outer	= 0;
		m->mbuf->l2_len		= l2_length;
		m->mbuf->l3_len		= sizeof(struct rte_ipv4_hdr);
		m->mbuf->data_len = l2_length + m->mbuf->l3_len + sizeof(struct rte_tcp_hdr);
		m->mbuf->pkt_len		= m->mbuf->data_len;

	}
	return m;
}

/**
 * Process the pseudo-header checksum of an IPv4 header.
 *
 * The checksum field must be set to 0 by the caller.
 *
 * @param ipv4_hdr
 *   The pointer to the contiguous IPv4 header.
 * @return
 *   The non-complemented checksum to set in the L4 header.
 */
static inline uint16_t
ipv4_phdr_cksum(uint8_t proto, uint32_t saddr, uint32_t daddr, uint16_t l4len)
{
	struct ipv4_psd_header {
		uint32_t saddr;    /* IP address of source host. */
		uint32_t daddr;    /* IP address of destination host. */
		uint8_t  zero;     /* zero. */
		uint8_t  proto;    /* L4 protocol type. */
		uint16_t len;      /* L4 length. */
	} psd_hdr;
	log_debug("ipv4_phdr_cksum %x %x %u", saddr, daddr, l4len);

	psd_hdr.saddr = rte_cpu_to_be_32(saddr);
	psd_hdr.daddr = rte_cpu_to_be_32(daddr);
	psd_hdr.zero = 0;
	psd_hdr.proto = proto;
	psd_hdr.len = rte_cpu_to_be_16(l4len);
	return raw_cksum(&psd_hdr, sizeof(psd_hdr));
}

/**
 * trans_init_3tuple - initializes a transport layer entry (3-tuple match)
 * @e: the entry to initialize
 * @proto: the IP protocol
 * @ops: operations to handle matching flows
 * @laddr: the local address
 */
static inline void trans_init_3tuple(struct trans_entry *e, uint8_t proto,
				     const struct trans_ops *ops,
				     struct netaddr laddr)
{
	e->match = TRANS_MATCH_3TUPLE;
	e->proto = proto;
	e->laddr = laddr;
	e->ops = ops;
}

/**
 * trans_init_5tuple - initializes a transport layer entry (5-tuple match)
 * @e: the entry to initialize
 * @proto: the IP protocol
 * @ops: operations to handle matching flows
 * @laddr: the local address
 * @raddr: the remote address
 */
static inline void trans_init_5tuple(struct trans_entry *e, uint8_t proto,
				     const struct trans_ops *ops,
				     struct netaddr laddr, struct netaddr raddr)
{
	e->match = TRANS_MATCH_5TUPLE;
	e->proto = proto;
	e->laddr = laddr;
	e->raddr = raddr;
	e->ops = ops;
}

void tcp_rx_closed(struct rte_mbuf *m);

typedef struct tcpconn tcpconn_t;

/**
 * wraps_lt - a < b ?
 *
 * This comparison is safe against unsigned wrap around.
 */
static inline bool wraps_lt(uint32_t a, uint32_t b)
{
        return (int32_t)(a - b) < 0;
}

/**
 * wraps_lte - a <= b ?
 *
 * This comparison is safe against unsigned wrap around.
 */
static inline bool wraps_lte(uint32_t a, uint32_t b)
{
        return (int32_t)(a - b) <= 0;
}


/**
 * wraps_gt - a > b ?
 *
 * This comparison is safe against unsigned wrap around.
 */
static inline bool wraps_gt(uint32_t a, uint32_t b)
{
        return (int32_t)(b - a) < 0;
}

/**
 * wraps_gte - a >= b ?
 *
 * This comparison is safe against unsigned wrap around.
 */
static inline bool wraps_gte(uint32_t a, uint32_t b)
{
        return (int32_t)(b - a) <= 0;
}

/**
 * swapvars - swaps the contents of two values
 */
#define swapvars(a, b) \
	do { typeof(a) _t = (a); (a) = (b); (b) = _t; } while(0)


/*
 * debugging
 */

static inline void tcp_debug_egress_pkt(tcpconn_t *c, struct tcp_mbuf *m)
{
	log_trace("TCP DEBUG %lu %u", c->ack_ts, m->mbuf->hash.rss);
}
static inline void tcp_debug_ingress_pkt(tcpconn_t *c, struct rte_mbuf *m)
{
	log_trace("TCP DEBUG %lu %u", c->ack_ts, m->hash.rss);
}
static inline void tcp_debug_state_change(tcpconn_t *c, int last, int next)
{
	log_trace("TCP DEBUG %lu %u %u", c->ack_ts, last, next);
}

#endif