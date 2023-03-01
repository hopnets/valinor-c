#ifndef APP_H
#define APP_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include "valinor.h"

#define BACKLOG 1024
#define PORT    1111
#define APP_IP  "10.1.1.1"
#define APP_IDLE_THRESHOLD 1000

struct tcpqueue;
typedef struct tcpqueue tcpqueue_t;
struct tcpconn;
typedef struct tcpconn tcpconn_t;

struct app_context {
    uint32_t app_ip;
    uint16_t app_port;
    uint32_t dst_ip;
    uint16_t dst_port;
    uint32_t *idle;
    uint32_t *commands;
    uint32_t redis_key;
    struct event_base *base;
	redisContext **c_pool;
    struct rte_ring *ts_ring;
    struct app_stats *app_stats;
};

struct timestamp_entry {
    uint32_t key;
    uint64_t ingress_mac;
    uint64_t ingress_global;
    uint32_t enqueue;
    uint32_t enqueue_delta;
    uint64_t egress_global;
    uint64_t egress_tx;
    uint16_t packet_length;
    uint32_t saddr;
    uint32_t daddr;
    uint16_t sport;
    uint16_t dport;
};


void hexDump (const char * desc, const void * addr, const int len);

int app_receive_udp_callback(struct udp_flow_id *udp_flow, void *data, u_int32_t size);

int app_initiate_callback(struct app_context *app);

int app_logic_callback(struct app_context *app);

int app_worker_init(unsigned int id, struct app_context *app);

int app_post_init_callback(struct app_context *app);

int app_periodic_callback(struct app_context *app, uint32_t uid);

extern int tcp_dial(struct netaddr laddr, struct netaddr raddr,
		    tcpconn_t **c_out);
extern int tcp_listen(struct netaddr laddr, int backlog, tcpqueue_t **q_out);
extern int tcp_accept(tcpqueue_t *q, tcpconn_t **c_out);
extern void tcp_qshutdown(tcpqueue_t *q);
extern void tcp_qclose(tcpqueue_t *q);
extern struct netaddr tcp_local_addr(tcpconn_t *c);
extern struct netaddr tcp_remote_addr(tcpconn_t *c);
extern ssize_t tcp_read(tcpconn_t *c, void *buf, size_t len);
extern ssize_t tcp_write(tcpconn_t *c, const void *buf, size_t len);
extern ssize_t tcp_readv(tcpconn_t *c, const struct iovec *iov, int iovcnt);
extern ssize_t tcp_writev(tcpconn_t *c, const struct iovec *iov, int iovcnt);
extern int tcp_shutdown(tcpconn_t *c, int how);
extern void tcp_abort(tcpconn_t *c);
extern void tcp_close(tcpconn_t *c);

static unsigned int counter = 0;

#endif