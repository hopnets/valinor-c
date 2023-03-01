#ifndef NET_TX_H
#define NET_TX_H

#include "valinor.h"

int net_tx_eth(struct rte_mbuf *m, uint16_t type, struct rte_ether_addr *dhost);
int net_tx_ip(struct rte_mbuf *m, uint8_t proto, uint32_t daddr);
int net_tx_flowinfo_ip(struct rte_mbuf *m, uint8_t proto, uint32_t daddr);
int net_tx_mbuf_burst(struct rte_mbuf **burst_buffer, u_int32_t burst_size, u_int8_t free_if_fail);

#endif