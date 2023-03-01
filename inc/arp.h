#include "valinor.h"


struct eth_addr {
	uint8_t addr[6];
} __packed;

int arp_init(void);

int arp_lookup(uint32_t daddr, struct rte_ether_addr *dhost, struct rte_mbuf *m);

int arp_table_add(char *IP, char *MAC);