#ifndef TS_H
#define TS_H

#include "valinor.h"
#include "core.h"

#define VALINOR_TS_HDR_LENGTH 46

struct valinor_ts_hdr {
    uint64_t protocol:8,
             pad1:8,
             ingress_mac:48;
    uint64_t pad2:16,
             ingress_global:48;
    uint32_t enqueue;
    uint32_t enqueue_delta;
    uint64_t pad5:16,
             egress_global:48;
    uint64_t pad6:16,
             egress_tx:48;
    uint16_t packet_length;
    uint16_t pad7;
} __attribute__((__packed__));

// struct timestamp_entry {
//     uint32_t key;
//     uint64_t ingress_mac;
//     uint64_t ingress_global;
//     uint32_t enqueue;
//     uint32_t enqueue_delta;
//     uint64_t egress_global;
//     uint64_t egress_tx;
//     uint16_t packet_length;
// };

void process_valinor_ts(struct rte_mbuf *m, struct rte_ether_hdr *ethhdr, struct rte_ipv4_hdr *iphdr, struct rte_ring *ts_ring);



#endif