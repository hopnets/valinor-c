#include "../inc/arp.h"

int arp_init(void)
{
    struct rte_hash_parameters hash_params = {0};

    hash_params.name = "arp_table";
	hash_params.entries = 25;
	hash_params.key_len = 4;
	hash_params.hash_func = rte_jhash;
	hash_params.hash_func_init_val = 0;
	hash_params.socket_id = rte_socket_id();
	arp_table = rte_hash_create(&hash_params);
    if (arp_table == NULL)
        return -1;
    return 0;

}

int arp_lookup(uint32_t daddr, struct rte_ether_addr *dhost, struct rte_mbuf *m)
{
    int ret;
    void *data;
    ret = rte_hash_lookup_data(arp_table, &daddr, &data);
    if (unlikely(ret < 0))
    {
        log_debug("IP address not found in ARP table %x", daddr);
        // TODO: implement ARP resolution later.
        return -1;
    }
    // dhost = (struct rte_ether_hdr *)data;
    log_debug("Found ARP entry for %u: %x %x %x %x %x %x", daddr, dhost->addr_bytes[0], dhost->addr_bytes[1]
            , dhost->addr_bytes[2], dhost->addr_bytes[3], dhost->addr_bytes[4], dhost->addr_bytes[5]);
    rte_ether_addr_copy(data, dhost);

    return 1;
}

int arp_table_add(char *IP, char *MAC)
{
    uint32_t daddr;
    int ret;
    struct eth_addr *mac_addr = (struct eth_addr *) rte_malloc("ARP_TABLE_ENTRY_VALUE", sizeof(struct eth_addr), 0);
    if(mac_addr == NULL)
        rte_exit(EXIT_FAILURE, "Failed to allocate memory for ARP table entry.");
    ret = str_to_ip(IP, &daddr);
    log_debug("converted %s to %x", IP, daddr);
    if(ret < 0)
    {
        log_error("FAILED to parse IP address.");
        return ret;
    }
    sscanf(MAC, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac_addr->addr[0], &mac_addr->addr[1], &mac_addr->addr[2], 
                    &mac_addr->addr[3], &mac_addr->addr[4], &mac_addr->addr[5]);
	ret = rte_hash_add_key_data(arp_table, &daddr, mac_addr);
	if (ret < 0)
	{
		log_fatal("Failed to add the MAC address provided in the config to hash table.");
		rte_exit(EXIT_FAILURE, "Cannot proceed.\n");
	}
    return 0;
}