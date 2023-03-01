// Copyright [2021] Erfan Sharafzadeh

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// 	http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "inc/valinor.h"
#include "inc/core.h"
#include "util/frozen.h"

unsigned int portmask;
unsigned int redis_key;
unsigned int verbosity_level;
char config_file[100];
volatile uint8_t quit_signal;

static struct rte_mempool *mbuf_pool;
struct net_conf conf;
struct list_head tcp_conns;

static struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
		.mq_mode = ETH_MQ_RX_RSS | ETH_MQ_RX_RSS_FLAG,
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = 0x7ef8 // 0x3afbc //  0x7ef8,
		},
	},
	// .txmode = {
	// 	.offloads = DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM | DEV_TX_OFFLOAD_TCP_CKSUM,
	// }
};

static struct rte_hash *app_mac_hash;

struct worker_thread_args
{
	struct rte_ring *ring_in;
	struct rte_ring *ring_out;
	struct rte_ring *completion_ring;
	struct app_context *app;
};

struct send_thread_args
{
	struct rte_ring *ring_in;
	struct rte_reorder_buffer *buffer;
};

/* per worker lcore stats */
struct wkr_stats_per
{
	uint64_t deq_pkts;
	uint64_t enq_pkts;
	uint64_t enq_failed_pkts;
} __rte_cache_aligned;

static struct wkr_stats_per wkr_stats[RTE_MAX_LCORE] = {{0}};

int parse_app_conf(struct net_conf *conf);
extern int time_init(void);

/**
 * Get the last enabled lcore ID
 *
 * @return
 *   The last enabled lcore ID.
 */
static unsigned int
get_last_lcore_id(void)
{
	int i;

	for (i = RTE_MAX_LCORE - 1; i >= 0; i--)
		if (rte_lcore_is_enabled(i))
			return i;
	return 0;
}

/**
 * Get the previous enabled lcore ID
 * @param id
 *  The current lcore ID
 * @return
 *   The previous enabled lcore ID or the current lcore
 *   ID if it is the first available core.
 */
static unsigned int
get_previous_lcore_id(unsigned int id)
{
	int i;

	for (i = id - 1; i >= 0; i--)
		if (rte_lcore_is_enabled(i))
			return i;
	return id;
}

static inline void
pktmbuf_free_bulk(struct rte_mbuf *mbuf_table[], unsigned n)
{
	unsigned int i;

	for (i = 0; i < n; i++)
		rte_pktmbuf_free(mbuf_table[i]);
}

/* display usage */
static void
print_usage(const char *prgname)
{
	printf("%s [EAL options] -- -p PORTMASK -c APP_CONF_FILE [-k REDIS_KEY] [-v [LOG_LEVEL]]\n"
		   "  -p PORTMASK: hexadecimal bitmask of DPDK ports to configure (Required)\n"
		   "  -c APP_CONF_FILE: Defines attributes required by application. Refer to server.json file. (Required)\n"
		   "  -k REDIS_KEY: Key used in Redis to store timestamps. (Optional) (Default=0)\n"
		   "  -v [LOG_LEVEL]: Set verbosity level. 0->Trace, 1->Debug, no-arg->Debug, 2->Info, 3->Warning, 4->Error. (Optional) (Default=2)\n",
		   prgname);
}

static int
parse_portmask(const char *portmask)
{
	unsigned long pm;
	char *end = NULL;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (pm == 0)
		return -1;

	return pm;
}

/* Parse the argument given in the command line of the application */
static int
parse_args(int argc, char **argv)
{
	int opt;
	int option_index;
	char **argvopt;
	char *prgname = argv[0];
	static struct option lgopts[] = {
		{"portmask", 1, 0, 0},
		{"app-config", 1, 0, 0},
		{"redis-key", 1, 0, 0},
		{"verbose", 2, 0, 1},
		{"help", 0, 0, 0},
		{NULL, 0, 0, 0}};

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "p:c:k:vh",
							  lgopts, &option_index)) != EOF)
	{
		switch (opt)
		{
		/* portmask */
		case 'p':
			portmask = parse_portmask(optarg);
			if (portmask == 0)
			{
				printf("invalid portmask\n");
				print_usage(prgname);
				return -1;
			}
			break;
		/* config file */
		case 'c':
			strcpy(config_file, optarg);
			break;
		case 'k':
			redis_key = atoi(optarg);
			break;
		case 'v':
			if (optarg != NULL)
				verbosity_level = atoi(optarg);
			else
				verbosity_level = LOG_DEBUG;
			break;
		case 'h':
			print_usage(prgname);
			return -2;
		default:
			print_usage(prgname);
			return -1;
		}
	}
	if (optind <= 1)
	{
		print_usage(prgname);
		return -1;
	}

	argv[optind - 1] = prgname;
	optind = 1; /* reset getopt lib */
	return 0;
}

/*
 * Tx buffer error callback
 */
static void
flush_tx_error_callback(struct rte_mbuf **unsent, uint16_t count,
						void *userdata __rte_unused)
{

	/* free the mbufs which failed from transmit */
	app_stats.tx.ro_tx_failed_pkts += count;
	RTE_LOG_DP(DEBUG, MARKERAPP, "%s:Packet loss with tx_burst\n", __func__);
	pktmbuf_free_bulk(unsent, count);
}

static inline int
free_tx_buffers(struct rte_eth_dev_tx_buffer *tx_buffer[])
{
	uint16_t port_id;

	/* initialize buffers for all ports */
	RTE_ETH_FOREACH_DEV(port_id)
	{
		/* skip ports that are not enabled */
		if ((portmask & (1 << port_id)) == 0)
			continue;

		rte_free(tx_buffer[port_id]);
	}
	return 0;
}

static inline int
configure_tx_buffers(struct rte_eth_dev_tx_buffer *tx_buffer[])
{
	uint16_t port_id;
	int ret;

	/* initialize buffers for all ports */
	RTE_ETH_FOREACH_DEV(port_id)
	{
		/* skip ports that are not enabled */
		if ((portmask & (1 << port_id)) == 0)
			continue;

		/* Initialize TX buffers */
		tx_buffer[port_id] = rte_zmalloc_socket("tx_buffer",
												RTE_ETH_TX_BUFFER_SIZE(MAX_PKTS_BURST), 0,
												rte_eth_dev_socket_id(port_id));
		if (tx_buffer[port_id] == NULL)
			rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",
					 port_id);

		rte_eth_tx_buffer_init(tx_buffer[port_id], MAX_PKTS_BURST);

		ret = rte_eth_tx_buffer_set_err_callback(tx_buffer[port_id],
												 flush_tx_error_callback, NULL);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
					 "Cannot set error callback for tx buffer on port %u\n",
					 port_id);
	}
	return 0;
}

static inline int
configure_eth_port(uint16_t port_id)
{
	const uint16_t rxRings = 1, txRings = 1;
	int ret;
	uint16_t q;
	uint16_t nb_rxd = RX_DESC_PER_QUEUE;
	uint16_t nb_txd = TX_DESC_PER_QUEUE;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;
	struct rte_eth_conf port_conf = port_conf_default;

	if (!rte_eth_dev_is_valid_port(port_id))
		return -1;

	ret = rte_eth_dev_info_get(port_id, &dev_info);
	if (ret != 0)
	{
		log_error("Error during getting device (port %u) info: %s\n",
				  port_id, strerror(-ret));
		return ret;
	}

	ret = rte_eth_dev_configure(port_id, rxRings, txRings, &port_conf_default);
	if (ret != 0)
		return ret;

	ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
	if (ret != 0)
		return ret;

	for (q = 0; q < rxRings; q++)
	{
		ret = rte_eth_rx_queue_setup(port_id, q, nb_rxd,
									 rte_eth_dev_socket_id(port_id), NULL,
									 mbuf_pool);
		if (ret < 0)
			return ret;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	for (q = 0; q < txRings; q++)
	{
		ret = rte_eth_tx_queue_setup(port_id, q, nb_txd,
									 rte_eth_dev_socket_id(port_id), &txconf);
		if (ret < 0)
			return ret;
	}

	ret = rte_eth_dev_start(port_id);
	if (ret < 0)
		return ret;

	ret = rte_eth_macaddr_get(port_id, &port_addr);
	if (ret != 0)
	{
		log_error("Failed to get MAC address (port %u): %s\n",
				  port_id, rte_strerror(-ret));
		return ret;
	}

	log_info("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			 port_id,
			 port_addr.addr_bytes[0], port_addr.addr_bytes[1],
			 port_addr.addr_bytes[2], port_addr.addr_bytes[3],
			 port_addr.addr_bytes[4], port_addr.addr_bytes[5]);

	ret = rte_eth_promiscuous_enable(port_id);
	if (ret != 0)
		return ret;

	return 0;
}

static void terminate_redis(struct app_context *app)
{
}

static void
print_stats(void)
{
	struct rte_eth_stats eth_stats;
	rte_eth_stats_get(OUT_PORT, &eth_stats);
	log_fatal("---------------------");
	log_fatal(" - Pkts in:   %" PRIu64, eth_stats.ipackets);
	log_fatal(" - Pkts out:  %" PRIu64, eth_stats.opackets);
	log_fatal(" - In Errs:   %" PRIu64, eth_stats.ierrors);
	log_fatal(" - Out Errs:  %" PRIu64, eth_stats.oerrors);
	log_fatal(" - Mbuf Errs: %" PRIu64, eth_stats.rx_nombuf);
	log_fatal(" - Dropped SW: %" PRIu64, app_stats.rx.enqueue_failed_pkts);
	log_fatal(" - TX failed: %" PRIu64, app_stats.tx.failed);
	log_fatal(" - RX failed: %" PRIu64, app_stats.rx.failed);
	log_fatal(" - Timestamp packets: %" PRIu64, app_stats.wkr.valinor);
	log_fatal(" - TX rate pps: %" PRIu64, app_stats.tx.num_packets);
	log_fatal(" - RX rate pps: %" PRIu64, app_stats.rx.num_packets);
	app_stats.tx.num_packets = 0;
	app_stats.rx.num_packets = 0;
}

static void
int_handler(int sig_num)
{
	quit_signal = 1;
	log_warn("received quit signal");
}

static void rx_one_pkt(struct rte_mbuf *buf, struct rte_ring **ring_out, struct net_conf *conf)
{
	struct rte_ether_hdr *ptr_mac_hdr;
	struct rte_ether_addr *ptr_dst_addr, *ptr_src_addr;
	u_int16_t ether_type;
	int ret, push, flush, pulled;

	ptr_mac_hdr = (struct rte_ether_hdr *)rte_pktmbuf_mtod(buf, struct rte_ether_hdr *);
	if (unlikely(ptr_mac_hdr == NULL))
	{
		log_error("Ether header is NULL!");
		rte_pktmbuf_free(buf);
		return;
	}
	ptr_dst_addr = &ptr_mac_hdr->d_addr;
	ether_type = rte_be_to_cpu_16(ptr_mac_hdr->ether_type);

	// rte_pktmbuf_dump(stdout, buf, buf->pkt_len);

	/* handle unicast destinations (send to the application) */
	if (likely(rte_is_unicast_ether_addr(ptr_dst_addr)))
	{
		void *data;
		if (MAC_FILTERING)
		{
			/* lookup runtime by MAC in hash table */
			ret = rte_hash_lookup_data(app_mac_hash,
									   &ptr_dst_addr->addr_bytes[0], &data);
			if (unlikely(ret < 0))
			{
				log_debug("rx: received packet for unregistered MAC");
				rte_pktmbuf_free(buf);
				return;
			}
		}
		// log_info("%u", buf->hash);
		ret = rte_ring_enqueue_burst(ring_out[buf->hash.rss % conf->num_workers],
									 (void *)&buf, 1, NULL);
		app_stats.rx.enqueue_pkts += ret;
		if (unlikely(ret < 1))
		{
			app_stats.rx.enqueue_failed_pkts += 1;
			rte_pktmbuf_free(buf);
		}

		return;
	}
	else
	{
		if (ether_type == RTE_ETHER_TYPE_ARP)
		{
			ret = rte_ring_enqueue_burst(ring_out[buf->hash.rss % conf->num_workers],
										 (void *)&buf, 1, NULL);
			app_stats.rx.enqueue_pkts += ret;
			if (unlikely(ret < 1))
			{
				app_stats.rx.enqueue_failed_pkts += 1;
				rte_pktmbuf_free(buf);
			}
		}
	}

	/* everything else */
	ptr_src_addr = &ptr_mac_hdr->s_addr;
	log_debug("rx: Unhandled packet (%lu)  SRC MAC: %x %x %x %x %x %x, DST MAC: %x %x %x %x %x %x, ethertype %x (%X)",
			  0,
			  ptr_src_addr->addr_bytes[0], ptr_src_addr->addr_bytes[1],
			  ptr_src_addr->addr_bytes[2], ptr_src_addr->addr_bytes[3],
			  ptr_src_addr->addr_bytes[4], ptr_src_addr->addr_bytes[5],
			  ptr_dst_addr->addr_bytes[0], ptr_dst_addr->addr_bytes[1],
			  ptr_dst_addr->addr_bytes[2], ptr_dst_addr->addr_bytes[3],
			  ptr_dst_addr->addr_bytes[4], ptr_dst_addr->addr_bytes[5],
			  ether_type, ptr_mac_hdr->ether_type);
	rte_pktmbuf_free(buf);
}

static int completion_thread(struct rte_ring *completion_ring)
{
	uint16_t i, nb_rx_completions;
	struct rte_mbuf *comp_buffer[MAX_PKTS_BURST] = {NULL};

	log_info("%s() started on lcore %u\n", __func__, rte_lcore_id());

	while (!quit_signal)
	{
		/* Receive completions from the workers */
		nb_rx_completions = rte_ring_dequeue_burst(completion_ring,
												   (void *)comp_buffer, MAX_PKTS_BURST, NULL);
		// if (nb_rx_completions)
		// 	log_debug("received %u completions. Freeing ....", nb_rx_completions);
		// for (i = 0; i < nb_rx_completions; i++)
		// {
		rte_pktmbuf_free_bulk(comp_buffer, nb_rx_completions);
		// }
		app_stats.rx.num_packets += nb_rx_completions;
	}

	log_info("Completion thread exitting");
	return 0;
}

/**
 * This thread receives mbufs from the port and affects them an internal
 * sequence number to keep track of their order of arrival through an
 * mbuf structure.
 * The mbufs are then passed to the worker threads via the rx_to_workers
 * ring.
 */
static int
rx_thread(struct rte_ring **ring_out, struct net_conf *conf, struct rte_ring *completion_ring)
{
	uint16_t i, nb_rx_pkts, nb_rx_completions, nb_rx_timeout, pulled;
	int ret;
	struct rte_mbuf *pkts[MAX_PKTS_BURST];
	struct rte_mbuf *comp_buffer[MAX_PKTS_BURST] = {NULL};

	log_info("%s() started on lcore %u\n", __func__, rte_lcore_id());

	while (!quit_signal)
	{
		/* Receive completions from the workers */
		// nb_rx_completions = rte_ring_dequeue_burst(completion_ring,
		// 										   (void *)comp_buffer, MAX_PKTS_BURST, NULL);
		// if (nb_rx_completions)
		// 	log_debug("received %u completions. Freeing ....", nb_rx_completions);
		// for (i = 0; i < nb_rx_completions; i++)
		// {
		// 	rte_pktmbuf_free(comp_buffer[i]);
		// }
		// app_stats.rx.num_packets += nb_rx_completions;

		/* receive packets */
		nb_rx_pkts = rte_eth_rx_burst(OUT_PORT, 0,
									  pkts, MAX_PKTS_BURST);
		if (nb_rx_pkts == 0)
		{
			RTE_LOG_DP(DEBUG, MARKERAPP,
					   "%s():Received zero packets\n", __func__);
			continue;
		}
		app_stats.rx.rx_pkts += nb_rx_pkts;

		for (i = 0; i < nb_rx_pkts; i++)
			rx_one_pkt(pkts[i], ring_out, conf);
	}

	log_info("RX thread exitting");
	return 0;
}

static int
worker_handle_rx(unsigned int core_id, struct rte_ring *ring_in, struct rte_ring *completion_ring,
				 struct rte_mempool *mp, struct rte_mbuf *burst_buffer[], struct rte_ring *ts_ring)
{
	uint16_t burst_size = 0;
	/* dequeue the mbufs from rx_to_workers ring */
	burst_size = rte_ring_dequeue_burst(ring_in,
										(void *)burst_buffer, MAX_PKTS_BURST, NULL);
	if (unlikely(burst_size == 0))
		return 0;
	net_rcv(burst_buffer, burst_size, mp, completion_ring, ts_ring);
	return burst_size;
}

static int
worker_handle_tx(void)
{

	return 0;
}

static int create_connection_hash(unsigned int core_id)
{
	struct rte_hash *hash;
	struct rte_hash_parameters hash_params = {0};
	char hash_name[25];
	sprintf(hash_name, "transport_hash_table_%u", core_id);

	hash_params.name = hash_name;
	hash_params.entries = 1000;
	hash_params.key_len = 4;
	hash_params.hash_func = rte_jhash;
	hash_params.hash_func_init_val = 0;
	hash_params.socket_id = rte_socket_id();
	hash = rte_hash_create(&hash_params);
	if (hash == NULL)
		return -1;
	transport_hash[core_id] = hash;
	return 0;
}

/**
 * This thread takes bursts of packets from the rx_to_workers ring and
 * Changes the input port value to output port value. And feds it to
 * workers_to_tx
 */
static int
worker_thread(void *args_ptr)
{
	struct worker_thread_args *args;
	struct rte_mbuf *burst_buffer[MAX_PKTS_BURST] = {NULL};
	struct rte_ring *ring_in, *ring_out;
	char mp_name[20];
	struct rte_mempool *mp;
	struct rte_ring *completion_ring;
	uint64_t now, last_ts, diff, denom, diff_ns;
	int ret;
	unsigned int core_id = rte_lcore_id();

	args = (struct worker_thread_args *)args_ptr;
	ring_in = args->ring_in;
	ring_out = args->ring_out;
	completion_ring = args->completion_ring;
	worker_tx_rings[core_id] = ring_out;

	log_info("%s() started on lcore %u", __func__, core_id);

	sprintf(mp_name, "mbuf_pool_%u", core_id);
	mp = rte_pktmbuf_pool_create(mp_name, MBUF_PER_POOL, MBUF_POOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
								 rte_socket_id());
	if (mp == NULL)
		rte_exit(EXIT_FAILURE, "%s\n", rte_strerror(rte_errno));
	worker_mempools[core_id] = mp;

	log_info("Worker %u: Successfully created internal mempool\n", core_id);

	ret = app_worker_init(core_id, args->app);
	if (ret < 0)
	{
		log_error("Application failed to initialize. Exitting");
		rte_exit(EXIT_FAILURE, "APP INIT FAIL");
	}

	last_ts = rte_get_tsc_cycles();

	while (!quit_signal)
	{

		ret = worker_handle_rx(core_id, ring_in, completion_ring, mp, burst_buffer, args->app->ts_ring);
		if (unlikely(ret < 0))
			log_error("Worker RX failed: %d", ret);
		if (ret > 0)
		{
			ret = app_logic_callback(args->app);
			if (unlikely(ret < 0))
				log_error("App callback failed: %d", ret);
		}
		if (core_id == 1)
		{
			now = rte_get_tsc_cycles();
			diff = now - last_ts;
			denom = diff * NS_PER_S;
			diff_ns = denom / rte_get_tsc_hz();
			if (diff_ns >= 1000000000)
			{
				last_ts = now;
				print_stats();
			}
		}
	}
	log_info("Worker thread exitting");
	return 0;
}

void onRedisMessage(redisAsyncContext *c, void *reply, void *privdata)
{
	redisReply *r = reply;
	if (reply == NULL)
		return;

	if (r->type == REDIS_REPLY_ARRAY)
	{
		for (int j = 0; j < r->elements; j++)
		{
			log_info(" Redis: (%u) %s\n", j, r->element[j]->str);
		}
	}
}

/**
 * This worker thread is responsible for handling async libevent communications with Redis
 */
static int
redis_thread(void *args_ptr)
{
	struct worker_thread_args *args;
	int ret;
	args = (struct worker_thread_args *)args_ptr;
	unsigned int core_id = rte_lcore_id();

	log_info("%s() started on lcore %u", __func__, core_id);
	log_info("Redis Worker %u: Connecting to Redis, using key = %u", core_id, args->app->redis_key);

	args->app->c_pool[core_id] = redisConnect("127.0.0.1", 6379);
	if (args->app->c_pool[core_id]->err)
	{
		log_error("Redis worker error %u: %s", core_id, args->app->c_pool[core_id]->errstr);
		return 1;
	}
	log_info("Redis Worker %u: Connected to Redis", core_id);

	while (!quit_signal)
	{
		ret = app_periodic_callback(args->app, core_id);
		if (unlikely(ret < 0))
			log_error("App callback failed for redis worker %u: %d", core_id, ret);
	}
	log_info("Redis Worker %u: Exitting", core_id);

	return 0;
}

/**
 * Dequeue mbufs from the workers_to_tx ring and transmit them
 */
static int
tx_thread(struct rte_ring *ring_in)
{
	uint32_t i, dqnum, sent;
	uint8_t outp;
	int ret;
	struct rte_mbuf *mbufs[MAX_PKTS_BURST];
	static struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];

	log_info("%s() started on lcore %u\n", __func__, rte_lcore_id());

	configure_tx_buffers(tx_buffer);

	while (!quit_signal)
	{

		/* deque the mbufs from workers_to_tx ring */
		dqnum = rte_ring_dequeue_burst(ring_in,
									   (void *)mbufs, MAX_PKTS_BURST, NULL);

		if (unlikely(dqnum == 0))
			continue;

		log_debug("TX thread received %u packets", dqnum);

		app_stats.tx.from_app += dqnum;

		for (i = 0; i < dqnum; i++)
		{
			outp = OUT_PORT;
			/* skip ports that are not enabled */
			if ((portmask & (1 << outp)) == 0)
			{
				rte_pktmbuf_free(mbufs[i]);
				continue;
			}
			mbufs[i]->port = outp;
		}
		// send the packet on the wire
		sent = rte_eth_tx_burst(outp, 0, mbufs, dqnum);
		if (sent < dqnum)
		{
			// log_error("Failed to send %u packets", dqnum - sent);
			app_stats.tx.failed += (dqnum - sent);
			for (i = sent; i < dqnum; i++)
				rte_pktmbuf_free(mbufs[i]);
		}
		app_stats.tx.num_packets += sent;
	}

	return 0;
}

int parse_app_conf(struct net_conf *conf)
{
	int ret;
	char *mac_str, *addr_str, *dst_addr_str, *mask_str, *gateway;
	struct json_token t;
	char *IP, *MAC;
	int i;
	struct rte_hash_parameters hash_params = {0};

	log_info("Trying to open the app config file %s.", config_file);
	FILE *f = fopen(config_file, "r");
	if (f == NULL)
	{
		log_error("Failed to open config file %s", config_file);
	}
	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	char *string = rte_malloc(NULL, fsize + 1, 0);
	ret = fread(string, 1, fsize, f);
	if (ret < 0)
	{
		log_error("Failed to read the application config.\n");
	}
	fclose(f);
	ret = json_scanf(string, strlen(string), "{ MAC_addr:%Q, num_workers:%d, worker2_enabled:%d, addr:%Q, port:%d, dst_addr:%Q, dst_port:%d, mask:%Q, gateway:%Q}",
					 &mac_str, &conf->num_workers, &conf->worker2_enabled, &addr_str, &conf->port, &dst_addr_str, &conf->dst_port, &mask_str, &gateway);

	log_info("%d attributes read from the JSON: App MAC address is %s, worker count is %d, addr is %s", ret, mac_str, conf->num_workers, addr_str);
	for (i = 0; json_scanf_array_elem(string, strlen(string), ".arp_table", i, &t) > 0; i++)
	{
		json_scanf(t.ptr, t.len, "{IP: %Q, MAC:%Q}", &IP, &MAC);
		log_info("read ARP entry: %s -> %s", IP, MAC);
		ret = arp_add_entry(IP, MAC);
		if (ret < 0)
			log_error("FAILED to add ARP entry: %s -> %s", IP, MAC);
		else
			log_info("added ARP entry: %s -> %s", IP, MAC);
		free(IP);
		free(MAC);
	}

	ret = str_to_ip(addr_str, &conf->addr);
	if (ret < 0)
	{
		log_error("FAILED to parse application IP address.");
		return ret;
	}
	ret = str_to_ip(dst_addr_str, &conf->dst_addr);
	if (ret < 0)
	{
		log_error("FAILED to parse destination IP address.");
		return ret;
	}
	ret = str_to_ip(mask_str, &conf->netmask);
	if (ret < 0)
	{
		log_error("FAILED to parse netmask.");
		return ret;
	}
	ret = str_to_ip(gateway, &conf->gateway);
	if (ret < 0)
	{
		log_error("FAILED to parse gateway IP address.");
		return ret;
	}

	// register MAC addr to the hash
	hash_params.name = "mac_to_app_hash_table";
	hash_params.entries = 10;
	hash_params.key_len = RTE_ETHER_ADDR_LEN;
	hash_params.hash_func = rte_jhash;
	hash_params.hash_func_init_val = 0;
	hash_params.socket_id = rte_socket_id();
	app_mac_hash = rte_hash_create(&hash_params);
	if (app_mac_hash == NULL)
	{
		log_fatal("Failed to initialize the application MAC hash table. Exitting...");
		rte_exit(EXIT_FAILURE, "Cannot proceed.\n");
	}
	sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &conf->mac[0], &conf->mac[1], &conf->mac[2], &conf->mac[3], &conf->mac[4], &conf->mac[5]);
	log_info("Registered MAC %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8,
			 conf->mac[0], conf->mac[1], conf->mac[2], conf->mac[3], conf->mac[4], conf->mac[5]);
	ret = rte_hash_add_key_data(app_mac_hash, &conf->mac[0], &conf->num_workers);
	if (ret < 0)
	{
		log_fatal("Failed to add the MAC address provided in the config to hash table.");
		rte_exit(EXIT_FAILURE, "Cannot proceed.\n");
	}
	rte_free(string);
	return 0;
}

int get_link_status(uint16_t port_id)
{
	struct rte_eth_link link;
	int ret;
	char link_status_text[RTE_ETH_LINK_MAX_STR_LEN];

	ret = rte_eth_link_get_nowait(port_id, &link);
	if (ret < 0)
	{
		log_error("Failed link get on port %d: %s",
				  port_id, rte_strerror(-ret));
		return ret;
	}
	rte_eth_link_to_str(link_status_text, sizeof(link_status_text), &link);
	log_info("Port %d %s", port_id, link_status_text);
	return 0;
}

int main(int argc, char **argv)
{
	int ret;
	unsigned nb_ports, i;
	unsigned int lcore_id, last_lcore_id, master_lcore_id;
	uint16_t port_id;
	uint16_t nb_ports_available;
	struct worker_thread_args *worker_args;
	struct rte_ring **rx_to_workers;
	struct rte_ring *workers_to_tx, *completion_ring, *ts_ring;
	struct app_context app;

	quit_signal = 0;
	verbosity_level = LOG_INFO;
	redis_key = 0;

	/* catch ctrl-c so we can print on exit */
	signal(SIGINT, int_handler);

	/* Initialize EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments = %u\n", ret);

	argc -= ret;
	argv += ret;

	/* Parse the application specific arguments */
	ret = parse_args(argc, argv);
	if (ret == -1)
		rte_exit(EXIT_FAILURE, "Invalid valinor arguments\n");
	else if (ret == -2)
		rte_exit(EXIT_SUCCESS, ";)\n");

	log_set_level(verbosity_level);

	ret = arp_init();
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Failed to initialize ARP tables.\n");

	ret = parse_app_conf(&conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Parsing application config failed\n");

	app.app_ip = conf.addr;
	app.app_port = conf.port;
	app.dst_ip = conf.dst_addr;
	app.dst_port = conf.dst_port;
	app.app_stats = &app_stats;
	app.redis_key = redis_key;
	log_info("redis = %u, log = %u", redis_key, verbosity_level);

	/* Check if we have enought cores */
	if (rte_lcore_count() < 3)
		rte_exit(EXIT_FAILURE, "Error, This application needs at "
							   "least 3 logical cores to run:\n"
							   "1 lcore for packet RX\n"
							   "1 lcore for packet TX\n"
							   "and at least 1 lcore for worker threads\n");

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "Error: no ethernet ports detected\n");
	if (nb_ports != 1 && (nb_ports & 1))
		rte_exit(EXIT_FAILURE, "Error: number of ports must be even, except "
							   "when using a single port\n");

	log_info("Creating mbuf pool");

	mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NIC_MBUF_PER_POOL,
										MBUF_POOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
										rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Failed to create mbuf_pool: %s\n", rte_strerror(rte_errno));
	log_info("Created mbuf pool");
	nb_ports_available = nb_ports;

	/* initialize all ports */
	RTE_ETH_FOREACH_DEV(port_id)
	{
		/* skip ports that are not enabled */
		if ((portmask & (1 << port_id)) == 0)
		{
			log_info("\nSkipping disabled port %d", port_id);
			nb_ports_available--;
			continue;
		}
		/* init port */
		log_info("Initializing port %u...", port_id);

		if (configure_eth_port(port_id) != 0)
			rte_exit(EXIT_FAILURE, "Cannot initialize port %" PRIu8 "\n",
					 port_id);
		ret = get_link_status(port_id);
		if (ret < 0)
		{
			rte_exit(EXIT_FAILURE, "Failed to get link status on port %" PRIu8 "\n",
					 port_id);
		}
	}

	if (!nb_ports_available)
	{
		rte_exit(EXIT_FAILURE,
				 "All available ports are disabled. Please set portmask.\n");
	}
	log_debug("Trying to allocate RX to workers Rings of size %d", conf.num_workers);
	rx_to_workers = (struct rte_ring **)rte_malloc("RX_TO_WORKERS_RINGS", conf.num_workers * sizeof(struct rte_ring *), 0);
	if (rx_to_workers == NULL)
		rte_exit(EXIT_FAILURE,
				 "Failed to allocate RX_TO_WORKERS rings array.\n");

	workers_to_tx = rte_ring_create("workers_to_tx", RING_SIZE, rte_socket_id(),
									RING_F_SC_DEQ);
	if (workers_to_tx == NULL)
		rte_exit(EXIT_FAILURE, "%s\n", rte_strerror(rte_errno));

	completion_ring = rte_ring_create("completion_ring", RING_SIZE, rte_socket_id(),
									  RING_F_SC_DEQ);
	if (completion_ring == NULL)
		rte_exit(EXIT_FAILURE, "%s\n", rte_strerror(rte_errno));

	ts_ring = rte_ring_create("ts_ring", LARGE_RING_SIZE, rte_socket_id(),
							  RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (ts_ring == NULL)
		rte_exit(EXIT_FAILURE, "%s\n", rte_strerror(rte_errno));
	app.ts_ring = ts_ring;
	log_info("Main: Successfully created timestamp ring\n");

	ret = time_init();
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Time subsystem initialization failed.\n");

	ret = create_connection_hash(0);
	if (ret < 0)
	{
		log_fatal("Failed to initialize the transport hash table. Exitting... (%d)", rte_errno);
		rte_exit(EXIT_FAILURE, "Cannot proceed.\n");
	}

	list_head_init(&tcp_conns);

	worker_args = (struct worker_thread_args *)rte_malloc("WORKER_THREAD_ARGS", conf.num_workers * sizeof(struct worker_thread_args), 0);
	if (worker_args == NULL)
		rte_exit(EXIT_FAILURE,
				 "Failed to allocate Wroker args struct.\n");

	for (i = 0; i < conf.num_workers; i++)
	{
		char ring_name[30];
		/* Create rings for inter core communication */

		log_debug("Creating rx to worker ring %u", i);
		sprintf(ring_name, "rx_to_workers_%u", i);
		rx_to_workers[i] = rte_ring_create(ring_name, LARGE_RING_SIZE, rte_socket_id(),
										   RING_F_SP_ENQ);
		if (rx_to_workers[i] == NULL)
			rte_exit(EXIT_FAILURE, "%s\n", rte_strerror(rte_errno));

		worker_args[i].ring_in = rx_to_workers[i];
		worker_args[i].ring_out = workers_to_tx;
		worker_args[i].completion_ring = completion_ring;
		worker_args[i].app = &app;
	}

	last_lcore_id = get_last_lcore_id();
	master_lcore_id = rte_get_main_lcore();

	app.c_pool = rte_malloc(NULL, 16 * sizeof(struct RedisContext *), 0);
	if (app.c_pool == NULL)
	{
		log_error("Failed to allocate RedisContext array");
		rte_exit(EXIT_FAILURE, "Valinor Redis cntxt INIT FAIL");
	}
	app.idle = rte_calloc(NULL, 16, sizeof(uint32_t), 0);
	if (app.idle == NULL)
	{
		log_error("Failed to allocate idle array");
		rte_exit(EXIT_FAILURE, "Valinor idle array INIT FAIL");
	}
	app.commands = rte_calloc(NULL, 16, sizeof(uint32_t), 0);
	if (app.commands == NULL)
	{
		log_error("Failed to allocate commands array");
		rte_exit(EXIT_FAILURE, "Valinor commands array INIT FAIL");
	}
	for (i = 0; i < 16; i++)
		app.commands[i] = 0;

	ret = app_initiate_callback(&app);
	if (ret < 0)
	{
		log_error("Application failed to initialize. Exitting");
		rte_exit(EXIT_FAILURE, "APP INIT FAIL");
	}

	/* Start worker_thread() on all the available slave cores but the last 1 */
	for (lcore_id = 1; lcore_id <= conf.num_workers; lcore_id++)
		if (rte_lcore_is_enabled(lcore_id) && lcore_id != master_lcore_id)
			rte_eal_remote_launch(worker_thread, (void *)&worker_args[lcore_id - 1],
								  lcore_id);
	for (; lcore_id <= 10; lcore_id++)
		if (rte_lcore_is_enabled(lcore_id) && lcore_id != master_lcore_id)
			rte_eal_remote_launch(redis_thread, (void *)&worker_args[0],
								  lcore_id);

	/* Start send_thread() on the last slave core */
	rte_eal_remote_launch((lcore_function_t *)tx_thread,
						  (void *)workers_to_tx, lcore_id);

	/* Start send_thread() on the last slave core */
	rte_eal_remote_launch((lcore_function_t *)completion_thread,
						  (void *)completion_ring, last_lcore_id);

	/* Start rx_thread() on the master core */
	rx_thread(rx_to_workers, &conf, completion_ring);

	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		if (rte_eal_wait_lcore(lcore_id) < 0)
			return -1;
	}

	print_stats();
	terminate_redis(&app);
	rte_free(rx_to_workers);
	rte_free(app.c_pool);
	rte_free(app.idle);
	rte_free(app.commands);
	rte_free(worker_args);
	log_warn("Gracefully exitting!");
	return 0;
}
