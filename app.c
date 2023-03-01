#include <stdio.h>
#include <string.h>

#include "inc/app.h"
#include "inc/tcp.h"
#include "inc/udp.h"
#include "util/log.h"
#include "inc/crc.h"

#define IA_NS 20000
#define RESPONSE_SIZE 10000

typedef struct {
    struct app_context *app;
    char udp_buffer[4096];
    uint64_t latency[100000000];
    uint64_t latency_ptr;
    uint64_t first_sent;
    uint64_t last_sent;
    uint8_t sent;
} app_data_t;

struct app_header {
    uint64_t tx_ts;
    uint64_t rid;
};

static app_data_t app_data;
struct udp_flow_id udp_f;
uint64_t first_sent;
uint64_t last_sent;
uint64_t next_send;
char TX_BUF[10000];


void hexDump (const char * desc, const void * addr, const int len) {
    int i;
    unsigned char buff[17];
    const unsigned char * pc = (const unsigned char *)addr;
    // Output description if given.
    if (desc != NULL)
        printf ("%s:\n", desc);
    // Length checks.
    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    else if (len < 0) {
        printf("  NEGATIVE LENGTH: %d\n", len);
        return;
    }
    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).
        if ((i % 16) == 0) {
            // Don't print ASCII buffer for the "zeroth" line.
            if (i != 0)
                printf ("  %s\n", buff);
            // Output the offset.
            printf ("  %04x ", i);
        }
        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);
        // And buffer a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) // isprint() may be better.
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }
    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }
    // And print the final ASCII buffer.
    printf ("  %s\n", buff);
}

// Connects to Redis on localhost and default port
int app_worker_init(unsigned int id, struct app_context *app)
{
    log_info("App init: Connecting to Redis\n");
	app->base = event_base_new();

    app->c_pool[id] = redisConnect("127.0.0.1", 6379);
    if (app->c_pool[id]->err) {
        log_error("Redis error: %s\n", app->c_pool[id]->errstr);
        return 1;
    }
	log_info("App init: Connected to Redis\n");
}


int app_receive_udp_callback(struct udp_flow_id *udp_flow, void *data, u_int32_t size) { return 0;}

int app_initiate_callback(struct app_context *app) {return 0;};

void redis_cb(redisAsyncContext *c, void *reply, void *privdata)
{
    redisReply *r = reply;
    if (reply == NULL) return;

    if (r->type == REDIS_REPLY_ARRAY) {
        for (int j = 0; j < r->elements; j++) {
            log_info(" Redis: (%u) %s\n", j, r->element[j]->str);
        }
    }
}

// This function executes the batched commands and receives Redis replies
int valinor_flush_to_redis(struct app_context *app, uint32_t uid)
{
    int i, count;
    redisReply *reply;
    redisContext *c = app->c_pool[uid];
    count = app->commands[uid];
    log_debug("Redis worker: Executing Redis commands (%u), count=%u", uid, count);
    for(i=0;i<app->commands[uid];i++) {
        if(redisGetReply(c,(void *)&reply) == REDIS_OK ){
            freeReplyObject(reply);
        }
        else {
            log_error("App redis callaback error (%u): %s", uid, reply->str);
        }
    }
    app->commands[uid] = 0;
    return count;
}

// This function creates a new Redis commands and enqueues it for deferred execution
int valinor_data_received(struct app_context *app, uint32_t uid)
{
    int count, ret, i, pos = 0;
    uint64_t now, then, denom, diff;
    char cmd[9000];
    redisContext *c = app->c_pool[uid];
    struct timestamp_entry* timestamps[MAX_PKTS_BURST];
    if(unlikely(c == NULL)) {
        log_error("App redis callaback (%u): Redis context is NULL!", uid);
        return -1;
    }
    count = rte_ring_dequeue_burst(app->ts_ring, (void *)timestamps, MAX_PKTS_BURST, NULL);
    if (unlikely(count <= 0))
        return count;
    pos += sprintf(cmd, "ZADD %d", app->redis_key);
    for (i=0;i < count;i++)
    {
        pos += sprintf(&cmd[pos], " %lu %016" PRIx64 "%08" PRIx32 "%08" PRIx32 "%04" PRIx16 "%08" PRIx32 "%08" PRIx32 "%08" 
                PRIx32 "%04" PRIx16 "%04" PRIx16, timestamps[i]->ingress_global, 
                timestamps[i]->ingress_global, timestamps[i]->enqueue, timestamps[i]->enqueue_delta, timestamps[i]->packet_length, 
                timestamps[i]->key, timestamps[i]->saddr, timestamps[i]->daddr, timestamps[i]->sport, timestamps[i]->dport);
    }
    redisAppendCommand(c, cmd);
    app->commands[uid]++;
    app->app_stats->wkr.valinor += count;
    return count;
}


int app_logic_callback(struct app_context *app)
{
    return 0;
}

// Check if we have been idle for some time. If so, start executing redis commands
int app_periodic_callback(struct app_context *app, uint32_t uid)
{
    int ret = valinor_data_received(app, uid);
    if (ret == 0) {
        app->idle[uid]++;
        if (app->idle[uid] >= APP_IDLE_THRESHOLD && app->commands[uid] > 0) {
            app->idle[uid] = 0;
            return valinor_flush_to_redis(app, uid);
        }
    }
    return 0;
}

int cmpfunc (const void * a, const void * b) {
   return ( *(uint64_t*)a - *(uint64_t*)b );
}