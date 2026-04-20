#ifndef TPROXY2TUNNEL_UDP_PROXY_H
#define TPROXY2TUNNEL_UDP_PROXY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#include "ev_types.h"

#include "lrucache.h"
#include "netutils.h"

/* Cache capacity API. */

uint16_t udp_lrucache_get_main_maxsize(void);
uint16_t udp_lrucache_get_fork_maxsize(void);
uint16_t udp_lrucache_get_tproxy_maxsize(void);
void udp_lrucache_set_maxsize(uint16_t base_size);

/* Memory-pool and batch I/O sizing. */

#define MEMPOOL_INITIAL_SIZE  256

#define UDP_BATCH_SIZE        16

/* ATYP(1) + LEN(1) + DOMAIN(255) + PORT(2). */
#define MAX_TUNNEL_UDP_HEADER 259

/* Reserve header space before the payload for zero-copy tunnel prepend. */
#define UDP_BATCH_BUFSIZ     (UDP_DATAGRAM_MAXSIZ + MAX_TUNNEL_UDP_HEADER)

/* Cache keys.
 *
 * udp_endpoint_key_t is the canonical key shape for all UDP caches. It is
 * hashed by value, so constructors must zero-initialize it before filling.
 */

typedef struct {
    uint16_t family;   /* AF_INET / AF_INET6 */
    portno_t port;     /* network byte order */
    uint8_t  addr[16]; /* v4 uses the first 4 bytes */
} udp_endpoint_key_t;

_Static_assert(sizeof(udp_endpoint_key_t) == 20,
               "udp_endpoint_key_t must be 20B with zero padding for memcmp hashing");

typedef struct {
    udp_endpoint_key_t client;
    udp_endpoint_key_t target;
} udp_fork_key_t;

typedef udp_endpoint_key_t udp_tproxy_key_t;

/* Sessions and cache index nodes.
 *
 * A session owns the connected tunnel UDP socket. It is indexed by exactly one
 * table at a time: main_idx XOR fork_idx.
 */

typedef struct udp_main_node udp_main_node_t;
typedef struct udp_fork_node udp_fork_node_t;

typedef struct udp_session {
    /* Must stay at offset 0: udp_tunnel_recv_cb recovers the session via offsetof. */
    evio_t             udp_watcher;

    udp_endpoint_key_t client;       /* reply destination */
    udp_endpoint_key_t orig_dst;     /* original destination */

    bool               is_fakedns;

    udp_main_node_t   *main_idx;
    udp_fork_node_t   *fork_idx;
} udp_session_t;

struct udp_main_node {
    udp_endpoint_key_t key;
    udp_session_t     *session;
    ev_tstamp          last_active;
    myhash_hh          hh;
};

struct udp_fork_node {
    udp_fork_key_t     key;
    udp_session_t     *session;
    ev_tstamp          last_active;
    myhash_hh          hh;
};

typedef struct {
    udp_tproxy_key_t key;
    int              udp_sockfd;
    ev_tstamp        last_active;

    myhash_hh        hh;
} udp_tproxy_entry_t;

/* LRU cache functions generated in udp_lrucache.c. */

udp_main_node_t* udp_main_node_add(udp_main_node_t **cache, udp_main_node_t *entry);
udp_fork_node_t* udp_fork_node_add(udp_fork_node_t **cache, udp_fork_node_t *entry);
udp_tproxy_entry_t* udp_tproxy_entry_add(udp_tproxy_entry_t **cache, udp_tproxy_entry_t *entry);

udp_main_node_t* udp_main_node_find(udp_main_node_t **cache, const udp_endpoint_key_t *keyptr);
udp_fork_node_t* udp_fork_node_find(udp_fork_node_t **cache, const udp_fork_key_t     *keyptr);
udp_tproxy_entry_t* udp_tproxy_entry_find(udp_tproxy_entry_t **cache, const udp_tproxy_key_t   *keyptr);

void udp_main_node_del(udp_main_node_t **cache, udp_main_node_t *entry);
void udp_fork_node_del(udp_fork_node_t **cache, udp_fork_node_t *entry);
void udp_tproxy_entry_del(udp_tproxy_entry_t **cache, udp_tproxy_entry_t *entry);

typedef void (*udp_main_node_cb_t)(void *ctx, udp_main_node_t *entry);
typedef void (*udp_fork_node_cb_t)(void *ctx, udp_fork_node_t *entry);
typedef void (*udp_tproxy_entry_cb_t)(void *ctx, udp_tproxy_entry_t *entry);

void udp_main_node_clear(udp_main_node_t **cache, udp_main_node_cb_t cb, void *ctx);
void udp_fork_node_clear(udp_fork_node_t **cache, udp_fork_node_cb_t cb, void *ctx);
void udp_tproxy_entry_clear(udp_tproxy_entry_t **cache, udp_tproxy_entry_cb_t cb, void *ctx);

void udp_tproxy_recvmsg_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
void udp_proxy_thread_init(void);
void udp_proxy_close_all_sessions(evloop_t *evloop);
void udp_proxy_init_gc(evloop_t *evloop);
void udp_proxy_stop_gc(evloop_t *evloop);

#endif /* TPROXY2TUNNEL_UDP_PROXY_H */
