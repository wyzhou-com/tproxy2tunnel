#include "lrucache.h"
#include "udp_proxy.h"

/* Capacity configuration. */

#define FORK_SIZE_MULTIPLIER   2
#define TPROXY_SIZE_MULTIPLIER 4

static uint16_t g_main_cache_maxsize   = 256;
static uint16_t g_fork_cache_maxsize   = 256 * FORK_SIZE_MULTIPLIER;
static uint16_t g_tproxy_cache_maxsize = 256 * TPROXY_SIZE_MULTIPLIER;

uint16_t udp_lrucache_get_main_maxsize(void)   {
    return g_main_cache_maxsize;
}
uint16_t udp_lrucache_get_fork_maxsize(void)   {
    return g_fork_cache_maxsize;
}
uint16_t udp_lrucache_get_tproxy_maxsize(void) {
    return g_tproxy_cache_maxsize;
}

void udp_lrucache_set_maxsize(uint16_t base_size) {
    g_main_cache_maxsize = base_size;

    unsigned int fork_size  = (unsigned int)base_size * FORK_SIZE_MULTIPLIER;
    unsigned int tproxy_size = (unsigned int)base_size * TPROXY_SIZE_MULTIPLIER;

    g_fork_cache_maxsize   = (fork_size   > 65535u) ? 65535u : (uint16_t)fork_size;
    g_tproxy_cache_maxsize = (tproxy_size > 65535u) ? 65535u : (uint16_t)tproxy_size;
}

/* Main table: client endpoint -> session. */

LRU_DEFINE_ADD(udp_main_node_add,
               udp_main_node_t, key,
               g_main_cache_maxsize, last_active)

LRU_DEFINE_FIND(udp_main_node_find,
                udp_main_node_t, udp_endpoint_key_t)

LRU_DEFINE_DEL(udp_main_node_del,
               udp_main_node_t)

/* Fork table: (client endpoint, target endpoint) -> session. */

LRU_DEFINE_ADD(udp_fork_node_add,
               udp_fork_node_t, key,
               g_fork_cache_maxsize, last_active)

LRU_DEFINE_FIND(udp_fork_node_find,
                udp_fork_node_t, udp_fork_key_t)

LRU_DEFINE_DEL(udp_fork_node_del,
               udp_fork_node_t)

/* TProxy table: remote source endpoint -> bound tproxy socket. */

LRU_DEFINE_ADD(udp_tproxy_entry_add,
               udp_tproxy_entry_t, key,
               g_tproxy_cache_maxsize, last_active)

LRU_DEFINE_FIND(udp_tproxy_entry_find,
                udp_tproxy_entry_t, udp_tproxy_key_t)

LRU_DEFINE_DEL(udp_tproxy_entry_del,
               udp_tproxy_entry_t)

/* Clear helpers. */

LRU_DEFINE_CLEAR(udp_main_node_clear, udp_main_node_t)
LRU_DEFINE_CLEAR(udp_fork_node_clear, udp_fork_node_t)
LRU_DEFINE_CLEAR(udp_tproxy_entry_clear, udp_tproxy_entry_t)
