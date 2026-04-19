#include "lrucache.h"    /* LRU_DEFINE_*                                   */
#include "udp_proxy.h"   /* udp_tunnelctx_t, udp_tproxyctx_t, ip_port_t, … */

/* ── udp_lrucache.c ────────────────────────────────────────────────────────
 * Single instantiation point for all typed LRU cache functions.
 * ──────────────────────────────────────────────────────────────────────── */

/* ════════════════════════════════════════════════════════════════════════
 * Cache Capacity Configuration & Globals
 * ════════════════════════════════════════════════════════════════════════ */

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

/* ════════════════════════════════════════════════════════════════════════
 * Main Table  (key: client source IP:Port)
 * ════════════════════════════════════════════════════════════════════════ */

LRU_DEFINE_ADD(udp_tunnelctx_add,
               udp_tunnelctx_t, key_ipport,
               udp_lrucache_get_main_maxsize(), last_active)

LRU_DEFINE_FIND(udp_tunnelctx_find,
                udp_tunnelctx_t, ip_port_t)

LRU_DEFINE_DEL(udp_tunnelctx_del,
               udp_tunnelctx_t)

/* ════════════════════════════════════════════════════════════════════════
 * Fork Table  (key: composite (client, target) pair; capacity ×2)
 * ════════════════════════════════════════════════════════════════════════ */

LRU_DEFINE_ADD(udp_tunnelctx_fork_add,
               udp_tunnelctx_t, fork_key,
               udp_lrucache_get_fork_maxsize(), last_active)

LRU_DEFINE_FIND(udp_tunnelctx_fork_find,
                udp_tunnelctx_t, udp_fork_key_t)

/* Fork Table shares udp_tunnelctx_del with Main Table */

/* ════════════════════════════════════════════════════════════════════════
 * TProxy Table  (key: remote source IP:Port; capacity ×4)
 * ════════════════════════════════════════════════════════════════════════ */

LRU_DEFINE_ADD(udp_tproxyctx_add,
               udp_tproxyctx_t, key,
               udp_lrucache_get_tproxy_maxsize(), last_active)

LRU_DEFINE_FIND(udp_tproxyctx_find,
                udp_tproxyctx_t, udp_tproxy_key_t)

LRU_DEFINE_DEL(udp_tproxyctx_del,
               udp_tproxyctx_t)

/* ════════════════════════════════════════════════════════════════════════
 * Clear All  (LRU_DEFINE_CLEAR)
 * ════════════════════════════════════════════════════════════════════════ */

LRU_DEFINE_CLEAR(udp_tunnelctx_clear_main, udp_tunnelctx_t)
LRU_DEFINE_CLEAR(udp_tunnelctx_clear_fork, udp_tunnelctx_t)
LRU_DEFINE_CLEAR(udp_tproxyctx_clear,      udp_tproxyctx_t)
