#include "udp_proxy.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "addr_header.h"
#include "ctx.h"
#include "fakedns.h"
#include "logutils.h"

/* Layout checks. */

_Static_assert(sizeof(udp_tunnel_hdr_ipv4_t) <= MAX_TUNNEL_UDP_HEADER, "MAX_TUNNEL_UDP_HEADER too small for ipv4");
_Static_assert(sizeof(udp_tunnel_hdr_ipv6_t) <= MAX_TUNNEL_UDP_HEADER, "MAX_TUNNEL_UDP_HEADER too small for ipv6");
_Static_assert(sizeof(udp_tunnel_hdr_domain_t) + MAX_DOMAIN_LEN + sizeof(portno_t) <= MAX_TUNNEL_UDP_HEADER,
               "MAX_TUNNEL_UDP_HEADER too small for domain");

/* fork_key is hashed as a whole struct; both endpoints must be tightly packed. */
_Static_assert(sizeof(udp_fork_key_t) == 2 * sizeof(udp_endpoint_key_t),
               "udp_fork_key_t must be tightly packed for memcmp hashing");

/* Reply-path recovery uses offsetof; watcher must be at offset 0. */
_Static_assert(offsetof(udp_session_t, udp_watcher) == 0,
               "udp_watcher must be first in udp_session_t");

static void udp_tunnel_on_reply(evloop_t *evloop, struct ev_watcher *watcher, int revents);

typedef enum {
    UDP_ENTRY_INDEXED,
    UDP_ENTRY_DETACHED,
} udp_entry_state_t;

typedef struct {
    udp_endpoint_key_t client;
    udp_endpoint_key_t orig_dst;
    const char        *fake_domain;
    char              *header_start;
    size_t             header_len;
} udp_ingress_t;

typedef struct {
    char              *payload;
    size_t             payload_len;
    udp_endpoint_key_t reply_src;
} udp_reply_t;

typedef struct {
    udp_tproxy_entry_t *entry;
    struct mmsghdr      msg;
    struct iovec        iov;
    skaddr6_t           addr;
} udp_tproxy_send_t;

/* Per-thread batch I/O buffers. */
static __thread struct mmsghdr  g_tprecv_msgs[UDP_BATCH_SIZE];
static __thread struct iovec    g_tprecv_iovs[UDP_BATCH_SIZE];
static __thread char            g_tprecv_ctrl_bufs[UDP_BATCH_SIZE][UDP_CTRLMESG_BUFSIZ];
static __thread skaddr6_t       g_tprecv_skaddrs[UDP_BATCH_SIZE];

static __thread struct mmsghdr  g_tunnel_msgs[UDP_BATCH_SIZE];
static __thread struct mmsghdr  g_tunnel_send_msgs[UDP_BATCH_SIZE];
static __thread struct iovec    g_tunnel_iovs[UDP_BATCH_SIZE];

static inline void udp_endpoint_to_string(const udp_endpoint_key_t *ep, char ipstr[IP6STRLEN], portno_t *portno) {
    if (ep->family == AF_INET) {
        inet_ntop(AF_INET, ep->addr, ipstr, IP6STRLEN);
    } else {
        inet_ntop(AF_INET6, ep->addr, ipstr, IP6STRLEN);
    }
    *portno = ntohs(ep->port);
}

static inline void udp_log_transfer(const char *stage, const char *action,
                                    const udp_endpoint_key_t *src, const udp_endpoint_key_t *dst,
                                    const char *unit, int val) {
    IF_VERBOSE {
        char src_ipstr[IP6STRLEN];
        char dst_ipstr[IP6STRLEN];
        portno_t src_port;
        portno_t dst_port;

        udp_endpoint_to_string(src, src_ipstr, &src_port);
        udp_endpoint_to_string(dst, dst_ipstr, &dst_port);

        LOGINF_RAW("[%s] %s: %s#%hu -> %s#%hu, %s:%d",
                   stage, action,
                   src_ipstr, src_port,
                   dst_ipstr, dst_port,
                   unit, val);
    }
}

static inline udp_endpoint_key_t udp_endpoint_from_skaddr(const skaddr6_t *skaddr, bool is_ipv4) {
    udp_endpoint_key_t ep;
    memset(&ep, 0, sizeof(ep));
    if (is_ipv4) {
        const skaddr4_t *sa4 = (const skaddr4_t *)skaddr;
        ep.family = AF_INET;
        ep.port   = sa4->sin_port;
        memcpy(ep.addr, &sa4->sin_addr.s_addr, IP4BINLEN);
    } else {
        ep.family = AF_INET6;
        ep.port   = skaddr->sin6_port;
        memcpy(ep.addr, &skaddr->sin6_addr.s6_addr, IP6BINLEN);
    }
    return ep;
}

static inline void udp_skaddr_from_endpoint(skaddr6_t *dst, const udp_endpoint_key_t *ep) {
    memset(dst, 0, sizeof(*dst));
    if (ep->family == AF_INET) {
        skaddr4_t *a = (void *)dst;
        a->sin_family = AF_INET;
        memcpy(&a->sin_addr.s_addr, ep->addr, IP4BINLEN);
        a->sin_port   = ep->port;
    } else {
        dst->sin6_family = AF_INET6;
        memcpy(&dst->sin6_addr.s6_addr, ep->addr, IP6BINLEN);
        dst->sin6_port  = ep->port;
    }
}

static inline void udp_session_touch(udp_session_t *session, ev_tstamp now) {
    if (session->main_idx) {
        session->main_idx->last_active = now;
    } else {
        session->fork_idx->last_active = now;
    }
}

static void udp_log_session_route(const char *action, const udp_ingress_t *pkt) {
    IF_VERBOSE {
        char client_ipstr[IP6STRLEN];
        portno_t client_port;
        portno_t orig_dst_port;

        udp_endpoint_to_string(&pkt->client, client_ipstr, &client_port);

        if (pkt->fake_domain) {
            orig_dst_port = ntohs(pkt->orig_dst.port);
            LOGINF_RAW("[udp_session] %s fork session (FakeDNS): %s#%hu -> %s#%hu",
                       action, client_ipstr, client_port, pkt->fake_domain, orig_dst_port);
        } else {
            char orig_dst_ipstr[IP6STRLEN];
            udp_endpoint_to_string(&pkt->orig_dst, orig_dst_ipstr, &orig_dst_port);
            LOGINF_RAW("[udp_session] %s main session (RealIP): %s#%hu -> %s#%hu",
                       action, client_ipstr, client_port, orig_dst_ipstr, orig_dst_port);
        }
    }
}

static bool udp_ingress_copy_sender(struct msghdr *msg, skaddr6_t *skaddr) {
    if (msg->msg_namelen == sizeof(skaddr4_t)) {
        memcpy(skaddr, msg->msg_name, sizeof(skaddr4_t));
        return true;
    }
    if (msg->msg_namelen == sizeof(skaddr6_t)) {
        memcpy(skaddr, msg->msg_name, sizeof(skaddr6_t));
        return true;
    }

    LOGERR("[udp_ingress] invalid msg_namelen: %d", (int)msg->msg_namelen);
    return false;
}

static bool udp_ingress_resolve_fakedns(const skaddr6_t *orig_dst_skaddr, bool is_ipv4, const char **fake_domain) {
    *fake_domain = NULL;
    if (!(g_options & OPT_ENABLE_FAKEDNS) || !is_ipv4) {
        return true;
    }

    uint32_t target_ip = ((const skaddr4_t *)orig_dst_skaddr)->sin_addr.s_addr;
    bool is_miss;
    *fake_domain = fakedns_try_resolve(target_ip, &is_miss);
    if (is_miss) {
        LOGERR("[udp_fakedns] miss for FakeIP: %u.%u.%u.%u, dropping packet",
               ((uint8_t *)&target_ip)[0], ((uint8_t *)&target_ip)[1],
               ((uint8_t *)&target_ip)[2], ((uint8_t *)&target_ip)[3]);
        return false;
    }

    IF_VERBOSE if (*fake_domain) {
        LOGINF_RAW("[udp_fakedns] hit: %u.%u.%u.%u -> %s",
                   ((uint8_t *)&target_ip)[0], ((uint8_t *)&target_ip)[1],
                   ((uint8_t *)&target_ip)[2], ((uint8_t *)&target_ip)[3],
                   *fake_domain);
    }
    return true;
}

static bool udp_ingress_prepare(struct msghdr *msg, size_t nrecv, char *buffer, bool is_ipv4, udp_ingress_t *pkt) {
    skaddr6_t client_skaddr;
    skaddr6_t orig_dst_skaddr;

    if (!udp_ingress_copy_sender(msg, &client_skaddr)) {
        return false;
    }

    pkt->client = udp_endpoint_from_skaddr(&client_skaddr, is_ipv4);

    IF_VERBOSE {
        char client_ipstr[IP6STRLEN];
        portno_t client_port;
        udp_endpoint_to_string(&pkt->client, client_ipstr, &client_port);
        LOGINF_RAW("[udp_ingress] recv from %s#%hu, nrecv:%zd", client_ipstr, client_port, nrecv);
    }

    if (!get_udp_orig_dstaddr(is_ipv4 ? AF_INET : AF_INET6, msg, &orig_dst_skaddr)) {
        LOGERR("[udp_ingress] destination address not found in udp msg");
        return false;
    }

    if (!udp_ingress_resolve_fakedns(&orig_dst_skaddr, is_ipv4, &pkt->fake_domain)) {
        return false;
    }
    pkt->orig_dst = udp_endpoint_from_skaddr(&orig_dst_skaddr, is_ipv4);

    char *payload_start = buffer + MAX_TUNNEL_UDP_HEADER;
    pkt->header_start = addr_header_build_udp(payload_start, pkt->fake_domain, &orig_dst_skaddr, is_ipv4, &pkt->header_len);
    if (!pkt->header_start) {
        LOGERR("[udp_ingress] failed to build tunnel UDP header");
        return false;
    }

    if (nrecv > UDP_DATAGRAM_MAXSIZ - pkt->header_len) {
        LOGWAR("[udp_ingress] packet too large to encapsulate (%zu+%zu > %d), dropping",
               nrecv, pkt->header_len, UDP_DATAGRAM_MAXSIZ);
        return false;
    }

    return true;
}

static udp_fork_key_t udp_ingress_build_fork_key(const udp_ingress_t *pkt) {
    udp_fork_key_t fork_key;
    fork_key.client = pkt->client;
    fork_key.target = pkt->orig_dst;
    return fork_key;
}

static udp_session_t *udp_session_find(const udp_ingress_t *pkt, const udp_fork_key_t *fork_key) {
    if (pkt->fake_domain) {
        assert(fork_key);

        udp_fork_node_t *node = udp_fork_node_find(&g_udp_fork_table, fork_key);
        if (node) {
            udp_log_session_route("reuse", pkt);
            return node->session;
        }
        return NULL;
    }

    udp_main_node_t *node = udp_main_node_find(&g_udp_main_table, &pkt->client);
    if (node) {
        udp_log_session_route("reuse", pkt);
        return node->session;
    }
    return NULL;
}

static int udp_tunnel_connect(void) {
    int udp_sockfd = new_udp_normal_sockfd(g_server_skaddr.sin6_family);
    if (udp_sockfd < 0) {
        LOGERR("[udp_tunnel] new_udp_normal_sockfd: %s", strerror(errno));
        return -1;
    }

    bool server_is_ipv4 = g_server_skaddr.sin6_family == AF_INET;
    if (connect(udp_sockfd, (void *)&g_server_skaddr, server_is_ipv4 ? sizeof(skaddr4_t) : sizeof(skaddr6_t)) < 0) {
        LOGERR("[udp_tunnel] connect to %s#%hu: %s", g_server_ipstr, g_server_portno, strerror(errno));
        close(udp_sockfd);
        return -1;
    }

    return udp_sockfd;
}

static void udp_session_destroy(evloop_t *evloop, udp_session_t *session) {
    ev_io_stop(evloop, &session->udp_watcher);
    close(session->udp_watcher.fd);
    mempool_free_sized(g_udp_session_pool, session, sizeof(*session));
}

static void udp_tproxy_entry_destroy(udp_tproxy_entry_t *entry) {
    close(entry->udp_sockfd);
    mempool_free_sized(g_udp_tproxy_pool, entry, sizeof(*entry));
}

/* Indexed entries still live in their hash table and must be deleted first.
 * Detached entries were already removed by LRU_DEFINE_ADD. */
static void udp_session_release(evloop_t *evloop, udp_session_t *session, udp_entry_state_t state) {
    assert((session->main_idx != NULL) ^ (session->fork_idx != NULL));
    if (session->main_idx) {
        udp_main_node_t *node = session->main_idx;
        if (state == UDP_ENTRY_INDEXED) {
            udp_main_node_del(&g_udp_main_table, node);
        }
        mempool_free_sized(g_udp_main_node_pool, node, sizeof(*node));
        session->main_idx = NULL;
    } else {
        udp_fork_node_t *node = session->fork_idx;
        if (state == UDP_ENTRY_INDEXED) {
            udp_fork_node_del(&g_udp_fork_table, node);
        }
        mempool_free_sized(g_udp_fork_node_pool, node, sizeof(*node));
        session->fork_idx = NULL;
    }
    udp_session_destroy(evloop, session);
}

static void udp_session_release_indexed(evloop_t *evloop, udp_session_t *session) {
    udp_session_release(evloop, session, UDP_ENTRY_INDEXED);
}

static void udp_session_release_detached(evloop_t *evloop, udp_session_t *session) {
    udp_session_release(evloop, session, UDP_ENTRY_DETACHED);
}

static void udp_tproxy_entry_release_indexed(evloop_t *evloop __attribute__((unused)), udp_tproxy_entry_t *entry) {
    udp_tproxy_entry_del(&g_udp_tproxy_table, entry);
    udp_tproxy_entry_destroy(entry);
}

static bool udp_session_register_main(evloop_t *evloop, udp_session_t *session, ev_tstamp now) {
    udp_main_node_t *node = mempool_alloc_sized(g_udp_main_node_pool, sizeof(*node));
    if (!node) {
        LOGERR("[udp_session] mempool alloc failed for main-node");
        return false;
    }

    node->key         = session->client;
    node->session     = session;
    node->last_active = now;
    session->main_idx = node;

    udp_main_node_t *victim = udp_main_node_add(&g_udp_main_table, node);
    if (victim) {
        LOGINF("[udp_session] main table full, evicting least active entry");
        udp_session_release_detached(evloop, victim->session);
    }
    return true;
}

static bool udp_session_register_fork(evloop_t *evloop, udp_session_t *session, const udp_fork_key_t *fork_key, ev_tstamp now) {
    assert(fork_key);

    udp_fork_node_t *node = mempool_alloc_sized(g_udp_fork_node_pool, sizeof(*node));
    if (!node) {
        LOGERR("[udp_session] mempool alloc failed for fork-node");
        return false;
    }

    node->key         = *fork_key;
    node->session     = session;
    node->last_active = now;
    session->fork_idx = node;

    udp_fork_node_t *victim = udp_fork_node_add(&g_udp_fork_table, node);
    if (victim) {
        LOGINF("[udp_session] fork table full, evicting least active entry");
        udp_session_release_detached(evloop, victim->session);
    }
    return true;
}

static udp_session_t *udp_session_create(evloop_t *evloop, const udp_ingress_t *pkt, const udp_fork_key_t *fork_key) {
    int udp_sockfd = udp_tunnel_connect();
    if (udp_sockfd < 0) {
        return NULL;
    }

    udp_session_t *session = mempool_alloc_sized(g_udp_session_pool, sizeof(*session));
    if (!session) {
        LOGERR("[udp_session] mempool alloc failed for session");
        close(udp_sockfd);
        return NULL;
    }

    session->client      = pkt->client;
    session->orig_dst    = pkt->orig_dst;
    session->is_fakedns  = (pkt->fake_domain != NULL);
    session->main_idx    = NULL;
    session->fork_idx    = NULL;
    ev_tstamp now        = ev_now(evloop);

    ev_io_init(&session->udp_watcher, udp_tunnel_on_reply, udp_sockfd, EV_READ);
    ev_io_start(evloop, &session->udp_watcher);

    bool indexed = session->is_fakedns
                   ? udp_session_register_fork(evloop, session, fork_key, now)
                   : udp_session_register_main(evloop, session, now);
    if (!indexed) {
        udp_session_destroy(evloop, session);
        return NULL;
    }

    assert((session->main_idx != NULL) ^ (session->fork_idx != NULL));
    udp_log_session_route("new", pkt);
    return session;
}

static void udp_session_send_to_tunnel(evloop_t *evloop, udp_session_t *session,
                                       const udp_endpoint_key_t *orig_dst_for_log,
                                       const char *data, size_t data_len) {
    ssize_t nsend = send(session->udp_watcher.fd, data, data_len, 0);
    if (nsend < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[udp_tunnel] send to %s#%hu: %s", g_server_ipstr, g_server_portno, strerror(errno));
            if (errno == EPIPE || errno == ECONNRESET || errno == ECONNREFUSED) {
                udp_session_release_indexed(evloop, session);
            }
        }
        return;
    }

    udp_log_transfer("udp_tunnel", "send",
                     &session->client, orig_dst_for_log,
                     "nsend", (int)nsend);
}

static void udp_ingress_handle(evloop_t *evloop, evio_t *tprecv_watcher, struct msghdr *msg, size_t nrecv, char *buffer) {
    bool is_ipv4 = (intptr_t)tprecv_watcher->data;
    udp_ingress_t pkt;
    udp_fork_key_t fork_key;
    const udp_fork_key_t *fork_key_ptr = NULL;

    if (!udp_ingress_prepare(msg, nrecv, buffer, is_ipv4, &pkt)) {
        return;
    }

    if (pkt.fake_domain) {
        fork_key = udp_ingress_build_fork_key(&pkt);
        fork_key_ptr = &fork_key;
    }

    udp_session_t *session = udp_session_find(&pkt, fork_key_ptr);
    if (!session) {
        session = udp_session_create(evloop, &pkt, fork_key_ptr);
        if (!session) {
            return;
        }
    } else {
        udp_session_touch(session, ev_now(evloop));
    }

    udp_session_send_to_tunnel(evloop, session, &pkt.orig_dst, pkt.header_start, pkt.header_len + nrecv);
}

void udp_proxy_on_recvmsg(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *tprecv_watcher = (evio_t *)watcher;
    bool is_ipv4 = (intptr_t)tprecv_watcher->data;

    for (int i = 0; i < UDP_BATCH_SIZE; i++) {
        g_tprecv_msgs[i].msg_hdr.msg_namelen    = sizeof(skaddr6_t);
        g_tprecv_msgs[i].msg_hdr.msg_controllen = UDP_CTRLMESG_BUFSIZ;
    }

    int retval = recvmmsg(tprecv_watcher->fd, g_tprecv_msgs, UDP_BATCH_SIZE, 0, NULL);

    if (retval < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[udp_proxy] recvmmsg from udp%s socket: %s", is_ipv4 ? "4" : "6", strerror(errno));
        }
        return;
    }

    if (retval == 0) return;

    for (int i = 0; i < retval; i++) {
        udp_ingress_handle(evloop, tprecv_watcher, &g_tprecv_msgs[i].msg_hdr, (size_t)g_tprecv_msgs[i].msg_len, g_udp_batch_buffer[i]);
    }
}

static bool udp_tunnel_parse_reply(const udp_session_t *session, char *buffer, size_t nrecv, udp_reply_t *reply) {
    if (nrecv < sizeof(addr_hdr_ipv4_t)) {
        return false;
    }

    uint8_t atype = (uint8_t)buffer[0];
    size_t headerlen;

    switch (atype) {
        case ADDRTYPE_IPV4:
            headerlen = sizeof(addr_hdr_ipv4_t);
            break;
        case ADDRTYPE_IPV6:
            headerlen = sizeof(addr_hdr_ipv6_t);
            break;
        default:
            LOGERR("[udp_tunnel] unsupported reply address type: 0x%02x", atype);
            return false;
    }

    if (nrecv < headerlen) {
        return false;
    }

    reply->reply_src = (udp_endpoint_key_t) {
        0
    };
    if (session->is_fakedns) {
        reply->reply_src = session->orig_dst;
    } else if (atype == ADDRTYPE_IPV4) {
        addr_hdr_ipv4_t *hdr = (addr_hdr_ipv4_t *)buffer;
        reply->reply_src.family = AF_INET;
        reply->reply_src.port = hdr->portnum;
        memcpy(reply->reply_src.addr, &hdr->ipaddr4, IP4BINLEN);
    } else {
        addr_hdr_ipv6_t *hdr = (addr_hdr_ipv6_t *)buffer;
        reply->reply_src.family = AF_INET6;
        reply->reply_src.port = hdr->portnum;
        memcpy(reply->reply_src.addr, &hdr->ipaddr6, IP6BINLEN);
    }

    reply->payload = buffer + headerlen;
    reply->payload_len = nrecv - headerlen;
    return true;
}

static udp_tproxy_entry_t *udp_tproxy_entry_get_or_create(evloop_t *evloop,
        const udp_endpoint_key_t *reply_src,
        const udp_endpoint_key_t *client,
        udp_tproxy_entry_t **deferred_evict,
        int *deferred_evict_count) {
    udp_tproxy_entry_t *tproxy_entry = udp_tproxy_entry_find(&g_udp_tproxy_table, reply_src);
    if (tproxy_entry) {
        tproxy_entry->last_active = ev_now(evloop);
        return tproxy_entry;
    }

    skaddr6_t fromskaddr;
    udp_skaddr_from_endpoint(&fromskaddr, reply_src);

    bool reply_src_is_ipv4 = (reply_src->family == AF_INET);
    int tproxy_sockfd = new_udp_tpsend_sockfd(reply_src_is_ipv4 ? AF_INET : AF_INET6);
    if (tproxy_sockfd < 0) {
        LOGERR("[udp_tproxy] new_udp_tpsend_sockfd failed");
        return NULL;
    }

    if (bind(tproxy_sockfd, (void *)&fromskaddr, reply_src_is_ipv4 ? sizeof(skaddr4_t) : sizeof(skaddr6_t)) < 0) {
        char bind_ipstr[IP6STRLEN];
        portno_t bind_port;
        parse_socket_addr(&fromskaddr, bind_ipstr, &bind_port);
        LOGERR("[udp_tproxy] bind tproxy_sockfd to %s#%hu: %s", bind_ipstr, bind_port, strerror(errno));
        close(tproxy_sockfd);
        return NULL;
    }

    tproxy_entry = mempool_alloc_sized(g_udp_tproxy_pool, sizeof(*tproxy_entry));
    if (!tproxy_entry) {
        LOGERR("[udp_tproxy] mempool alloc failed for tproxy entry");
        close(tproxy_sockfd);
        return NULL;
    }

    tproxy_entry->key = *reply_src;
    tproxy_entry->udp_sockfd = tproxy_sockfd;
    tproxy_entry->last_active = ev_now(evloop);

    udp_tproxy_entry_t *victim = udp_tproxy_entry_add(&g_udp_tproxy_table, tproxy_entry);
    if (victim) {
        LOGINF("[udp_tproxy] tproxy table full, deferring eviction");
        deferred_evict[(*deferred_evict_count)++] = victim;
    }

    udp_log_transfer("udp_tproxy", "new entry", reply_src, client, "fd", tproxy_sockfd);
    return tproxy_entry;
}

static void udp_tproxy_send_queue(udp_tproxy_send_t *slot,
                                  udp_tproxy_entry_t *tproxy_entry,
                                  const udp_reply_t *reply,
                                  const udp_endpoint_key_t *client) {
    udp_skaddr_from_endpoint(&slot->addr, client);

    slot->entry = tproxy_entry;
    slot->iov.iov_base = reply->payload;
    slot->iov.iov_len = reply->payload_len;
    slot->msg.msg_hdr.msg_name = &slot->addr;
    slot->msg.msg_hdr.msg_namelen = client->family == AF_INET ? sizeof(skaddr4_t) : sizeof(skaddr6_t);
    slot->msg.msg_hdr.msg_iov = &slot->iov;
    slot->msg.msg_hdr.msg_iovlen = 1;
    slot->msg.msg_hdr.msg_control = NULL;
    slot->msg.msg_hdr.msg_controllen = 0;
}

static void udp_tproxy_send_flush_batch(const udp_session_t *session, udp_tproxy_send_t batch_sends[], int send_count) {
    if (send_count <= 0) {
        return;
    }

    uint16_t indices[UDP_BATCH_SIZE];
    for (int k = 0; k < send_count; k++) {
        indices[k] = (uint16_t)k;
    }

    for (int i = 0; i < send_count;) {
        udp_tproxy_entry_t *entry = batch_sends[indices[i]].entry;
        int group_count = 0;

        for (int j = i; j < send_count; j++) {
            if (batch_sends[indices[j]].entry == entry) {
                if (j != i + group_count) {
                    uint16_t tmp = indices[i + group_count];
                    indices[i + group_count] = indices[j];
                    indices[j] = tmp;
                }
                group_count++;
            }
        }

        for (int k = 0; k < group_count; k++) {
            g_tunnel_send_msgs[k] = batch_sends[indices[i + k]].msg;
        }

        int sent = sendmmsg(entry->udp_sockfd, g_tunnel_send_msgs, (unsigned int)group_count, 0);
        if (sent < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                LOGERR("[udp_tproxy] sendmmsg failed: %s", strerror(errno));
            }
        } else {
            if (sent < group_count) {
                LOGWAR("[udp_tproxy] sendmmsg partial: sent=%d/%d, dropped=%d",
                       sent, group_count, group_count - sent);
            }
            udp_log_transfer("udp_tproxy", "sendmmsg",
                             &entry->key, &session->client,
                             "npackets", sent);
        }

        i += group_count;
    }
}

static void udp_tunnel_on_reply(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *udp_watcher = (evio_t *)watcher;
    udp_session_t *session = (void *)((uint8_t *)udp_watcher - offsetof(udp_session_t, udp_watcher));

    int retval = recvmmsg(udp_watcher->fd, g_tunnel_msgs, UDP_BATCH_SIZE, 0, NULL);

    if (retval < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[udp_tunnel] recv reply: %s", strerror(errno));
        }
        return;
    }

    if (retval == 0) return;

    /* Process batch and prepare for sendmmsg */
    udp_tproxy_send_t batch_sends[UDP_BATCH_SIZE];
    int send_count = 0;

    udp_tproxy_entry_t *deferred_evict[UDP_BATCH_SIZE];
    int deferred_evict_count = 0;

    udp_session_touch(session, ev_now(evloop));

    for (int i = 0; i < retval; i++) {
        char *buffer = g_udp_batch_buffer[i];
        size_t nrecv = (size_t)g_tunnel_msgs[i].msg_len;

        udp_reply_t reply;
        if (!udp_tunnel_parse_reply(session, buffer, nrecv, &reply)) {
            continue;
        }

        udp_tproxy_entry_t *tproxy_entry = udp_tproxy_entry_get_or_create(evloop, &reply.reply_src, &session->client,
                                           deferred_evict, &deferred_evict_count);
        if (!tproxy_entry) {
            continue;
        }

        udp_tproxy_send_queue(&batch_sends[send_count], tproxy_entry, &reply, &session->client);
        send_count++;
        if (send_count >= UDP_BATCH_SIZE) break;
    }

    udp_tproxy_send_flush_batch(session, batch_sends, send_count);

    /* LRU add already removed deferred evictions from the table. */
    for (int i = 0; i < deferred_evict_count; i++) {
        udp_tproxy_entry_destroy(deferred_evict[i]);
    }
}


#define GC_INTERVAL_SEC      10.0

static __thread evtimer_t g_gc_timer;

static inline bool udp_gc_is_idle(ev_tstamp now, ev_tstamp last_active, ev_tstamp timeout) {
    return (now - last_active) >= timeout;
}

static ev_tstamp udp_gc_tproxy_timeout(void) {
    return g_udp_idletimeout_sec >= 20
           ? (ev_tstamp)g_udp_idletimeout_sec / 2.0
           : 10.0;
}

static void udp_gc_log_evicted(const char *table_name, int evicted) {
    if (evicted > 0) {
        LOGINF("[udp_gc] %s evicted: %d", table_name, evicted);
    }
}

static int udp_gc_sweep_main_sessions(evloop_t *evloop, ev_tstamp now, ev_tstamp timeout) {
    int evicted = 0;
    udp_main_node_t *cur, *tmp;

    MYLRU_HASH_FOR(g_udp_main_table, cur, tmp) {
        if (udp_gc_is_idle(now, cur->last_active, timeout)) {
            udp_session_release_indexed(evloop, cur->session);
            evicted++;
        }
    }
    return evicted;
}

static int udp_gc_sweep_fork_sessions(evloop_t *evloop, ev_tstamp now, ev_tstamp timeout) {
    int evicted = 0;
    udp_fork_node_t *cur, *tmp;

    MYLRU_HASH_FOR(g_udp_fork_table, cur, tmp) {
        if (udp_gc_is_idle(now, cur->last_active, timeout)) {
            udp_session_release_indexed(evloop, cur->session);
            evicted++;
        }
    }
    return evicted;
}

static int udp_gc_sweep_tproxy_entries(evloop_t *evloop, ev_tstamp now, ev_tstamp timeout) {
    int evicted = 0;
    udp_tproxy_entry_t *cur, *tmp;

    MYLRU_HASH_FOR(g_udp_tproxy_table, cur, tmp) {
        if (udp_gc_is_idle(now, cur->last_active, timeout)) {
            udp_tproxy_entry_release_indexed(evloop, cur);
            evicted++;
        }
    }
    return evicted;
}

static void udp_gc_on_tick(evloop_t *evloop, struct ev_watcher *watcher __attribute__((unused)), int revents __attribute__((unused))) {
    ev_tstamp now = ev_now(evloop);
    ev_tstamp session_timeout = (ev_tstamp)g_udp_idletimeout_sec;
    ev_tstamp tproxy_timeout = udp_gc_tproxy_timeout();

    udp_gc_log_evicted("main table", udp_gc_sweep_main_sessions(evloop, now, session_timeout));
    udp_gc_log_evicted("fork table", udp_gc_sweep_fork_sessions(evloop, now, session_timeout));
    udp_gc_log_evicted("tproxy table", udp_gc_sweep_tproxy_entries(evloop, now, tproxy_timeout));
}

void udp_proxy_gc_start(evloop_t *evloop) {
    ev_timer_init(&g_gc_timer, udp_gc_on_tick, GC_INTERVAL_SEC, GC_INTERVAL_SEC);
    ev_timer_start(evloop, &g_gc_timer);
}

void udp_proxy_gc_stop(evloop_t *evloop) {
    ev_timer_stop(evloop, &g_gc_timer);
}

static void udp_main_session_clear_cb(void *evloop_ctx, udp_main_node_t *node) {
    udp_session_release_indexed((evloop_t *)evloop_ctx, node->session);
}

static void udp_fork_session_clear_cb(void *evloop_ctx, udp_fork_node_t *node) {
    udp_session_release_indexed((evloop_t *)evloop_ctx, node->session);
}

static void udp_tproxy_entry_clear_cb(void *evloop_ctx, udp_tproxy_entry_t *entry) {
    udp_tproxy_entry_release_indexed((evloop_t *)evloop_ctx, entry);
}

void udp_proxy_thread_init(void) {
    for (int i = 0; i < UDP_BATCH_SIZE; i++) {
        g_tprecv_iovs[i].iov_base            = (uint8_t *)g_udp_batch_buffer[i] + MAX_TUNNEL_UDP_HEADER;
        g_tprecv_iovs[i].iov_len             = UDP_DATAGRAM_MAXSIZ;
        g_tprecv_msgs[i].msg_hdr.msg_name    = &g_tprecv_skaddrs[i];
        g_tprecv_msgs[i].msg_hdr.msg_iov     = &g_tprecv_iovs[i];
        g_tprecv_msgs[i].msg_hdr.msg_iovlen  = 1;
        g_tprecv_msgs[i].msg_hdr.msg_control = g_tprecv_ctrl_bufs[i];

        g_tunnel_iovs[i].iov_base               = g_udp_batch_buffer[i];
        g_tunnel_iovs[i].iov_len                = UDP_DATAGRAM_MAXSIZ;
        g_tunnel_msgs[i].msg_hdr.msg_name       = NULL;
        g_tunnel_msgs[i].msg_hdr.msg_namelen    = 0;
        g_tunnel_msgs[i].msg_hdr.msg_iov        = &g_tunnel_iovs[i];
        g_tunnel_msgs[i].msg_hdr.msg_iovlen     = 1;
        g_tunnel_msgs[i].msg_hdr.msg_control    = NULL;
        g_tunnel_msgs[i].msg_hdr.msg_controllen = 0;
    }
}

void udp_proxy_close_all_sessions(evloop_t *evloop) {
    LOGINF("[udp_proxy] cleaning up remaining sessions...");

    udp_proxy_gc_stop(evloop);
    udp_main_node_clear(&g_udp_main_table, udp_main_session_clear_cb, evloop);
    udp_fork_node_clear(&g_udp_fork_table, udp_fork_session_clear_cb, evloop);
    udp_tproxy_entry_clear(&g_udp_tproxy_table, udp_tproxy_entry_clear_cb, evloop);
}
