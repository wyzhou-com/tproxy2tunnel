#include "udp_proxy.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "addr_header.h"
#include "ctx.h"
#include "fakedns.h"
#include "logutils.h"

/* ── Compile-time layout assertions ── */

/* MAX_TUNNEL_UDP_HEADER must cover the largest possible tunnel header */
_Static_assert(sizeof(udp_tunnel_hdr_ipv4_t) <= MAX_TUNNEL_UDP_HEADER, "MAX_TUNNEL_UDP_HEADER too small for ipv4");
_Static_assert(sizeof(udp_tunnel_hdr_ipv6_t) <= MAX_TUNNEL_UDP_HEADER, "MAX_TUNNEL_UDP_HEADER too small for ipv6");
_Static_assert(sizeof(udp_tunnel_hdr_domain_t) + MAX_DOMAIN_LEN + sizeof(portno_t) <= MAX_TUNNEL_UDP_HEADER,
               "MAX_TUNNEL_UDP_HEADER too small for domain");

/* fork_key must start at a 0-offset within udp_fork_key_t.client_ipport for hash key correctness */
_Static_assert(offsetof(udp_fork_key_t, client_ipport) == 0, "fork_key hash relies on client_ipport at offset 0");

/* Forward declarations */
static void handle_udp_socket_msg(evloop_t *evloop, evio_t *tprecv_watcher, struct msghdr *msg, size_t nrecv, char *buffer);
static void udp_tunnel_recv_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static void gc_release_tunnelctx(evloop_t *evloop, udp_tunnelctx_t *context);
static void gc_release_tproxyctx(evloop_t *evloop, udp_tproxyctx_t *context);
static void gc_sweep_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static void destroy_tunnelctx(evloop_t *evloop, udp_tunnelctx_t *context);
static void destroy_tproxyctx(evloop_t *evloop, udp_tproxyctx_t *context);

static inline void udp_tunnelctx_keepalive(evloop_t *evloop, udp_tunnelctx_t *ctx) {
    ctx->last_active = ev_now(evloop);
}

void udp_tproxy_recvmsg_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *tprecv_watcher = (evio_t *)watcher;
    bool isipv4 = (intptr_t)tprecv_watcher->data;

    const size_t max_headerlen = MAX_TUNNEL_UDP_HEADER;

    static __thread struct mmsghdr msgs[UDP_BATCH_SIZE];
    static __thread struct iovec iovs[UDP_BATCH_SIZE];
    static __thread char msg_control_buffers[UDP_BATCH_SIZE][UDP_CTRLMESG_BUFSIZ];
    static __thread skaddr6_t skaddrs[UDP_BATCH_SIZE];
    static __thread bool tproxy_recvmsg_initialized = false;

    if (!tproxy_recvmsg_initialized) {
        for (int i = 0; i < UDP_BATCH_SIZE; i++) {
            iovs[i].iov_base            = (uint8_t *)g_udp_batch_buffer[i] + max_headerlen;
            iovs[i].iov_len             = UDP_DATAGRAM_MAXSIZ - max_headerlen;
            msgs[i].msg_hdr.msg_name    = &skaddrs[i];
            msgs[i].msg_hdr.msg_iov     = &iovs[i];
            msgs[i].msg_hdr.msg_iovlen  = 1;
            msgs[i].msg_hdr.msg_control = msg_control_buffers[i];
        }
        tproxy_recvmsg_initialized = true;
    }

    for (int i = 0; i < UDP_BATCH_SIZE; i++) {
        msgs[i].msg_hdr.msg_namelen    = sizeof(skaddr6_t);
        msgs[i].msg_hdr.msg_controllen = UDP_CTRLMESG_BUFSIZ;
    }

    int retval = recvmmsg(tprecv_watcher->fd, msgs, UDP_BATCH_SIZE, 0, NULL);

    if (retval < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[udp_tproxy_recvmsg_cb] recvmmsg from udp%s socket: %s", isipv4 ? "4" : "6", strerror(errno));
        }
        return;
    }

    if (retval == 0) return;

    for (int i = 0; i < retval; i++) {
        handle_udp_socket_msg(evloop, tprecv_watcher, &msgs[i].msg_hdr, (size_t)msgs[i].msg_len, g_udp_batch_buffer[i]);
    }
}

#ifdef ENABLE_PERPACKET_LOG
static inline void log_udp_transfer(const char *funcname, const char *action,
                                    const ip_port_t *src, const ip_port_t *dst,
                                    bool is_ipv4, const char *unit, int val) {
    IF_VERBOSE {
        char src_ipstr[IP6STRLEN];
        char dst_ipstr[IP6STRLEN];

        if (is_ipv4) {
            inet_ntop(AF_INET, &src->ip.ip4, src_ipstr, sizeof(src_ipstr));
            inet_ntop(AF_INET, &dst->ip.ip4, dst_ipstr, sizeof(dst_ipstr));
        } else {
            inet_ntop(AF_INET6, &src->ip.ip6, src_ipstr, sizeof(src_ipstr));
            inet_ntop(AF_INET6, &dst->ip.ip6, dst_ipstr, sizeof(dst_ipstr));
        }

        LOGINF_RAW("[%s] %s: %s#%hu -> %s#%hu, %s:%d",
                   funcname, action,
                   src_ipstr, ntohs(src->port),
                   dst_ipstr, ntohs(dst->port),
                   unit, val);
    }
}
#endif

static inline void build_fork_key(udp_fork_key_t *fk, const ip_port_t *client, const skaddr6_t *skaddr, bool isipv4) {
    memset(fk, 0, sizeof(*fk));
    fk->client_ipport = *client;
    fk->target_is_ipv4 = isipv4;
    if (isipv4) {
        fk->target_ipport.ip.ip4 = ((const skaddr4_t *)skaddr)->sin_addr.s_addr;
        fk->target_ipport.port = ((const skaddr4_t *)skaddr)->sin_port;
    } else {
        memcpy(&fk->target_ipport.ip.ip6, &skaddr->sin6_addr.s6_addr, IP6BINLEN);
        fk->target_ipport.port = skaddr->sin6_port;
    }
}

static void handle_udp_socket_msg(evloop_t *evloop, evio_t *tprecv_watcher, struct msghdr *msg, size_t nrecv, char *buffer) {
    bool isipv4 = (intptr_t)tprecv_watcher->data;
    skaddr6_t skaddr;
    char ipstr[IP6STRLEN];
    portno_t portno;

    char *payload_start = buffer + MAX_TUNNEL_UDP_HEADER;

    /* Restore skaddr from msg->msg_name (sender address) */
    if (msg->msg_namelen == sizeof(skaddr4_t)) {
        memcpy(&skaddr, msg->msg_name, sizeof(skaddr4_t));
    } else if (msg->msg_namelen == sizeof(skaddr6_t)) {
        memcpy(&skaddr, msg->msg_name, sizeof(skaddr6_t));
    } else {
        LOGERR("[handle_udp_socket_msg] invalid msg_namelen: %d", (int)msg->msg_namelen);
        return;
    }

    IF_VERBOSE {
        parse_socket_addr(&skaddr, ipstr, &portno);
    }

#ifdef ENABLE_PERPACKET_LOG
    IF_VERBOSE {
        LOGINF_RAW("[handle_udp_socket_msg] recv from %s#%hu, nrecv:%zd", ipstr, portno, nrecv);
    }
#endif

    ip_port_t key_ipport;
    memset(&key_ipport, 0, sizeof(key_ipport));
    if (isipv4) {
        key_ipport.ip.ip4 = ((skaddr4_t *)&skaddr)->sin_addr.s_addr;
        key_ipport.port = ((skaddr4_t *)&skaddr)->sin_port;
    } else {
        memcpy(&key_ipport.ip.ip6, &skaddr.sin6_addr.s6_addr, IP6BINLEN);
        key_ipport.port = skaddr.sin6_port;
    }

    if (!get_udp_orig_dstaddr(isipv4 ? AF_INET : AF_INET6, msg, &skaddr)) {
        LOGERR("[handle_udp_socket_msg] destination address not found in udp msg");
        return;
    }

    /* FakeDNS reverse lookup for domain resolution */
    const char *fake_domain = NULL;
    if ((g_options & OPT_ENABLE_FAKEDNS) && isipv4) {
        uint32_t target_ip = ((skaddr4_t *)&skaddr)->sin_addr.s_addr;
        bool is_miss;
        fake_domain = fakedns_try_resolve(target_ip, &is_miss);
        if (is_miss) {
            LOGERR("[handle_udp_socket_msg] fakedns miss for FakeIP: %u.%u.%u.%u, dropping packet",
                   ((uint8_t *)&target_ip)[0], ((uint8_t *)&target_ip)[1],
                   ((uint8_t *)&target_ip)[2], ((uint8_t *)&target_ip)[3]);
            return;
        }
#ifdef ENABLE_PERPACKET_LOG
        IF_VERBOSE if (fake_domain) {
            LOGINF_RAW("[handle_udp_socket_msg] fakedns hit: %u.%u.%u.%u -> %s",
                       ((uint8_t *)&target_ip)[0], ((uint8_t *)&target_ip)[1],
                       ((uint8_t *)&target_ip)[2], ((uint8_t *)&target_ip)[3],
                       fake_domain);
        }
#endif
    }

    /* Build tunnel header backward from payload position (zero-copy) */
    size_t actual_headerlen;
    char *header_start = addr_header_build_udp(payload_start, fake_domain, &skaddr, isipv4, &actual_headerlen);
    if (!header_start) {
        LOGERR("[handle_udp_socket_msg] failed to build tunnel UDP header");
        return;
    }

    udp_tunnelctx_t *context = NULL;
    bool force_fork = false;
    udp_fork_key_t fork_key;

    /*
     * Traffic Separation Strategy:
     * 1. FakeDNS Traffic: Symmetric-NAT behavior (1:1 mapping per Client IP:Port + Target IP:Port).
     *    Uses Fork Table exclusively.
     * 2. Real IP Traffic: Preferred Full Cone behavior (1:N mapping).
     *    Uses Main Table first, falls back to Fork Table on collision.
     */
    if (fake_domain) {
        /* Strategy A: FakeDNS Traffic -> Fork Table Only */
        build_fork_key(&fork_key, &key_ipport, &skaddr, isipv4);
        context = udp_tunnelctx_fork_find(&g_udp_fork_table, &fork_key);

        if (!context) {
            force_fork = true;
        } else {
#ifdef ENABLE_PERPACKET_LOG
            IF_VERBOSE {
                portno_t target_port = isipv4 ? ((skaddr4_t *)&skaddr)->sin_port : skaddr.sin6_port;
                LOGINF_RAW("[handle_udp_socket_msg] reuse fork context (FakeDNS): %s#%hu -> %s#%hu", ipstr, portno, fake_domain, ntohs(target_port));
            }
#endif
        }
    } else {
        /* Strategy B: Real IP Traffic -> Main Table (Full Cone) -> Fork Table (Fallback) */
        udp_tunnelctx_t *main_ctx = udp_tunnelctx_find(&g_udp_tunnel_table, &key_ipport);

        if (main_ctx) {
            if (main_ctx->dest_is_ipv4 != isipv4) {
                udp_tunnelctx_keepalive(evloop, main_ctx);
                force_fork = true;
            } else {
                context = main_ctx;
#ifdef ENABLE_PERPACKET_LOG
                IF_VERBOSE {
                    char target_ipstr[IP6STRLEN];
                    portno_t target_port;
                    parse_socket_addr(&skaddr, target_ipstr, &target_port);
                    LOGINF_RAW("[handle_udp_socket_msg] reuse main context (RealIP): %s#%hu -> %s#%hu", ipstr, portno, target_ipstr, target_port);
                }
#endif
            }
        }

        if (!context) {
            build_fork_key(&fork_key, &key_ipport, &skaddr, isipv4);
            context = udp_tunnelctx_fork_find(&g_udp_fork_table, &fork_key);
            if (context) {
#ifdef ENABLE_PERPACKET_LOG
                IF_VERBOSE {
                    char target_ipstr[IP6STRLEN];
                    portno_t target_port;
                    parse_socket_addr(&skaddr, target_ipstr, &target_port);
                    LOGINF_RAW("[handle_udp_socket_msg] reuse fork context (RealIP): %s#%hu -> %s#%hu", ipstr, portno, target_ipstr, target_port);
                }
#endif
            }
        }
    }

    if (!context) {
        /* ── New session: create UDP socket and connect to tunnel server ── */
        int udp_sockfd = new_udp_normal_sockfd(g_server_skaddr.sin6_family);
        if (udp_sockfd < 0) {
            LOGERR("[handle_udp_socket_msg] new_udp_normal_sockfd: %s", strerror(errno));
            return;
        }

        bool server_isipv4 = g_server_skaddr.sin6_family == AF_INET;
        if (connect(udp_sockfd, (void *)&g_server_skaddr, server_isipv4 ? sizeof(skaddr4_t) : sizeof(skaddr6_t)) < 0) {
            LOGERR("[handle_udp_socket_msg] connect to %s#%hu: %s", g_server_ipstr, g_server_portno, strerror(errno));
            close(udp_sockfd);
            return;
        }

        context = mempool_alloc_sized(g_udp_context_pool, sizeof(*context));
        if (!context) {
            LOGERR("[handle_udp_socket_msg] mempool alloc failed for context");
            close(udp_sockfd);
            return;
        }
        memcpy(&context->key_ipport, &key_ipport, sizeof(key_ipport));

        context->dest_is_ipv4 = isipv4;
        context->is_fakedns = (fake_domain != NULL);

#ifndef ENABLE_PERPACKET_LOG
        if (fake_domain)
#endif
        {
            if (isipv4) {
                context->orig_dstaddr.ip.ip4 = ((skaddr4_t *)&skaddr)->sin_addr.s_addr;
                context->orig_dstaddr.port = ((skaddr4_t *)&skaddr)->sin_port;
            } else {
                memcpy(&context->orig_dstaddr.ip.ip6, &skaddr.sin6_addr.s6_addr, IP6BINLEN);
                context->orig_dstaddr.port = skaddr.sin6_port;
            }
        }

        /* UDP watcher: immediately ready for receive */
        evio_t *udp_watcher = &context->udp_watcher;
        ev_io_init(udp_watcher, udp_tunnel_recv_cb, udp_sockfd, EV_READ);
        ev_io_start(evloop, udp_watcher);

        context->last_active = ev_now(evloop);

        udp_tunnelctx_t *del_context = NULL;
        memcpy(&context->fork_key, &fork_key, sizeof(fork_key));

        if (force_fork) {
            context->is_forked = true;
            del_context = udp_tunnelctx_fork_add(&g_udp_fork_table, context);
            IF_VERBOSE {
                if (fake_domain) {
                    portno_t target_port = isipv4 ? ((skaddr4_t *)&skaddr)->sin_port : skaddr.sin6_port;
                    LOGINF_RAW("[handle_udp_socket_msg] new fork context (FakeDNS): %s#%hu -> %s#%hu", ipstr, portno, fake_domain, ntohs(target_port));
                } else {
                    char target_ipstr[IP6STRLEN];
                    portno_t target_port;
                    parse_socket_addr(&skaddr, target_ipstr, &target_port);
                    LOGINF_RAW("[handle_udp_socket_msg] new fork context (RealIP): %s#%hu -> %s#%hu", ipstr, portno, target_ipstr, target_port);
                }
            }
        } else {
            IF_VERBOSE {
                char target_ipstr[IP6STRLEN];
                portno_t target_port;
                parse_socket_addr(&skaddr, target_ipstr, &target_port);
                LOGINF_RAW("[handle_udp_socket_msg] new main context (RealIP): %s#%hu -> %s#%hu", ipstr, portno, target_ipstr, target_port);
            }
            context->is_forked = false;
            del_context = udp_tunnelctx_add(&g_udp_tunnel_table, context);
        }

        if (del_context) {
            LOGINF("[handle_udp_socket_msg] tunnel table full, evicting least active entry");
            destroy_tunnelctx(evloop, del_context);
        }

        /* Send immediately — no handshake, no buffering */
        ssize_t nsend = send(udp_sockfd, header_start, actual_headerlen + nrecv, 0);
        if (nsend < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                LOGERR("[handle_udp_socket_msg] send to %s#%hu: %s", g_server_ipstr, g_server_portno, strerror(errno));
            }
        }
#ifdef ENABLE_PERPACKET_LOG
        else {
            log_udp_transfer("handle_udp_socket_msg", "send",
                             &context->key_ipport, &context->orig_dstaddr,
                             context->dest_is_ipv4, "nsend", (int)nsend);
        }
#endif
        return;
    }

    /* ── Existing session: send immediately ── */
    udp_tunnelctx_keepalive(evloop, context);

    ssize_t nsend = send(context->udp_watcher.fd, header_start, actual_headerlen + nrecv, 0);
    if (nsend < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            parse_socket_addr(&skaddr, ipstr, &portno);
            LOGERR("[handle_udp_socket_msg] send to %s#%hu: %s", ipstr, portno, strerror(errno));
            if (errno == EPIPE || errno == ECONNRESET) {
                LOGWAR("[handle_udp_socket_msg] fatal send error, releasing zombie context");
                gc_release_tunnelctx(evloop, context);
            }
        }
        return;
    }
#ifdef ENABLE_PERPACKET_LOG
    log_udp_transfer("handle_udp_socket_msg", "send",
                     &context->key_ipport, &context->orig_dstaddr,
                     context->dest_is_ipv4, "nsend", (int)nsend);
#endif
}

/* ── Response path: receive from tunnel server, strip header, send to client via tproxy ── */

static inline void sendmmsg_fallback(udp_tunnelctx_t *tunnelctx __attribute__((unused)), udp_tproxyctx_t *tproxy_ctx, struct mmsghdr *msgs, int sent, int total) {
    LOGWAR("[udp_tunnel_recv_cb] partial send %d/%d, using fallback", sent, total);
    for (int k = sent; k < total; k++) {
        struct msghdr *hdr = &msgs[k].msg_hdr;
        ssize_t n = sendto(tproxy_ctx->udp_sockfd, hdr->msg_iov[0].iov_base,
                           hdr->msg_iov[0].iov_len, 0, hdr->msg_name, hdr->msg_namelen);
#ifdef ENABLE_PERPACKET_LOG
        if (n > 0) {
            log_udp_transfer("udp_tunnel_recv_cb", "send",
                             &tproxy_ctx->key_ipport, &tunnelctx->key_ipport,
                             tunnelctx->dest_is_ipv4, "nsend", (int)n);
        }
#endif
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            LOGERR("[udp_tunnel_recv_cb] fallback sendto failed: %s", strerror(errno));
        }
    }
}

static void udp_tunnel_recv_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *udp_watcher = (evio_t *)watcher;
    udp_tunnelctx_t *tunnelctx = (void *)((uint8_t *)udp_watcher - offsetof(udp_tunnelctx_t, udp_watcher));

    /* Connected socket: msg_name/msg_control are NULL — init once */
    static __thread struct mmsghdr msgs[UDP_BATCH_SIZE];
    static __thread struct mmsghdr send_msgs[UDP_BATCH_SIZE];
    static __thread struct iovec iovs[UDP_BATCH_SIZE];
    static __thread bool udpmsg_initialized = false;

    if (!udpmsg_initialized) {
        for (int i = 0; i < UDP_BATCH_SIZE; i++) {
            iovs[i].iov_base               = g_udp_batch_buffer[i];
            iovs[i].iov_len                = UDP_DATAGRAM_MAXSIZ;
            msgs[i].msg_hdr.msg_name       = NULL;
            msgs[i].msg_hdr.msg_namelen    = 0;
            msgs[i].msg_hdr.msg_iov        = &iovs[i];
            msgs[i].msg_hdr.msg_iovlen     = 1;
            msgs[i].msg_hdr.msg_control    = NULL;
            msgs[i].msg_hdr.msg_controllen = 0;
        }
        udpmsg_initialized = true;
    }

    int retval = recvmmsg(udp_watcher->fd, msgs, UDP_BATCH_SIZE, 0, NULL);

    if (retval < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[udp_tunnel_recv_cb] recvmmsg: %s", strerror(errno));
        }
        return;
    }

    if (retval == 0) return;

    /* Process batch and prepare for sendmmsg */
    struct {
        udp_tproxyctx_t *ctx;
        struct mmsghdr msg;
        struct iovec iov;
        skaddr6_t addr;
    } batch_sends[UDP_BATCH_SIZE];
    int send_count = 0;

    udp_tproxyctx_t *deferred_evict[UDP_BATCH_SIZE];
    int deferred_evict_count = 0;

    udp_tunnelctx_keepalive(evloop, tunnelctx);

    for (int i = 0; i < retval; i++) {
        char *buffer = g_udp_batch_buffer[i];
        size_t nrecv = (size_t)msgs[i].msg_len;

        /* Parse tunnel header: ATYP(1) + ADDR + PORT */
        if (nrecv < sizeof(addr_hdr_ipv4_t)) continue;

        uint8_t atype = (uint8_t)buffer[0];
        bool isipv4 = atype == ADDRTYPE_IPV4;
        bool isipv6 = atype == ADDRTYPE_IPV6;

        size_t headerlen;
        if (isipv4) {
            headerlen = sizeof(addr_hdr_ipv4_t);
            if (nrecv < headerlen) continue;
        } else if (isipv6) {
            headerlen = sizeof(addr_hdr_ipv6_t);
            if (nrecv < headerlen) continue;
        } else {
            LOGERR("[udp_tunnel_recv_cb] unsupported address type: 0x%02x", atype);
            continue;
        }

        /* Determine source (bind) address for tproxy response */
        ip_port_t fromipport;
        memset(&fromipport, 0, sizeof(fromipport));
        bool dest_isipv4;

        if (tunnelctx->is_fakedns) {
            fromipport = tunnelctx->orig_dstaddr;
            dest_isipv4 = tunnelctx->dest_is_ipv4;
        } else {
            if (isipv4) {
                addr_hdr_ipv4_t *hdr = (addr_hdr_ipv4_t *)buffer;
                fromipport.ip.ip4 = hdr->ipaddr4;
                fromipport.port = hdr->portnum;
                dest_isipv4 = true;
            } else {
                addr_hdr_ipv6_t *hdr = (addr_hdr_ipv6_t *)buffer;
                memcpy(&fromipport.ip.ip6, &hdr->ipaddr6, IP6BINLEN);
                fromipport.port = hdr->portnum;
                dest_isipv4 = false;
            }
        }

        /* Get or create tproxy context */
        udp_tproxyctx_t *tproxyctx = udp_tproxyctx_find(&g_udp_tproxyctx_table, &fromipport);
        if (!tproxyctx) {
            skaddr6_t fromskaddr;
            memset(&fromskaddr, 0, sizeof(fromskaddr));
            if (dest_isipv4) {
                skaddr4_t *addr = (void *)&fromskaddr;
                addr->sin_family = AF_INET;
                addr->sin_addr.s_addr = fromipport.ip.ip4;
                addr->sin_port = fromipport.port;
            } else {
                fromskaddr.sin6_family = AF_INET6;
                memcpy(&fromskaddr.sin6_addr.s6_addr, &fromipport.ip.ip6, IP6BINLEN);
                fromskaddr.sin6_port = fromipport.port;
            }
            int tproxy_sockfd = new_udp_tpsend_sockfd(dest_isipv4 ? AF_INET : AF_INET6);
            if (tproxy_sockfd < 0) {
                LOGERR("[udp_tunnel_recv_cb] new_udp_tpsend_sockfd failed");
                continue;
            }
            if (bind(tproxy_sockfd, (void *)&fromskaddr, dest_isipv4 ? sizeof(skaddr4_t) : sizeof(skaddr6_t)) < 0) {
                char bind_ipstr[IP6STRLEN];
                portno_t bind_port;
                parse_socket_addr(&fromskaddr, bind_ipstr, &bind_port);
                LOGERR("[udp_tunnel_recv_cb] bind tproxy_sockfd to %s#%hu: %s", bind_ipstr, bind_port, strerror(errno));
                close(tproxy_sockfd);
                continue;
            }
            tproxyctx = mempool_alloc_sized(g_udp_tproxy_pool, sizeof(*tproxyctx));
            if (!tproxyctx) {
                LOGERR("[udp_tunnel_recv_cb] mempool alloc failed for tproxyctx");
                close(tproxy_sockfd);
                continue;
            }
            memcpy(&tproxyctx->key_ipport, &fromipport, sizeof(fromipport));
            tproxyctx->udp_sockfd = tproxy_sockfd;
            tproxyctx->last_active = ev_now(evloop);
            udp_tproxyctx_t *del_context = udp_tproxyctx_add(&g_udp_tproxyctx_table, tproxyctx);
            if (del_context) {
                LOGINF("[udp_tunnel_recv_cb] tproxyctx table full, deferring eviction");
                deferred_evict[deferred_evict_count++] = del_context;
            }
            IF_VERBOSE {
                char src_ipstr[IP6STRLEN];
                char dst_ipstr[IP6STRLEN];
                if (dest_isipv4) {
                    inet_ntop(AF_INET, &fromipport.ip.ip4, src_ipstr, sizeof(src_ipstr));
                    inet_ntop(AF_INET, &tunnelctx->key_ipport.ip.ip4, dst_ipstr, sizeof(dst_ipstr));
                } else {
                    inet_ntop(AF_INET6, &fromipport.ip.ip6, src_ipstr, sizeof(src_ipstr));
                    inet_ntop(AF_INET6, &tunnelctx->key_ipport.ip.ip6, dst_ipstr, sizeof(dst_ipstr));
                }
                LOGINF_RAW("[udp_tunnel_recv_cb] new tproxy context: %s#%hu -> %s#%hu",
                           src_ipstr, ntohs(fromipport.port), dst_ipstr, ntohs(tunnelctx->key_ipport.port));
            }
        } else {
            tproxyctx->last_active = ev_now(evloop);
        }

        /* Prepare destination address */
        ip_port_t *toipport = &tunnelctx->key_ipport;
        memset(&batch_sends[send_count].addr, 0, sizeof(skaddr6_t));
        if (dest_isipv4) {
            skaddr4_t *addr = (void *)&batch_sends[send_count].addr;
            addr->sin_family = AF_INET;
            addr->sin_addr.s_addr = toipport->ip.ip4;
            addr->sin_port = toipport->port;
        } else {
            batch_sends[send_count].addr.sin6_family = AF_INET6;
            memcpy(&batch_sends[send_count].addr.sin6_addr.s6_addr, &toipport->ip.ip6, IP6BINLEN);
            batch_sends[send_count].addr.sin6_port = toipport->port;
        }

        /* Prepare send message — strip tunnel header, send payload only */
        batch_sends[send_count].ctx                        = tproxyctx;
        batch_sends[send_count].iov.iov_base               = buffer + headerlen;
        batch_sends[send_count].iov.iov_len                = nrecv - headerlen;
        batch_sends[send_count].msg.msg_hdr.msg_name       = &batch_sends[send_count].addr;
        batch_sends[send_count].msg.msg_hdr.msg_namelen    = dest_isipv4 ? sizeof(skaddr4_t) : sizeof(skaddr6_t);
        batch_sends[send_count].msg.msg_hdr.msg_iov        = &batch_sends[send_count].iov;
        batch_sends[send_count].msg.msg_hdr.msg_iovlen     = 1;
        batch_sends[send_count].msg.msg_hdr.msg_control    = NULL;
        batch_sends[send_count].msg.msg_hdr.msg_controllen = 0;

        send_count++;
        if (send_count >= UDP_BATCH_SIZE) break;
    }

    /* Batch send using sendmmsg — group by tproxy socket */
    if (send_count > 0) {
        udp_tproxyctx_t *first_ctx = batch_sends[0].ctx;
        bool all_same = true;
        for (int k = 1; k < send_count; k++) {
            if (batch_sends[k].ctx != first_ctx) {
                all_same = false;
                break;
            }
        }

        if (all_same) {
            for (int k = 0; k < send_count; k++) {
                send_msgs[k] = batch_sends[k].msg;
            }
            int sent = sendmmsg(first_ctx->udp_sockfd, send_msgs, (unsigned int)send_count, 0);
            if (sent < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    LOGERR("[udp_tunnel_recv_cb] sendmmsg failed: %s", strerror(errno));
                }
            } else {
#ifdef ENABLE_PERPACKET_LOG
                log_udp_transfer("udp_tunnel_recv_cb", "sendmmsg",
                                 &first_ctx->key_ipport, &tunnelctx->key_ipport,
                                 tunnelctx->dest_is_ipv4, "npackets", sent);
#endif
                if (sent < send_count) {
                    sendmmsg_fallback(tunnelctx, first_ctx, send_msgs, sent, send_count);
                }
            }
        } else {
            /* Slow path: multiple tproxy sockets — group by ctx pointer */
            uint16_t indices[UDP_BATCH_SIZE];
            for (int k = 0; k < send_count; k++) {
                indices[k] = (uint16_t)k;
            }

            for (int i = 0; i < send_count;) {
                udp_tproxyctx_t *ctx = batch_sends[indices[i]].ctx;
                int group_start = i;
                int group_count = 0;

                for (int j = i; j < send_count; j++) {
                    if (batch_sends[indices[j]].ctx == ctx) {
                        if (j != i + group_count) {
                            uint16_t tmp = indices[i + group_count];
                            indices[i + group_count] = indices[j];
                            indices[j] = tmp;
                        }
                        group_count++;
                    }
                }

                for (int k = 0; k < group_count; k++) {
                    send_msgs[k] = batch_sends[indices[group_start + k]].msg;
                }

                int sent = sendmmsg(ctx->udp_sockfd, send_msgs, (unsigned int)group_count, 0);
                if (sent < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        LOGERR("[udp_tunnel_recv_cb] sendmmsg failed: %s", strerror(errno));
                    }
                } else {
#ifdef ENABLE_PERPACKET_LOG
                    log_udp_transfer("udp_tunnel_recv_cb", "sendmmsg",
                                     &ctx->key_ipport, &tunnelctx->key_ipport,
                                     tunnelctx->dest_is_ipv4, "npackets", sent);
#endif
                    if (sent < group_count) {
                        sendmmsg_fallback(tunnelctx, ctx, send_msgs, sent, group_count);
                    }
                }

                i += group_count;
            }
        }
    }

    /* Flush deferred evictions */
    for (int i = 0; i < deferred_evict_count; i++) {
        destroy_tproxyctx(evloop, deferred_evict[i]);
    }
}

/* ── Release helpers ── */

static void destroy_tunnelctx(evloop_t *evloop, udp_tunnelctx_t *context) {
    ev_io_stop(evloop, &context->udp_watcher);
    close(context->udp_watcher.fd);
    mempool_free_sized(g_udp_context_pool, context, sizeof(*context));
}

static void destroy_tproxyctx(evloop_t *evloop __attribute__((unused)), udp_tproxyctx_t *context) {
    close(context->udp_sockfd);
    mempool_free_sized(g_udp_tproxy_pool, context, sizeof(*context));
}

static void gc_release_tunnelctx(evloop_t *evloop, udp_tunnelctx_t *context) {
    if (context->is_forked) {
        udp_tunnelctx_del(&g_udp_fork_table, context);
    } else {
        udp_tunnelctx_del(&g_udp_tunnel_table, context);
    }
    destroy_tunnelctx(evloop, context);
}

static void gc_release_tproxyctx(evloop_t *evloop, udp_tproxyctx_t *context) {
    udp_tproxyctx_del(&g_udp_tproxyctx_table, context);
    destroy_tproxyctx(evloop, context);
}

/* ── GC: sweep callback ── */

#define GC_INTERVAL_SEC      10.0

static __thread evtimer_t g_gc_timer;

static void gc_sweep_cb(evloop_t *evloop, struct ev_watcher *watcher __attribute__((unused)), int revents __attribute__((unused))) {
    ev_tstamp now = ev_now(evloop);
    ev_tstamp idle_timeout = (ev_tstamp)g_udp_idletimeout_sec;
    ev_tstamp tproxy_timeout = g_udp_idletimeout_sec >= 20
                               ? (ev_tstamp)g_udp_idletimeout_sec / 2.0
                               : 10.0;
    int evicted;

    evicted = 0;
    {
        udp_tunnelctx_t *cur, *tmp;
        MYLRU_HASH_FOR(g_udp_tunnel_table, cur, tmp) {
            if ((now - cur->last_active) >= idle_timeout) {
                gc_release_tunnelctx(evloop, cur);
                evicted++;
            }
        }
    }
    if (evicted > 0) {
        LOGINF("[gc_sweep_cb] main table evicted: %d", evicted);
    }

    evicted = 0;
    {
        udp_tunnelctx_t *cur, *tmp;
        MYLRU_HASH_FOR(g_udp_fork_table, cur, tmp) {
            if ((now - cur->last_active) >= idle_timeout) {
                gc_release_tunnelctx(evloop, cur);
                evicted++;
            }
        }
    }
    if (evicted > 0) {
        LOGINF("[gc_sweep_cb] fork table evicted: %d", evicted);
    }

    evicted = 0;
    {
        udp_tproxyctx_t *cur, *tmp;
        MYLRU_HASH_FOR(g_udp_tproxyctx_table, cur, tmp) {
            if ((now - cur->last_active) >= tproxy_timeout) {
                gc_release_tproxyctx(evloop, cur);
                evicted++;
            }
        }
    }
    if (evicted > 0) {
        LOGINF("[gc_sweep_cb] tproxy table evicted: %d", evicted);
    }
}

void udp_proxy_init_gc(evloop_t *evloop) {
    ev_timer_init(&g_gc_timer, gc_sweep_cb, GC_INTERVAL_SEC, GC_INTERVAL_SEC);
    ev_timer_start(evloop, &g_gc_timer);
}

void udp_proxy_stop_gc(evloop_t *evloop) {
    ev_timer_stop(evloop, &g_gc_timer);
}

/* ── Session cleanup wrappers ── */

static void wrapper_tunnel_release_cb(void *evloop_ctx, udp_tunnelctx_t *entry) {
    gc_release_tunnelctx((evloop_t *)evloop_ctx, entry);
}

static void wrapper_tproxy_release_cb(void *evloop_ctx, udp_tproxyctx_t *entry) {
    gc_release_tproxyctx((evloop_t *)evloop_ctx, entry);
}

void udp_proxy_close_all_sessions(evloop_t *evloop) {
    LOGINF("[udp_proxy_close_all_sessions] cleaning up remaining sessions...");

    udp_proxy_stop_gc(evloop);
    udp_tunnelctx_clear_main(&g_udp_tunnel_table, wrapper_tunnel_release_cb, evloop);
    udp_tunnelctx_clear_fork(&g_udp_fork_table, wrapper_tunnel_release_cb, evloop);
    udp_tproxyctx_clear(&g_udp_tproxyctx_table, wrapper_tproxy_release_cb, evloop);
}
