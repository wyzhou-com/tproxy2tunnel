#include "tcp_proxy.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "ctx.h"
#include "fakedns.h"
#include "logutils.h"

/* splice() api */
#ifndef SPLICE_F_MOVE
#define SPLICE_F_MOVE 1

#undef  SPLICE_F_NONBLOCK
#define SPLICE_F_NONBLOCK 2

#define splice(fdin, offin, fdout, offout, len, flags) syscall(__NR_splice, fdin, offin, fdout, offout, len, flags)
#endif

/* Forward declarations */
static void tcp_connect_timeout_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static void tcp_tunnel_connect_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static void tcp_tunnel_send_header_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static bool tcp_start_forwarding(evloop_t *evloop, tcp_tunnel_ctx_t *context);
static void tcp_stream_payload_forward_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);

static inline tcp_tunnel_ctx_t* get_ctx_by_watcher(evio_t *watcher) {
    return (tcp_tunnel_ctx_t *)watcher->data;
}

static inline void ev_io_remove_event(evloop_t *evloop, evio_t *w, int event) {
    int new_events = w->events & ~event;
    ev_io_stop(evloop, w);
    if (new_events) {
        ev_io_set(w, w->fd, new_events);
        ev_io_start(evloop, w);
    }
}

static inline void ev_io_add_event(evloop_t *evloop, evio_t *w, int event) {
    ev_io_stop(evloop, w);
    ev_io_set(w, w->fd, w->events | event);
    ev_io_start(evloop, w);
}

static inline void tcp_context_release(evloop_t *evloop, tcp_tunnel_ctx_t *context, bool is_tcp_reset) {
    evio_t *client_watcher = &context->client_watcher;
    evio_t *remote_watcher = &context->remote_watcher;
    ev_io_stop(evloop, client_watcher);
    ev_io_stop(evloop, remote_watcher);
    ev_timer_stop(evloop, &context->connect_timer);
    if (is_tcp_reset) {
        tcp_close_by_rst(client_watcher->fd);
        tcp_close_by_rst(remote_watcher->fd);
    } else {
        close(client_watcher->fd);
        close(remote_watcher->fd);
    }

    if (context->client_pipefd[0] != -1) close(context->client_pipefd[0]);
    if (context->client_pipefd[1] != -1) close(context->client_pipefd[1]);
    if (context->remote_pipefd[0] != -1) close(context->remote_pipefd[0]);
    if (context->remote_pipefd[1] != -1) close(context->remote_pipefd[1]);

    /* Remove from session list */
    if (context->next) context->next->prev = context->prev;
    if (context->prev) {
        context->prev->next = context->next;
    } else {
        g_tcp_session_head = context->next;
    }

    mempool_free_sized(g_tcp_context_pool, context, sizeof(*context));
}

void tcp_proxy_close_all_sessions(evloop_t *evloop) {
    LOGINF("[tcp_proxy_close_all_sessions] cleaning up remaining sessions...");
    tcp_tunnel_ctx_t *curr = (tcp_tunnel_ctx_t *)g_tcp_session_head;
    while (curr) {
        tcp_tunnel_ctx_t *next = curr->next;
        tcp_context_release(evloop, curr, false);
        curr = next;
    }
}

static void tcp_connect_timeout_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    tcp_tunnel_ctx_t *context = (tcp_tunnel_ctx_t *)watcher->data;
    LOGERR("[tcp_connect_timeout_cb] connect/header-send timed out (%gs), closing", TCP_CONNECT_TIMEOUT_SEC);
    tcp_context_release(evloop, context, true);
}

void tcp_tproxy_accept_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *accept_watcher = (evio_t *)watcher;
    bool isipv4 = (intptr_t)accept_watcher->data;
    skaddr6_t skaddr;
    char ipstr[IP6STRLEN];
    portno_t portno;

    int client_sockfd = tcp_accept(accept_watcher->fd, (void *)&skaddr, &(socklen_t) {
        sizeof(skaddr)
    });
    if (client_sockfd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[tcp_tproxy_accept_cb] accept tcp%s socket: %s", isipv4 ? "4" : "6", strerror(errno));
        }
        return;
    }
    IF_VERBOSE {
        parse_socket_addr(&skaddr, ipstr, &portno);
        LOGINF_RAW("[tcp_tproxy_accept_cb] source socket address: %s#%hu", ipstr, portno);
    }

    if (!get_tcp_orig_dstaddr(isipv4 ? AF_INET : AF_INET6, client_sockfd, &skaddr, !(g_options & OPT_TCP_USE_REDIRECT))) {
        tcp_close_by_rst(client_sockfd);
        return;
    }
    IF_VERBOSE {
        parse_socket_addr(&skaddr, ipstr, &portno);
        LOGINF_RAW("[tcp_tproxy_accept_cb] target socket address: %s#%hu", ipstr, portno);
    }

    /* FakeDNS reverse lookup for domain resolution */
    const char *fake_domain = NULL;
    if ((g_options & OPT_ENABLE_FAKEDNS) && isipv4) {
        uint32_t target_ip = ((skaddr4_t *)&skaddr)->sin_addr.s_addr;
        bool is_miss;
        fake_domain = fakedns_try_resolve(target_ip, &is_miss);
        if (is_miss) {
            LOGERR("[tcp_tproxy_accept_cb] fakedns miss for FakeIP: %u.%u.%u.%u, dropping connection",
                   ((uint8_t *)&target_ip)[0], ((uint8_t *)&target_ip)[1],
                   ((uint8_t *)&target_ip)[2], ((uint8_t *)&target_ip)[3]);
            tcp_close_by_rst(client_sockfd);
            return;
        }
        IF_VERBOSE if (fake_domain) {
            LOGINF_RAW("[tcp_tproxy_accept_cb] fakedns hit: %u.%u.%u.%u -> %s",
                       ((uint8_t *)&target_ip)[0], ((uint8_t *)&target_ip)[1],
                       ((uint8_t *)&target_ip)[2], ((uint8_t *)&target_ip)[3],
                       fake_domain);
        }
    }

    /* Build address header on stack (needed before connect for TFO) */
    uint8_t addr_hdr_buf[TCP_ADDR_HDR_MAXLEN];
    size_t addr_hdr_len = 0;
    if (!addr_header_build(addr_hdr_buf, sizeof(addr_hdr_buf), &skaddr, fake_domain, &addr_hdr_len)) {
        LOGERR("[tcp_tproxy_accept_cb] failed to build tunnel address header");
        tcp_close_by_rst(client_sockfd);
        return;
    }

    int remote_sockfd = new_tcp_connect_sockfd(g_server_skaddr.sin6_family, g_tcp_syncnt_max);
    if (remote_sockfd < 0) {
        LOGERR("[tcp_tproxy_accept_cb] new_tcp_connect_sockfd: %s", strerror(errno));
        tcp_close_by_rst(client_sockfd);
        return;
    }

    const void *tfo_data = NULL;
    size_t tfo_datalen = 0;
    if (g_options & OPT_ENABLE_TFO_CONNECT) {
        tfo_data = addr_hdr_buf;
        tfo_datalen = addr_hdr_len;
    }
    ssize_t tfo_nsend = -1;

    if (!tcp_connect(remote_sockfd, &g_server_skaddr, tfo_data, tfo_datalen, &tfo_nsend)) {
        LOGERR("[tcp_tproxy_accept_cb] connect to %s#%hu: %s", g_server_ipstr, g_server_portno, strerror(errno));
        tcp_close_by_rst(client_sockfd);
        close(remote_sockfd);
        return;
    }
    if (tfo_nsend >= 0) {
        LOGINF("[tcp_tproxy_accept_cb] tfo send to %s#%hu, nsend:%zd", g_server_ipstr, g_server_portno, tfo_nsend);
    } else {
        LOGINF("[tcp_tproxy_accept_cb] try to connect to %s#%hu ...", g_server_ipstr, g_server_portno);
    }

    tcp_tunnel_ctx_t *context = mempool_alloc_sized(g_tcp_context_pool, sizeof(*context));
    if (!context) {
        LOGERR("[tcp_tproxy_accept_cb] mempool_alloc failed");
        tcp_close_by_rst(client_sockfd);
        close(remote_sockfd);
        return;
    }
    context->client_pipefd[0] = context->client_pipefd[1] = -1;
    context->remote_pipefd[0] = context->remote_pipefd[1] = -1;
    context->client_eof = false;
    context->remote_eof = false;

    /* Add to session list (prepend) */
    context->prev = NULL;
    context->next = (tcp_tunnel_ctx_t *)g_tcp_session_head;
    if (context->next) context->next->prev = context;
    g_tcp_session_head = context;

    /* Link watcher data to parent context */
    context->client_watcher.data = context;
    context->remote_watcher.data = context;

    evio_t *io_watcher = &context->client_watcher;
    ev_io_init(io_watcher, tcp_stream_payload_forward_cb, client_sockfd, EV_READ);

    /* Store address header in context */
    memcpy(context->hs.addr_hdr, addr_hdr_buf, addr_hdr_len);
    context->hs.addr_hdr_len = (uint16_t)addr_hdr_len;

    /* All TFO states funnel through tcp_tunnel_connect_cb, which is the single
     * point that confirms SYN-ACK via tcp_has_error() before dispatching to the
     * next stage (forwarding or header-send) based on send_offset. */
    io_watcher = &context->remote_watcher;
    ev_io_init(io_watcher, tcp_tunnel_connect_cb, remote_sockfd, EV_WRITE);
    context->hs.send_offset = (uint16_t)(tfo_nsend >= 0 ? tfo_nsend : 0);

    context->connect_timer.data = context;
    ev_timer_init(&context->connect_timer, tcp_connect_timeout_cb, TCP_CONNECT_TIMEOUT_SEC, 0.);

    ev_io_start(evloop, io_watcher);
    ev_timer_start(evloop, &context->connect_timer);
}

/* ── Tunnel callbacks: connect → send header → forward ── */

static void tcp_tunnel_connect_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *remote_watcher = (evio_t *)watcher;
    tcp_tunnel_ctx_t *context = get_ctx_by_watcher(remote_watcher);
    if (tcp_has_error(remote_watcher->fd)) {
        LOGERR("[tcp_tunnel_connect_cb] connect to %s#%hu: %s", g_server_ipstr, g_server_portno, strerror(errno));
        tcp_context_release(evloop, context, true);
        return;
    }
    LOGINF("[tcp_tunnel_connect_cb] connect to %s#%hu succeeded", g_server_ipstr, g_server_portno);

    if (context->hs.send_offset >= context->hs.addr_hdr_len) {
        /* TFO path: header was piggybacked on SYN, handshake now confirmed —
         * skip the header-send stage and go straight to forwarding. */
        context->hs.send_offset = 0;
        ev_io_stop(evloop, remote_watcher);
        ev_io_init(remote_watcher, tcp_stream_payload_forward_cb, remote_watcher->fd, EV_READ);
        if (!tcp_start_forwarding(evloop, context)) return;
        ev_io_start(evloop, remote_watcher);
        return;
    }

    ev_set_cb(remote_watcher, tcp_tunnel_send_header_cb);
    ev_invoke(evloop, remote_watcher, EV_WRITE);
}

/* return: -1(error_occurred); 0(partial_sent); 1(completely_sent) */
static int tcp_send_partial(const char *funcname, evloop_t *evloop, evio_t *remote_watcher,
                            const void *data, size_t datalen, uint16_t *offset) {
    tcp_tunnel_ctx_t *context = get_ctx_by_watcher(remote_watcher);
    const uint8_t *pdata = (const uint8_t *)data;
    ssize_t nsend = send(remote_watcher->fd, pdata + *offset, datalen - *offset, 0);
    if (nsend < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[%s] send to %s#%hu: %s", funcname, g_server_ipstr, g_server_portno, strerror(errno));
            tcp_context_release(evloop, context, true);
            return -1;
        }
        return 0;
    }
    LOGINF("[%s] send to %s#%hu, nsend:%zd", funcname, g_server_ipstr, g_server_portno, nsend);
    *offset += (uint16_t)nsend;
    if (*offset >= datalen) {
        *offset = 0;
        return 1;
    }
    return 0;
}

static void tcp_tunnel_send_header_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *remote_watcher = (evio_t *)watcher;
    tcp_tunnel_ctx_t *context = get_ctx_by_watcher(remote_watcher);
    if (tcp_send_partial("tcp_tunnel_send_header_cb", evloop, remote_watcher,
                         context->hs.addr_hdr, context->hs.addr_hdr_len,
                         &context->hs.send_offset) != 1) {
        return; /* partial or error */
    }
    /* Header fully sent — go straight to forwarding (no response to wait for) */
    ev_io_stop(evloop, remote_watcher);
    ev_io_init(remote_watcher, tcp_stream_payload_forward_cb, remote_watcher->fd, EV_READ);
    if (!tcp_start_forwarding(evloop, context)) return;
    ev_io_start(evloop, remote_watcher);
}

/* ── Shared helper: transition to forwarding ── */

static bool tcp_start_forwarding(evloop_t *evloop, tcp_tunnel_ctx_t *context) {
    context->fwd.client_pending = 0;
    context->fwd.remote_pending = 0;

    if (new_nonblock_pipefd(context->client_pipefd) < 0) {
        LOGERR("[tcp_start_forwarding] failed to create client pipe");
        tcp_context_release(evloop, context, true);
        return false;
    }
    if (new_nonblock_pipefd(context->remote_pipefd) < 0) {
        LOGERR("[tcp_start_forwarding] failed to create remote pipe");
        tcp_context_release(evloop, context, true);
        return false;
    }

    ev_timer_stop(evloop, &context->connect_timer);
    ev_io_start(evloop, &context->client_watcher);
    LOGINF("[tcp_start_forwarding] tunnel is ready, start forwarding ...");
    return true;
}

/* ── Bidirectional splice-based forwarding ── */

static void tcp_stream_payload_forward_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents) {
    evio_t *self_watcher = (evio_t *)watcher;
    tcp_tunnel_ctx_t *context = get_ctx_by_watcher(self_watcher);
    bool self_is_client = (self_watcher == &context->client_watcher);
    evio_t *peer_watcher = self_is_client ? &context->remote_watcher : &context->client_watcher;
    bool *self_eof = self_is_client ? &context->client_eof : &context->remote_eof;
    bool *peer_eof = self_is_client ? &context->remote_eof : &context->client_eof;
    uint32_t *self_pending = self_is_client ? &context->fwd.client_pending : &context->fwd.remote_pending;
    uint32_t *peer_pending = self_is_client ? &context->fwd.remote_pending : &context->fwd.client_pending;

    if (revents & EV_READ) {
        int *self_pipefd = self_is_client ? context->client_pipefd : context->remote_pipefd;
        ssize_t nrecv = splice(self_watcher->fd, NULL, self_pipefd[1], NULL, TCP_SPLICE_MAXLEN, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        if (nrecv < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                if (errno == ECONNRESET) {
                    IF_VERBOSE {
                        LOGINF_RAW("[tcp_stream_payload_forward_cb] recv from %s stream: %s, cascade RST", self_is_client ? "client" : "remote", strerror(errno));
                    }
                } else {
                    IF_VERBOSE {
                        LOGERR("[tcp_stream_payload_forward_cb] recv from %s stream: %s", self_is_client ? "client" : "remote", strerror(errno));
                    }
                }
                tcp_context_release(evloop, context, true);
                return;
            }
            goto DO_WRITE;
        }
        if (nrecv == 0) {
            LOGINF("[tcp_stream_payload_forward_cb] recv FIN from %s stream", self_is_client ? "client" : "remote");
            *self_eof = true;
            ev_io_remove_event(evloop, self_watcher, EV_READ);

            if (*self_pending == 0) {
                shutdown(peer_watcher->fd, SHUT_WR);
            }
        } else {
            ssize_t nsend = splice(self_pipefd[0], NULL, peer_watcher->fd, NULL, (size_t)nrecv, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
            if (nsend < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    if (errno == EPIPE || errno == ECONNRESET) {
                        IF_VERBOSE {
                            LOGINF_RAW("[tcp_stream_payload_forward_cb] send to %s stream: %s, cascade RST", self_is_client ? "remote" : "client", strerror(errno));
                        }
                    } else {
                        LOGERR("[tcp_stream_payload_forward_cb] send to %s stream: %s", self_is_client ? "remote" : "client", strerror(errno));
                    }
                    tcp_context_release(evloop, context, true);
                    return;
                }
                nsend = 0;
            }
            if (nsend < nrecv) {
                *self_pending = (uint32_t)(nrecv - nsend);
                ev_io_remove_event(evloop, self_watcher, EV_READ);
                ev_io_add_event(evloop, peer_watcher, EV_WRITE);
            }
        }
    }

DO_WRITE:
    if (revents & EV_WRITE) {
        int *peer_pipefd = self_is_client ? context->remote_pipefd : context->client_pipefd;

        ssize_t nsend = splice(peer_pipefd[0], NULL, self_watcher->fd, NULL, *peer_pending, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        if (nsend < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                if (errno == EPIPE || errno == ECONNRESET) {
                    IF_VERBOSE {
                        LOGINF_RAW("[tcp_stream_payload_forward_cb] send to %s stream: %s, cascade RST", self_is_client ? "client" : "remote", strerror(errno));
                    }
                } else {
                    LOGERR("[tcp_stream_payload_forward_cb] send to %s stream: %s", self_is_client ? "client" : "remote", strerror(errno));
                }
                tcp_context_release(evloop, context, true);
            }
            return;
        }
        if (nsend > 0) {
            *peer_pending -= (uint32_t)nsend;

            if (*peer_pending == 0) {
                ev_io_remove_event(evloop, self_watcher, EV_WRITE);

                if (!*peer_eof) {
                    ev_io_add_event(evloop, peer_watcher, EV_READ);
                } else {
                    shutdown(self_watcher->fd, SHUT_WR);
                }
            }
        }
    }

    if (context->client_eof && context->remote_eof && context->fwd.client_pending == 0 && context->fwd.remote_pending == 0) {
        LOGINF("[tcp_stream_payload_forward_cb] both streams are EOF and pipes are empty, release ctx");
        tcp_context_release(evloop, context, false);
    }
}
