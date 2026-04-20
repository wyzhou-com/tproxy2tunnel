#include "tcp_proxy.h"

#include <assert.h>
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

typedef struct {
    evio_t   *self_watcher;
    evio_t   *peer_watcher;
    int      *self_pipefd;
    int      *peer_pipefd;
    bool     *self_eof;
    bool     *peer_eof;
    uint32_t *self_pending;
    uint32_t *peer_pending;
    const char *self_name;
    const char *peer_name;
} tcp_stream_side_t;

static void tcp_tunnel_on_setup_timeout(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static void tcp_tunnel_on_connected(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static void tcp_tunnel_on_writable(evloop_t *evloop, struct ev_watcher *watcher, int revents);
static bool tcp_setup_prepare_header(int client_sockfd, bool isipv4,
                                     uint8_t addr_hdr[], size_t *addr_hdr_len);
static int tcp_tunnel_connect(const uint8_t *addr_hdr, size_t addr_hdr_len,
                              ssize_t *tfo_nsend);
static tcp_session_t *tcp_session_create(int client_sockfd, int remote_sockfd,
        const uint8_t *addr_hdr, size_t addr_hdr_len,
        ssize_t tfo_nsend);
static bool tcp_session_enter_forwarding(evloop_t *evloop, tcp_session_t *session);
static bool tcp_stream_start_forwarding(evloop_t *evloop, tcp_session_t *session);
static void tcp_stream_on_forward(evloop_t *evloop, struct ev_watcher *watcher, int revents);

static inline tcp_session_t *tcp_session_from_watcher(evio_t *watcher) {
    return (tcp_session_t *)watcher->data;
}

static tcp_stream_side_t tcp_stream_side_from_watcher(tcp_session_t *session, evio_t *self_watcher) {
    bool self_is_client = (self_watcher == &session->client_watcher);
    return (tcp_stream_side_t) {
        .self_watcher  = self_watcher,
        .peer_watcher  = self_is_client ? &session->remote_watcher : &session->client_watcher,
        .self_pipefd   = self_is_client ? session->client_pipefd : session->remote_pipefd,
        .peer_pipefd   = self_is_client ? session->remote_pipefd : session->client_pipefd,
        .self_eof      = self_is_client ? &session->fwd.client_eof : &session->fwd.remote_eof,
        .peer_eof      = self_is_client ? &session->fwd.remote_eof : &session->fwd.client_eof,
        .self_pending  = self_is_client ? &session->fwd.client_pending : &session->fwd.remote_pending,
        .peer_pending  = self_is_client ? &session->fwd.remote_pending : &session->fwd.client_pending,
        .self_name     = self_is_client ? "client" : "remote",
        .peer_name     = self_is_client ? "remote" : "client",
    };
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

static inline void tcp_session_release(evloop_t *evloop, tcp_session_t *session, bool is_tcp_reset) {
    evio_t *client_watcher = &session->client_watcher;
    evio_t *remote_watcher = &session->remote_watcher;
    assert(client_watcher->fd >= 0);
    assert(remote_watcher->fd >= 0);

    ev_io_stop(evloop, client_watcher);
    ev_io_stop(evloop, remote_watcher);
    ev_timer_stop(evloop, &session->connect_timer);
    if (is_tcp_reset) {
        tcp_close_by_rst(client_watcher->fd);
        tcp_close_by_rst(remote_watcher->fd);
    } else {
        close(client_watcher->fd);
        close(remote_watcher->fd);
    }

    if (session->client_pipefd[0] != -1) close(session->client_pipefd[0]);
    if (session->client_pipefd[1] != -1) close(session->client_pipefd[1]);
    if (session->remote_pipefd[0] != -1) close(session->remote_pipefd[0]);
    if (session->remote_pipefd[1] != -1) close(session->remote_pipefd[1]);

    /* Remove from session list */
    if (session->next) session->next->prev = session->prev;
    if (session->prev) {
        session->prev->next = session->next;
    } else {
        g_tcp_session_head = session->next;
    }

    mempool_free_sized(g_tcp_session_pool, session, sizeof(*session));
}

void tcp_proxy_close_all_sessions(evloop_t *evloop) {
    LOGINF("[tcp_proxy] cleaning up remaining sessions...");
    tcp_session_t *curr = g_tcp_session_head;
    while (curr) {
        tcp_session_t *next = curr->next;
        tcp_session_release(evloop, curr, false);
        curr = next;
    }
}

static void tcp_tunnel_on_setup_timeout(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    tcp_session_t *session = (tcp_session_t *)watcher->data;
    LOGERR("[tcp_tunnel] connect/header-send timed out (%gs), closing", TCP_CONNECT_TIMEOUT_SEC);
    tcp_session_release(evloop, session, true);
}

static bool tcp_setup_prepare_header(int client_sockfd, bool isipv4,
                                     uint8_t addr_hdr[], size_t *addr_hdr_len) {
    skaddr6_t skaddr;
    char ipstr[IP6STRLEN];
    portno_t portno;

    if (!get_tcp_orig_dstaddr(isipv4 ? AF_INET : AF_INET6, client_sockfd, &skaddr, !(g_options & OPT_TCP_USE_REDIRECT))) {
        return false;
    }
    IF_VERBOSE {
        parse_socket_addr(&skaddr, ipstr, &portno);
        LOGINF_RAW("[tcp_setup] target socket address: %s#%hu", ipstr, portno);
    }

    const char *fake_domain = NULL;
    if ((g_options & OPT_ENABLE_FAKEDNS) && isipv4) {
        uint32_t target_ip = ((skaddr4_t *)&skaddr)->sin_addr.s_addr;
        bool is_miss;
        fake_domain = fakedns_try_resolve(target_ip, &is_miss);
        if (is_miss) {
            LOGERR("[tcp_fakedns] miss for FakeIP: %u.%u.%u.%u, dropping connection",
                   ((uint8_t *)&target_ip)[0], ((uint8_t *)&target_ip)[1],
                   ((uint8_t *)&target_ip)[2], ((uint8_t *)&target_ip)[3]);
            return false;
        }
        IF_VERBOSE if (fake_domain) {
            LOGINF_RAW("[tcp_fakedns] hit: %u.%u.%u.%u -> %s",
                       ((uint8_t *)&target_ip)[0], ((uint8_t *)&target_ip)[1],
                       ((uint8_t *)&target_ip)[2], ((uint8_t *)&target_ip)[3],
                       fake_domain);
        }
    }

    if (!addr_header_build(addr_hdr, TCP_ADDR_HDR_MAXLEN, &skaddr, fake_domain, addr_hdr_len)) {
        LOGERR("[tcp_setup] failed to build tunnel address header");
        return false;
    }
    return true;
}

static int tcp_tunnel_connect(const uint8_t *addr_hdr, size_t addr_hdr_len,
                              ssize_t *tfo_nsend) {
    int remote_sockfd = new_tcp_connect_sockfd(g_server_skaddr.sin6_family, g_tcp_syncnt_max);
    if (remote_sockfd < 0) {
        LOGERR("[tcp_tunnel] new_tcp_connect_sockfd: %s", strerror(errno));
        return -1;
    }

    const void *tfo_data = NULL;
    size_t tfo_datalen = 0;
    if (g_options & OPT_ENABLE_TFO_CONNECT) {
        tfo_data = addr_hdr;
        tfo_datalen = addr_hdr_len;
    }

    *tfo_nsend = -1;
    if (!tcp_connect(remote_sockfd, &g_server_skaddr, tfo_data, tfo_datalen, tfo_nsend)) {
        LOGERR("[tcp_tunnel] connect to %s#%hu: %s", g_server_ipstr, g_server_portno, strerror(errno));
        close(remote_sockfd);
        return -1;
    }
    if (*tfo_nsend >= 0) {
        LOGINF("[tcp_tunnel] tfo send to %s#%hu, nsend:%zd", g_server_ipstr, g_server_portno, *tfo_nsend);
    } else {
        LOGINF("[tcp_tunnel] try to connect to %s#%hu ...", g_server_ipstr, g_server_portno);
    }

    return remote_sockfd;
}

static tcp_session_t *tcp_session_create(int client_sockfd, int remote_sockfd,
        const uint8_t *addr_hdr, size_t addr_hdr_len,
        ssize_t tfo_nsend) {
    tcp_session_t *session = mempool_alloc_sized(g_tcp_session_pool, sizeof(*session));
    if (!session) {
        LOGERR("[tcp_session] mempool alloc failed");
        return NULL;
    }
    session->client_pipefd[0] = session->client_pipefd[1] = -1;
    session->remote_pipefd[0] = session->remote_pipefd[1] = -1;

    session->client_watcher.data = session;
    session->remote_watcher.data = session;
    ev_io_init(&session->client_watcher, tcp_stream_on_forward, client_sockfd, EV_READ);
    ev_io_init(&session->remote_watcher, tcp_tunnel_on_connected, remote_sockfd, EV_WRITE);

    memcpy(session->hs.addr_hdr, addr_hdr, addr_hdr_len);
    session->hs.addr_hdr_len = (uint16_t)addr_hdr_len;
    session->hs.send_offset = (uint16_t)(tfo_nsend >= 0 ? tfo_nsend : 0);

    session->connect_timer.data = session;
    ev_timer_init(&session->connect_timer, tcp_tunnel_on_setup_timeout, TCP_CONNECT_TIMEOUT_SEC, 0.);

    session->prev = NULL;
    session->next = g_tcp_session_head;
    if (session->next) session->next->prev = session;
    g_tcp_session_head = session;

    return session;
}

void tcp_proxy_on_accept(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
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
            LOGERR("[tcp_proxy] accept tcp%s socket: %s", isipv4 ? "4" : "6", strerror(errno));
        }
        return;
    }
    IF_VERBOSE {
        parse_socket_addr(&skaddr, ipstr, &portno);
        LOGINF_RAW("[tcp_proxy] source socket address: %s#%hu", ipstr, portno);
    }

    uint8_t addr_hdr_buf[TCP_ADDR_HDR_MAXLEN];
    size_t addr_hdr_len = 0;
    if (!tcp_setup_prepare_header(client_sockfd, isipv4, addr_hdr_buf, &addr_hdr_len)) {
        tcp_close_by_rst(client_sockfd);
        return;
    }

    ssize_t tfo_nsend = -1;
    int remote_sockfd = tcp_tunnel_connect(addr_hdr_buf, addr_hdr_len, &tfo_nsend);
    if (remote_sockfd < 0) {
        tcp_close_by_rst(client_sockfd);
        return;
    }

    tcp_session_t *session = tcp_session_create(client_sockfd, remote_sockfd,
                             addr_hdr_buf, addr_hdr_len,
                             tfo_nsend);
    if (!session) {
        tcp_close_by_rst(client_sockfd);
        close(remote_sockfd);
        return;
    }

    ev_io_start(evloop, &session->remote_watcher);
    ev_timer_start(evloop, &session->connect_timer);
}

static bool tcp_session_enter_forwarding(evloop_t *evloop, tcp_session_t *session) {
    evio_t *remote_watcher = &session->remote_watcher;
    ev_io_stop(evloop, remote_watcher);
    ev_io_init(remote_watcher, tcp_stream_on_forward, remote_watcher->fd, EV_READ);
    if (!tcp_stream_start_forwarding(evloop, session)) return false;
    ev_io_start(evloop, remote_watcher);
    return true;
}

static void tcp_tunnel_on_connected(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *remote_watcher = (evio_t *)watcher;
    tcp_session_t *session = tcp_session_from_watcher(remote_watcher);
    if (tcp_has_error(remote_watcher->fd)) {
        LOGERR("[tcp_tunnel] connect to %s#%hu: %s", g_server_ipstr, g_server_portno, strerror(errno));
        tcp_session_release(evloop, session, true);
        return;
    }
    LOGINF("[tcp_tunnel] connect to %s#%hu succeeded", g_server_ipstr, g_server_portno);

    if (session->hs.send_offset >= session->hs.addr_hdr_len) {
        /* TFO path: header was piggybacked on SYN, connect is now confirmed —
         * skip the header-send stage and go straight to forwarding. */
        (void)tcp_session_enter_forwarding(evloop, session);
        return;
    }

    ev_set_cb(remote_watcher, tcp_tunnel_on_writable);
    ev_invoke(evloop, remote_watcher, EV_WRITE);
}

/* return: -1(error_occurred); 0(partial_sent); 1(completely_sent) */
static int tcp_tunnel_send_header_partial(evloop_t *evloop, tcp_session_t *session) {
    evio_t *remote_watcher = &session->remote_watcher;
    const uint8_t *addr_hdr = session->hs.addr_hdr;
    size_t addr_hdr_len = session->hs.addr_hdr_len;
    uint16_t *send_offset = &session->hs.send_offset;
    ssize_t nsend = send(remote_watcher->fd, addr_hdr + *send_offset, addr_hdr_len - *send_offset, 0);
    if (nsend < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[tcp_tunnel] send to %s#%hu: %s", g_server_ipstr, g_server_portno, strerror(errno));
            tcp_session_release(evloop, session, true);
            return -1;
        }
        return 0;
    }
    LOGINF("[tcp_tunnel] send to %s#%hu, nsend:%zd", g_server_ipstr, g_server_portno, nsend);
    *send_offset += (uint16_t)nsend;
    if (*send_offset >= addr_hdr_len) {
        return 1;
    }
    return 0;
}

static void tcp_tunnel_on_writable(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *remote_watcher = (evio_t *)watcher;
    tcp_session_t *session = tcp_session_from_watcher(remote_watcher);
    if (tcp_tunnel_send_header_partial(evloop, session) != 1) {
        return; /* partial or error */
    }
    /* Header fully sent — go straight to forwarding (no response to wait for) */
    (void)tcp_session_enter_forwarding(evloop, session);
}

static bool tcp_stream_start_forwarding(evloop_t *evloop, tcp_session_t *session) {
    session->fwd.client_eof = false;
    session->fwd.remote_eof = false;
    session->fwd.client_pending = 0;
    session->fwd.remote_pending = 0;

    if (new_nonblock_pipefd(session->client_pipefd) < 0) {
        LOGERR("[tcp_stream] failed to create client pipe");
        tcp_session_release(evloop, session, true);
        return false;
    }
    if (new_nonblock_pipefd(session->remote_pipefd) < 0) {
        LOGERR("[tcp_stream] failed to create remote pipe");
        tcp_session_release(evloop, session, true);
        return false;
    }

    ev_timer_stop(evloop, &session->connect_timer);
    ev_io_start(evloop, &session->client_watcher);
    LOGINF("[tcp_stream] tunnel is ready, start forwarding ...");
    return true;
}

static void tcp_stream_on_forward(evloop_t *evloop, struct ev_watcher *watcher, int revents) {
    evio_t *self_watcher = (evio_t *)watcher;
    tcp_session_t *session = tcp_session_from_watcher(self_watcher);
    tcp_stream_side_t side = tcp_stream_side_from_watcher(session, self_watcher);

    if (revents & EV_READ) {
        ssize_t nrecv = splice(side.self_watcher->fd, NULL, side.self_pipefd[1], NULL, TCP_SPLICE_MAXLEN, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        if (nrecv < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                if (errno == ECONNRESET) {
                    IF_VERBOSE {
                        LOGINF_RAW("[tcp_stream] recv from %s stream: %s, cascade RST", side.self_name, strerror(errno));
                    }
                } else {
                    IF_VERBOSE {
                        LOGERR("[tcp_stream] recv from %s stream: %s", side.self_name, strerror(errno));
                    }
                }
                tcp_session_release(evloop, session, true);
                return;
            }
            goto DO_WRITE;
        }
        if (nrecv == 0) {
            LOGINF("[tcp_stream] recv FIN from %s stream", side.self_name);
            *side.self_eof = true;
            ev_io_remove_event(evloop, side.self_watcher, EV_READ);

            if (*side.self_pending == 0) {
                shutdown(side.peer_watcher->fd, SHUT_WR);
            }
        } else {
            ssize_t nsend = splice(side.self_pipefd[0], NULL, side.peer_watcher->fd, NULL, (size_t)nrecv, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
            if (nsend < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    if (errno == EPIPE || errno == ECONNRESET) {
                        IF_VERBOSE {
                            LOGINF_RAW("[tcp_stream] send to %s stream: %s, cascade RST", side.peer_name, strerror(errno));
                        }
                    } else {
                        LOGERR("[tcp_stream] send to %s stream: %s", side.peer_name, strerror(errno));
                    }
                    tcp_session_release(evloop, session, true);
                    return;
                }
                nsend = 0;
            }
            if (nsend < nrecv) {
                *side.self_pending = (uint32_t)(nrecv - nsend);
                ev_io_remove_event(evloop, side.self_watcher, EV_READ);
                ev_io_add_event(evloop, side.peer_watcher, EV_WRITE);
            }
        }
    }

DO_WRITE:
    if (revents & EV_WRITE) {
        ssize_t nsend = splice(side.peer_pipefd[0], NULL, side.self_watcher->fd, NULL, *side.peer_pending, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        if (nsend < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                if (errno == EPIPE || errno == ECONNRESET) {
                    IF_VERBOSE {
                        LOGINF_RAW("[tcp_stream] send to %s stream: %s, cascade RST", side.self_name, strerror(errno));
                    }
                } else {
                    LOGERR("[tcp_stream] send to %s stream: %s", side.self_name, strerror(errno));
                }
                tcp_session_release(evloop, session, true);
            }
            return;
        }
        if (nsend > 0) {
            *side.peer_pending -= (uint32_t)nsend;

            if (*side.peer_pending == 0) {
                ev_io_remove_event(evloop, side.self_watcher, EV_WRITE);

                if (!*side.peer_eof) {
                    ev_io_add_event(evloop, side.peer_watcher, EV_READ);
                } else {
                    shutdown(side.self_watcher->fd, SHUT_WR);
                }
            }
        }
    }

    if (session->fwd.client_eof && session->fwd.remote_eof &&
            session->fwd.client_pending == 0 && session->fwd.remote_pending == 0) {
        LOGINF("[tcp_stream] both streams are EOF and pipes are empty, release session");
        tcp_session_release(evloop, session, false);
    }
}
