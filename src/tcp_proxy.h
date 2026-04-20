#ifndef TPROXY2TUNNEL_TCP_PROXY_H
#define TPROXY2TUNNEL_TCP_PROXY_H

#include <stdbool.h>
#include <stdint.h>

#include "ev_types.h"
#include "addr_header.h"
#include "fakedns.h"

#define TCP_SPLICE_MAXLEN         (64 * 1024)
#define TCP_CONNECT_TIMEOUT_SEC   5.0

#define TCP_ADDR_HDR_MAXLEN \
    (sizeof(addr_hdr_domain_t) + (FAKEDNS_MAX_DOMAIN_LEN - 1) + sizeof(portno_t))

/* One accepted TCP connection and its tunnel-side peer. */
typedef struct tcp_session_t {
    evio_t   client_watcher;
    evio_t   remote_watcher;
    int      client_pipefd[2];
    int      remote_pipefd[2];
    evtimer_t connect_timer;

    union {
        /* Active until the tunnel address header is fully sent. */
        struct {
            uint8_t  addr_hdr[TCP_ADDR_HDR_MAXLEN];
            uint16_t addr_hdr_len;
            uint16_t send_offset;
        } hs;
        /* Active after payload forwarding starts. */
        struct {
            bool     client_eof;
            bool     remote_eof;
            uint32_t client_pending;
            uint32_t remote_pending;
        } fwd;
    };

    struct tcp_session_t *prev;
    struct tcp_session_t *next;
} tcp_session_t;

void tcp_tproxy_accept_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
void tcp_proxy_close_all_sessions(evloop_t *evloop);

#endif
