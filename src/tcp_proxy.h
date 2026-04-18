#ifndef TPROXY2TUNNEL_TCP_PROXY_H
#define TPROXY2TUNNEL_TCP_PROXY_H

#include <stdbool.h>
#include <stdint.h>

#include "ev_types.h"
#include "addr_header.h"
#include "fakedns.h"

#define TCP_SPLICE_MAXLEN         (64 * 1024) /* PIPE_DEF_BUFSZ on x86-64 (16 * PAGE_SIZE) */
#define TCP_CONNECT_TIMEOUT_SEC   5.0         /* ev_tstamp: connect + header send deadline */

/* addr_hdr_domain_t(2) + domain(FAKEDNS_MAX_DOMAIN_LEN-1) + portno_t(2) */
#define TCP_ADDR_HDR_MAXLEN \
    (sizeof(addr_hdr_domain_t) + (FAKEDNS_MAX_DOMAIN_LEN - 1) + sizeof(portno_t))

typedef struct tcp_tunnel_ctx_t {
    evio_t   client_watcher;    /* .data: points to parent tcp_tunnel_ctx_t */
    evio_t   remote_watcher;    /* .data: points to parent tcp_tunnel_ctx_t */
    int      client_pipefd[2];  /* client pipe buffer (splice) */
    int      remote_pipefd[2];  /* remote pipe buffer (splice) */
    bool     client_eof;
    bool     remote_eof;
    evtimer_t connect_timer;    /* fired if connect + header send exceeds timeout */
    union {
        /* Active during header send phase (before tunnel is established) */
        struct {
            uint8_t  addr_hdr[TCP_ADDR_HDR_MAXLEN]; /* ATYP+ADDR+PORT */
            uint16_t addr_hdr_len;   /* actual header length */
            uint16_t send_offset;    /* current send byte offset */
        } hs;
        /* Active during payload forwarding (after tunnel is established) */
        struct {
            uint32_t client_pending; /* bytes remaining in client→remote pipe */
            uint32_t remote_pending; /* bytes remaining in remote→client pipe */
        } fwd;
    };
    struct tcp_tunnel_ctx_t *prev;  /* doubly linked list for cleanup */
    struct tcp_tunnel_ctx_t *next;
} tcp_tunnel_ctx_t;

void tcp_tproxy_accept_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);
void tcp_proxy_close_all_sessions(evloop_t *evloop);

#endif
