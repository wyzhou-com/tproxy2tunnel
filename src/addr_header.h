#ifndef TPROXY2TUNNEL_ADDR_HEADER_H
#define TPROXY2TUNNEL_ADDR_HEADER_H

/*
 * Tunnel address header encoding.
 *
 * Wire format (reuses SOCKS5 address encoding, no VER/CMD/RSV):
 *   ATYP(1) + ADDR(4|16|1+N) + PORT(2)
 *
 * Three address types:
 *   0x01  IPv4:   ATYP(1) + IPv4(4) + PORT(2) = 7 bytes
 *   0x04  IPv6:   ATYP(1) + IPv6(16) + PORT(2) = 19 bytes
 *   0x03  Domain: ATYP(1) + LEN(1) + DOMAIN(N) + PORT(2) = 4+N bytes
 */

#include "netutils.h"

/* Address type constants (same values as SOCKS5) */
#define ADDRTYPE_IPV4   0x01
#define ADDRTYPE_DOMAIN 0x03
#define ADDRTYPE_IPV6   0x04

/* Packed header structs for TCP (prefix-style, written forward) */

typedef struct {
    uint8_t   addrtype;
    ipaddr4_t ipaddr4;
    portno_t  portnum;
} __attribute__((packed)) addr_hdr_ipv4_t;  /* 7 bytes */

typedef struct {
    uint8_t   addrtype;
    ipaddr6_t ipaddr6;
    portno_t  portnum;
} __attribute__((packed)) addr_hdr_ipv6_t;  /* 19 bytes */

typedef struct {
    uint8_t   addrtype;
    uint8_t   domain_len;
    uint8_t   domain_str[];  /* + portno_t after domain */
} __attribute__((packed)) addr_hdr_domain_t;  /* 2 + N + 2 bytes */

/* Packed header structs for UDP (prefix-style, same layout) */
/* UDP tunnel header is identical to TCP tunnel header: ATYP+ADDR+PORT */
typedef addr_hdr_ipv4_t   udp_tunnel_hdr_ipv4_t;    /* 7 bytes */
typedef addr_hdr_ipv6_t   udp_tunnel_hdr_ipv6_t;    /* 19 bytes */
typedef addr_hdr_domain_t udp_tunnel_hdr_domain_t;   /* 2+N+2 bytes */

#define MAX_DOMAIN_LEN 255

/* Maximum header size: ATYP(1) + LEN(1) + DOMAIN(255) + PORT(2) = 259 */
#define ADDR_HDR_MAXLEN (1 + 1 + MAX_DOMAIN_LEN + sizeof(portno_t))

/*
 * Build a tunnel address header into `buf`.
 *
 * @param buf       Output buffer.
 * @param buf_len   Capacity of buf in bytes.
 * @param skaddr    Socket address (skaddr4_t or skaddr6_t).
 * @param domain    Domain name, or NULL for IP address mode.
 * @param out_len   Output: number of bytes written to buf (unchanged on failure).
 * @return          true on success; false if domain exceeds MAX_DOMAIN_LEN or
 *                  buf_len is insufficient for the encoded header.
 */
bool addr_header_build(void *buf, size_t buf_len, const void *skaddr, const char *domain, size_t *out_len);

/*
 * Build a tunnel UDP header backward from payload_start.
 *
 * Returns pointer to the start of the header (before payload_start).
 * This is the zero-copy optimization: header is built in the reserved
 * space preceding the payload in the batch buffer.
 *
 * @param payload_start  Pointer to the first byte of payload data.
 * @param domain         Domain name, or NULL for IP address mode.
 * @param skaddr         Socket address (skaddr4_t or skaddr6_t).
 * @param isipv4         true if skaddr is skaddr4_t.
 * @param out_headerlen  Output: number of header bytes written.
 * @return               Pointer to start of header, or NULL on error.
 */
char *addr_header_build_udp(char *payload_start, const char *domain,
                            const skaddr6_t *skaddr, bool isipv4,
                            size_t *out_headerlen);

#endif
