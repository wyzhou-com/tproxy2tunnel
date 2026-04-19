#include "addr_header.h"

#include <string.h>

#include "logutils.h"

bool addr_header_build(void *buf, size_t buf_len, const void *skaddr, const char *domain, size_t *out_len) {
    if (domain) {
        size_t domain_len = strlen(domain);
        if (domain_len > MAX_DOMAIN_LEN) {
            LOGERR("[addr_header_build] domain too long: %zu > %d", domain_len, MAX_DOMAIN_LEN);
            return false;
        }
        size_t need = sizeof(addr_hdr_domain_t) + domain_len + sizeof(portno_t);
        if (buf_len < need) {
            LOGERR("[addr_header_build] buf too small for domain header: %zu < %zu", buf_len, need);
            return false;
        }

        addr_hdr_domain_t *hdr = buf;
        hdr->addrtype = ADDRTYPE_DOMAIN;
        hdr->domain_len = (uint8_t)domain_len;
        memcpy(hdr->domain_str, domain, domain_len);

        portno_t port;
        if (((const skaddr4_t *)skaddr)->sin_family == AF_INET) {
            port = ((const skaddr4_t *)skaddr)->sin_port;
        } else {
            port = ((const skaddr6_t *)skaddr)->sin6_port;
        }
        memcpy(hdr->domain_str + domain_len, &port, sizeof(portno_t));

        if (out_len) {
            *out_len = need;
        }
    } else if (((const skaddr4_t *)skaddr)->sin_family == AF_INET) {
        if (buf_len < sizeof(addr_hdr_ipv4_t)) {
            LOGERR("[addr_header_build] buf too small for ipv4 header: %zu < %zu", buf_len, sizeof(addr_hdr_ipv4_t));
            return false;
        }
        const skaddr4_t *addr = skaddr;
        addr_hdr_ipv4_t *hdr = buf;
        hdr->addrtype = ADDRTYPE_IPV4;
        hdr->ipaddr4 = addr->sin_addr.s_addr;
        hdr->portnum = addr->sin_port;
        if (out_len) {
            *out_len = sizeof(addr_hdr_ipv4_t);
        }
    } else {
        if (buf_len < sizeof(addr_hdr_ipv6_t)) {
            LOGERR("[addr_header_build] buf too small for ipv6 header: %zu < %zu", buf_len, sizeof(addr_hdr_ipv6_t));
            return false;
        }
        const skaddr6_t *addr = skaddr;
        addr_hdr_ipv6_t *hdr = buf;
        hdr->addrtype = ADDRTYPE_IPV6;
        memcpy(&hdr->ipaddr6, &addr->sin6_addr.s6_addr, IP6BINLEN);
        hdr->portnum = addr->sin6_port;
        if (out_len) {
            *out_len = sizeof(addr_hdr_ipv6_t);
        }
    }
    return true;
}

char *addr_header_build_udp(char *payload_start, const char *domain,
                            const skaddr6_t *skaddr, bool isipv4,
                            size_t *out_headerlen) {
    char *header_start;
    size_t actual_headerlen;

    if (domain) {
        /* DOMAIN format: ATYP(1) + LEN(1) + DOMAIN(N) + PORT(2) */
        size_t domain_len = strlen(domain);
        if (domain_len > MAX_DOMAIN_LEN) {
            LOGERR("[addr_header_build_udp] domain too long: %zu", domain_len);
            return NULL;
        }

        actual_headerlen = 1 + 1 + domain_len + 2;
        header_start = payload_start - actual_headerlen;

        addr_hdr_domain_t *hdr = (addr_hdr_domain_t *)header_start;
        hdr->addrtype = ADDRTYPE_DOMAIN;
        hdr->domain_len = (uint8_t)domain_len;
        memcpy(hdr->domain_str, domain, domain_len);

        portno_t port = isipv4 ? ((const skaddr4_t *)skaddr)->sin_port
                        : skaddr->sin6_port;
        memcpy(hdr->domain_str + domain_len, &port, 2);
    } else {
        /* IP format */
        actual_headerlen = isipv4 ? sizeof(addr_hdr_ipv4_t) : sizeof(addr_hdr_ipv6_t);
        header_start = payload_start - actual_headerlen;

        if (isipv4) {
            addr_hdr_ipv4_t *hdr = (addr_hdr_ipv4_t *)header_start;
            hdr->addrtype = ADDRTYPE_IPV4;
            hdr->ipaddr4 = ((const skaddr4_t *)skaddr)->sin_addr.s_addr;
            hdr->portnum = ((const skaddr4_t *)skaddr)->sin_port;
        } else {
            addr_hdr_ipv6_t *hdr = (addr_hdr_ipv6_t *)header_start;
            hdr->addrtype = ADDRTYPE_IPV6;
            memcpy(&hdr->ipaddr6, &skaddr->sin6_addr.s6_addr, IP6BINLEN);
            hdr->portnum = skaddr->sin6_port;
        }
    }

    if (out_headerlen) {
        *out_headerlen = actual_headerlen;
    }
    return header_start;
}
