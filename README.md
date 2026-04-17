# tproxy2tunnel

A lightweight C relay that converts Linux tproxy/redirect-captured traffic into the shadowsocks tunnel wire format (ATYP+ADDR+PORT prefix), eliminating the 2+ RTT SOCKS5 handshake between the transparent proxy adapter and ss-local.

In essence, this is the client half of a local unencrypted shadowsocks relay. It prepends each connection/packet with the target address in SOCKS5 address encoding, then forwards to ss-local running in dynamic tunnel mode. ss-local reads the address, wraps the payload with encryption, and sends it to the remote ss-server. No encryption is needed on the local segment because both processes run on the same machine.

## Architecture

**TCP:**

```
kernel tproxy/redirect → accept → get orig dst →
[fakedns reverse lookup] → connect to ss-local →
send ATYP+ADDR+PORT (with optional TFO) → splice-based
bidirectional forwarding
```

**UDP:**

```
kernel tproxy recvmsg → get orig dst →
[fakedns reverse lookup] → zero-copy header prepend →
send to ss-local via connected UDP socket →
receive response → strip header → tproxy sendto client
```

## Design

- **Zero-copy UDP:** batch buffers reserve `MAX_TUNNEL_UDP_HEADER` bytes before the payload; `addr_header_build_udp` writes the header backward into this space, avoiding any memmove of payload data.

- **splice(2) TCP forwarding:** after the address header is sent, data flows through kernel pipes without touching userspace memory.

- **Three-table UDP session model:** Main Table (Full Cone NAT for real IP traffic), Fork Table (Symmetric NAT for FakeDNS traffic), and TProxy Table (per-source-address response sockets). FakeDNS sessions always use the Fork Table to guarantee per-target isolation; real IP sessions prefer the Main Table for socket reuse.

- **recvmmsg/sendmmsg batching:** up to 16 UDP packets per syscall, with automatic grouping by tproxy socket for sendmmsg efficiency.

- **Thread-local everything:** hash tables, batch buffers, memory pools, and libev loops are all per-thread with no locks.

- **FakeDNS integration:** built-in fake DNS server assigns IPs from a configurable range, with reverse lookup to recover domain names for the tunnel header. Supports persistence via cache file.

- **Memory pools:** fixed-size slab allocators for `tcp_tunnel_ctx_t`, `udp_tunnelctx_t`, and `udp_tproxyctx_t`, bounded by configurable capacity limits.

## Build

```bash
make                # release build
make DEBUG=1        # debug build with ASan/UBSan
make STATIC=1       # static linking
make install        # install to /usr/local/bin
```

## Usage

```
tproxy2tunnel <options...>

 -s, --server-addr <addr>           tunnel server ip, default: 127.0.0.1
 -p, --server-port <port>           tunnel server port, default: 1080
 -b, --listen-addr4 <addr>          listen ipv4 address, default: 127.0.0.1
 -B, --listen-addr6 <addr>          listen ipv6 address, default: ::1
 -l, --listen-port <port>           listen port number, default: 60080
 -S, --tcp-syncnt <cnt>             change the number of tcp syn retransmits
 -c, --cache-size <size>            udp context cache maxsize, default: 256
 -o, --udp-timeout <sec>            udp context idle timeout, default: 60
 -j, --thread-nums <num>            number of the worker threads, default: 1
 -J, --udp-thread-nums <num>        number of udp threads, default: 1
 -n, --nofile-limit <num>           set nofile limit, may need root privilege
 -u, --run-user <user>              run as the given user, need root privilege
 -T, --tcp-only                     listen tcp only, aka: disable udp proxy
 -U, --udp-only                     listen udp only, aka: disable tcp proxy
 -4, --ipv4-only                    listen ipv4 only, aka: disable ipv6 proxy
 -6, --ipv6-only                    listen ipv6 only, aka: disable ipv4 proxy
 -R, --redirect                     use redirect instead of tproxy for tcp
 -r, --reuse-port                   enable so_reuseport for single thread
 -w, --tfo-accept                   enable tcp_fastopen for server socket
 -W, --tfo-connect                  enable tcp_fastopen for client socket
 -v, --verbose                      print verbose log, affect performance
 -V, --version                      print version number and exit
 -h, --help                         print help information and exit
     --enable-fakedns               enable fakedns feature
     --fakedns-addr <addr>          fakedns listen address, default: 127.0.0.1
     --fakedns-port <port>          fakedns listen port, default: 5353
     --fakedns-ip-range <cidr>      fakedns ip range, default: 198.18.0.0/15
     --fakedns-cache <path>         fakedns cache file path, support persistence
```

## Third-party

- **libev/** — event loop (epoll backend, single-priority build)
- **uthash/** — hash table macros (with xxhash override)
- **xxhash/** — XXH3 hash function
