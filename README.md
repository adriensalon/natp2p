# natp2p

Provides functionnality for discovering and managing NAT-traversing host endpoints as RAII `natp2p::endpoint_lease` data structures to use in P2P applications that don't rely on public relays/STUN/TURN/ICE servers. Documentation for the data structures can be found in the [natp2p/natp2p.hpp](include/natp2p/natp2p.hpp) header.

Discovery searches for:
- Global IPv6 endpoints that can be directly reached from clients
- NAT-PMP IPv4 mapped endpoints implemented with [libnatpmp](https://github.com/miniupnp/libnatpmp)
- UPnP IGD IPv4 mapped endpoints implemented with [miniupnp](https://github.com/miniupnp/miniupnp)
- LAN IPv4 endpoints to be reached from clients on the local network

### Usage

Use `std::vector<endpoint_lease> natp2p::acquire_endpoints(const std::uint16_t local_port, const transport_protocol protocol)` to acquire endpoints for the requested local port. Mapped addresses can use or not the same port.

Selected transport protocol that can be either `natp2p::transport_protocol::udp` or `natp2p::transport_protocol::tcp`.
