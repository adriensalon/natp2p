#pragma once

#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace natp2p {

/// @brief How the endpoint is reachable
/// @note For mapped endpoints, external_ip is the router’s WAN address and external_port 
/// is the mapped public port
enum struct endpoint_type : std::uint8_t {
    
    /// @brief Host has a global unicast IPv6 address, external_port == local port
    ipv6_global,

    /// @brief IPv4 external mapping created via UPnP IGD
    ipv4_mapped_upnp,

    /// @brief IPv4 external mapping created via NAT-PMP
    ipv4_mapped_natpmp,

    /// @brief User/VPN supplied a manual forward (no auto-maintenance)
    ipv4_manual,

    /// @brief Private IPv4 on the same LAN (10/8, 172.16/12, 192.168/16)
    ipv4_lan,
};

/// @brief Transport to use over the endpoint
enum struct transport_protocol {

    /// @brief Datagram transport recommended for P2P + hole punching
    udp,

    /// @brief Stream transport, may require symmetric-open support to connect through NATs
    tcp
};

/// @brief The advertised external tuple and metadata for connecting to a host
struct endpoint_data {
    endpoint_type type;
    transport_protocol protocol; // optional?
    std::string external_ip;
    std::uint16_t external_port;
    std::optional<std::uint8_t> prefix_length;
};

/// @brief RAII handle for a discovered/created endpoint
struct endpoint_lease {
    endpoint_data data;
    std::uint16_t local_port;

private:
    std::shared_ptr<struct endpoint_lease_impl> _impl;
    friend void acquire_endpoints_ipv6(const std::uint16_t, const transport_protocol, std::vector<endpoint_lease>&);
    friend void acquire_endpoints_natpmp(const std::uint16_t, const transport_protocol, std::vector<endpoint_lease>&);
    friend void acquire_endpoints_unpnp(const std::uint16_t, const transport_protocol, std::vector<endpoint_lease>&);
    friend void acquire_endpoints_lan(const std::uint16_t, const transport_protocol, std::vector<endpoint_lease>&);
};

/// @brief Discover all viable endpoints for the given local port and transport. Attempts
///   1) Global IPv6 address on host (ipv6_global)
///   2) NAT-PMP mapping (ipv4_mapped_natpmp) for the requested protocol
///   3) UPnP IGD mapping (ipv4_mapped_upnp) for the requested protocol
///   4) LAN IPv4 addresses (ipv4_lan)
/// @param local_port The local UDP/TCP port already bound by your application
/// @param protocol The transport to advertise/mapping protocol to request
/// @return A vector of leases (possibly empty). Each lease’s destructor cleans up any mapping
[[nodiscard]] std::vector<endpoint_lease> acquire_endpoints(const std::uint16_t local_port, const transport_protocol protocol);

/// @brief Encode an endpoint into a stable, human-readable string (IPv6-safe)
/// Format : ep1|<endpoint_type>|<protocol>|<ip>|<port>|<prefix or ->
/// @param endpoint  The endpoint to encode 
/// @return A compact string suitable for transport/storage
[[nodiscard]] std::string encode_endpoint(const endpoint_data& endpoint);

/// @brief Decode a string produced by encode_endpoint() back into endpoint_data
/// @param endpoint The encoded string
/// @return Decoded endpoint_data
/// @throws std::invalid_argument on malformed input, unknown enum strings, invalid port,
/// or out-of-range prefix
[[nodiscard]] endpoint_data decode_endpoint(const std::string& endpoint);

}