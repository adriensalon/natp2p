#include <natp2p/natp2p.hpp>

#ifdef _WIN32
// clang-format off
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
// clang-format on
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")
#endif

#include <natpmp.h>

#define STATICLIB
#include <miniupnpc.h>
#include <upnpcommands.h>
#include <upnperrors.h>

#include <algorithm>
#include <atomic>
#include <mutex>
#include <thread>

static bool is_operational_adapter_v4(const IP_ADAPTER_ADDRESSES* adapter_addresses)
{
    if (!adapter_addresses)
        return false;
    if (adapter_addresses->OperStatus != IfOperStatusUp)
        return false;
    if (adapter_addresses->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
        return false;
    if (adapter_addresses->IfType == IF_TYPE_TUNNEL)
        return false;
    return (adapter_addresses->Ipv4Enabled != 0);
}

static bool is_operational_adapter_v6(const IP_ADAPTER_ADDRESSES* adapter_addresses)
{
    if (!adapter_addresses)
        return false;
    if (adapter_addresses->OperStatus != IfOperStatusUp)
        return false;
    if (adapter_addresses->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
        return false;
    if (adapter_addresses->IfType == IF_TYPE_TUNNEL)
        return false; // e.g., Teredo/ISATAP
    // Optional: ignore WWAN/VM virtual NICs if you like:
    // if (adapter_addresses->IfType == IF_TYPE_PPP || adapter_addresses->IfType == IF_TYPE_IEEE80211) ...
    return (adapter_addresses->Ipv6Enabled != 0);
}

static bool is_rfc1918_ipv4(const in_addr& a4)
{
    // 10.0.0.0/8
    if ((a4.S_un.S_addr & htonl(0xFF000000u)) == htonl(0x0A000000u))
        return true;
    // 172.16.0.0/12
    if ((a4.S_un.S_addr & htonl(0xFFF00000u)) == htonl(0xAC100000u))
        return true;
    // 192.168.0.0/16
    if ((a4.S_un.S_addr & htonl(0xFFFF0000u)) == htonl(0xC0A80000u))
        return true;
    return false;
}

static bool is_global_unicast_v6(const in6_addr& a6)
{
    // Exclude obvious non-routables first:
    if (IN6_IS_ADDR_LINKLOCAL(&a6))
        return false; // fe80::/10
    if (IN6_IS_ADDR_LOOPBACK(&a6))
        return false;
    if (IN6_IS_ADDR_MULTICAST(&a6))
        return false; // ff00::/8
    if (IN6_IS_ADDR_UNSPECIFIED(&a6))
        return false;
    // Unique local (fc00::/7) is not globally routable:
    const uint8_t first = a6.u.Byte[0];
    if ((first & 0xFE) == 0xFC)
        return false; // fc00::/7
    // Global unicast is 2000::/3 (001xxxxx)
    return ((first & 0xE0) == 0x20);
}

static std::string v4_to_string(const in_addr& a4)
{
    char buf[INET_ADDRSTRLEN] {};
    if (InetNtopA(AF_INET, const_cast<in_addr*>(&a4), buf, INET_ADDRSTRLEN))
        return std::string(buf);
    return {};
}

static std::string v6_to_string(const in6_addr& a6, DWORD scope_id = 0)
{
    sockaddr_in6 sa {};
    sa.sin6_family = AF_INET6;
    sa.sin6_addr = a6;
    sa.sin6_port = 0;
    sa.sin6_scope_id = scope_id;

    char buf[INET6_ADDRSTRLEN] {};
    if (InetNtopA(AF_INET6, const_cast<in6_addr*>(&sa.sin6_addr), buf, INET6_ADDRSTRLEN)) {
        // For nonzero scope_id on link-local you would append %<ifindex>,
        // but globals have scope_id = 0, so just return the literal.
        return std::string(buf);
    }
    return {};
}

static bool dad_is_preferred(const IP_ADAPTER_UNICAST_ADDRESS_LH* ua)
{
    return ua && ua->DadState == IpDadStatePreferred;
}

static bool is_temporary_privacy(const IP_ADAPTER_UNICAST_ADDRESS_LH* ua)
{
    // Windows marks temporary (RFC 4941) with TRANSIENT flag.
    return ua && (ua->Flags & IP_ADAPTER_ADDRESS_TRANSIENT) != 0;
}

static bool natpmp_wait_response(natpmp_t& p, natpmpresp_t& resp, int wanted_type, int max_iters = 1)
{
    for (int i = 0; i < max_iters; ++i) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(p.s, &fds);

        timeval tv {};
        // libnatpmp suggests using getnatpmprequesttimeout()
        if (getnatpmprequesttimeout(&p, &tv) != 0) {
            // fall back to a short bound if nothing pending
            tv.tv_sec = 1;
            tv.tv_usec = 0;
        }
        // On Windows, first arg to select() is ignored.
        (void)select(0, &fds, nullptr, nullptr, &tv);

        const int r = readnatpmpresponseorretry(&p, &resp);
        if (r == 0) {
            if (resp.type == wanted_type)
                return true; // got what we asked for
            // different response; keep looping a bit
        } else if (r != NATPMP_TRYAGAIN) {
            return false; // hard error (-7 no-gw-support, etc.)
        }
    }
    return false; // too many retries
}

static const char* to_string(natp2p::endpoint_type t)
{
    switch (t) {
    case natp2p::endpoint_type::ipv6_global:
        return "ipv6_global";
    case natp2p::endpoint_type::ipv4_mapped_upnp:
        return "ipv4_mapped_upnp";
    case natp2p::endpoint_type::ipv4_mapped_natpmp:
        return "ipv4_mapped_natpmp";
    case natp2p::endpoint_type::ipv4_manual:
        return "ipv4_manual";
    case natp2p::endpoint_type::ipv4_lan:
        return "ipv4_lan";
    }
    return "unknown";
}

static natp2p::endpoint_type parse_endpoint_type(const std::string& s)
{
    if (s == "ipv6_global")
        return natp2p::endpoint_type::ipv6_global;
    if (s == "ipv4_mapped_upnp")
        return natp2p::endpoint_type::ipv4_mapped_upnp;
    if (s == "ipv4_mapped_natpmp")
        return natp2p::endpoint_type::ipv4_mapped_natpmp;
    if (s == "ipv4_manual")
        return natp2p::endpoint_type::ipv4_manual;
    if (s == "ipv4_lan")
        return natp2p::endpoint_type::ipv4_lan;
    throw std::invalid_argument("decode_endpoint: unknown endpoint_type: " + s);
}

static const char* to_string(natp2p::transport_protocol p)
{
    switch (p) {
    case natp2p::transport_protocol::udp:
        return "udp";
    case natp2p::transport_protocol::tcp:
        return "tcp";
    }
    return "unknown";
}

static natp2p::transport_protocol parse_transport_protocol(const std::string& s)
{
    if (s == "udp")
        return natp2p::transport_protocol::udp;
    if (s == "tcp")
        return natp2p::transport_protocol::tcp;
    throw std::invalid_argument("decode_endpoint: unknown protocol: " + s);
}

static std::string trim(std::string v)
{
    auto issp = [](unsigned char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
    auto b = std::find_if_not(v.begin(), v.end(), issp);
    auto e = std::find_if_not(v.rbegin(), v.rend(), issp).base();
    if (b >= e)
        return {};
    return std::string(b, e);
}

static std::vector<std::string> split(const std::string& s, char sep)
{
    std::vector<std::string> out;
    std::string cur;
    cur.reserve(s.size());
    for (char c : s) {
        if (c == sep) {
            out.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    out.push_back(cur);
    return out;
}

namespace natp2p {

struct endpoint_lease_impl {
    // Which kind of endpoint this impl manages (use your existing enum)
    endpoint_type kind = endpoint_type::ipv6_global;

    // NAT-PMP fields (used iff kind == ipv4_mapped_natpmp)
    std::uint16_t private_port = 0; // local port (LAN)
    std::uint16_t public_port = 0; // mapped port (WAN)
    int proto = NATPMP_PROTOCOL_UDP; // UDP/TCP
    std::atomic<std::uint32_t> lifetime_sec { 0 }; // as granted by router
    std::uint32_t forced_gw = 0; // network-order IPv4 GW (0 = autodetect)
    std::chrono::steady_clock::time_point obtained_at {};

    // Auto-renew machinery
    std::thread renew_thread;
    std::atomic<bool> stop_flag { false };
    std::mutex mtx;
    std::condition_variable cv;

    endpoint_lease_impl() = default;

    static std::shared_ptr<endpoint_lease_impl> make_natpmp_autorenew(
        std::uint16_t priv,
        std::uint16_t pub,
        int protocol,
        std::uint32_t lifetime,
        std::uint32_t forced_gw_net = 0)
    {
        auto p = std::make_shared<endpoint_lease_impl>();
        p->kind = endpoint_type::ipv4_mapped_natpmp;
        p->private_port = priv;
        p->public_port = pub;
        p->proto = protocol;
        p->forced_gw = forced_gw_net;
        p->lifetime_sec = lifetime ? lifetime : 7200;
        p->obtained_at = std::chrono::steady_clock::now();
        p->start_renew_loop();
        return p;
    }

    // unpnp
    std::string upnp_control_url;
    std::string upnp_service_type;
    std::string upnp_proto;
    std::uint16_t upnp_public_port = 0;

    static std::shared_ptr<endpoint_lease_impl> make_upnp(
        std::string control_url,
        std::string service_type,
        std::uint16_t public_port,
        const char* proto)
    {
        auto p = std::make_shared<endpoint_lease_impl>();
        p->kind = endpoint_type::ipv4_mapped_upnp;
        p->upnp_control_url = std::move(control_url);
        p->upnp_service_type = std::move(service_type);
        p->upnp_public_port = public_port;
        p->upnp_proto = proto;
        return p;
    }

    ~endpoint_lease_impl()
    {
        // Stop renew loop
        stop_flag.store(true, std::memory_order_relaxed);
        cv.notify_all();
        if (renew_thread.joinable())
            renew_thread.join();
        // Revoke mapping if needed
        if (kind == endpoint_type::ipv4_mapped_natpmp) {
            revoke_blocking();
        }

        // UPnP revoke (best-effort)
        if (kind == endpoint_type::ipv4_mapped_upnp) {
            if (!upnp_control_url.empty() && !upnp_service_type.empty() && upnp_public_port != 0) {
                char eport[16] {};
                _snprintf_s(eport, _TRUNCATE, "%u", static_cast<unsigned>(upnp_public_port));
                // remoteHost = nullptr means "all"
                (void)UPNP_DeletePortMapping(upnp_control_url.c_str(),
                    upnp_service_type.c_str(),
                    eport,
                    upnp_proto.c_str(),
                    nullptr);
            }
        }
    }

    void start_renew_loop()
    {
        if (kind != endpoint_type::ipv4_mapped_natpmp)
            return;
        renew_thread = std::thread([this] {
            WSADATA wsa {};
            (void)WSAStartup(MAKEWORD(2, 2), &wsa);

            // basic backoff bounds
            constexpr std::uint32_t kMinSleep = 30; // seconds
            constexpr std::uint32_t kMaxSleep = 3600; // seconds

            while (!stop_flag.load(std::memory_order_relaxed)) {
                // next wake based on current lifetime (~60%)
                auto life = lifetime_sec.load(std::memory_order_relaxed);
                if (life == 0)
                    life = 7200;
                std::uint32_t sleep_s = std::clamp<std::uint32_t>(life * 3 / 5, kMinSleep, kMaxSleep);

                std::unique_lock<std::mutex> lk(mtx);
                if (cv.wait_for(lk, std::chrono::seconds(sleep_s), [this] { return stop_flag.load(); }))
                    break; // stop requested
                lk.unlock();

                // Try to renew; on failure, quick backoff retries then continue.
                if (!renew_once_blocking(life)) {
                    // quick retry a few times
                    bool renewed = false;
                    for (int i = 0; i < 3 && !stop_flag.load(); ++i) {
                        std::this_thread::sleep_for(std::chrono::seconds(10));
                        renewed = renew_once_blocking(life);
                        if (renewed)
                            break;
                    }
                    // if still failed, loop will compute a new wait and try again
                }
            }
        });
    }

    bool renew_once_blocking(std::uint32_t desired_lifetime)
    {
        if (kind != endpoint_type::ipv4_mapped_natpmp)
            return true;

        natpmp_t p {};
        if (initnatpmp(&p, /*forcegw*/ forced_gw ? 1 : 0, /*forcedgw*/ forced_gw) != 0) {
            return false;
        }
        bool ok = false;
        do {
            if (sendnewportmappingrequest(&p, proto, private_port, public_port, desired_lifetime) < 0)
                break;

            natpmpresp_t r {};
            const int wanted = (proto == NATPMP_PROTOCOL_UDP)
                ? NATPMP_RESPTYPE_UDPPORTMAPPING
                : NATPMP_RESPTYPE_TCPPORTMAPPING;

            if (!natpmp_wait_response(p, r, wanted))
                break;
            if (r.resultcode != 0)
                break;

            // Update lifetime/ports in case the gateway changed them
            public_port = r.pnu.newportmapping.mappedpublicport;
            lifetime_sec = r.pnu.newportmapping.lifetime;
            obtained_at = std::chrono::steady_clock::now();
            ok = true;
        } while (false);

        closenatpmp(&p);
        return ok;
    }

    void revoke_blocking()
    {
        natpmp_t p {};
        if (initnatpmp(&p, /*forcegw*/ forced_gw ? 1 : 0, /*forcedgw*/ forced_gw) != 0)
            return;
        (void)sendnewportmappingrequest(&p, proto, private_port, public_port, 0); // lifetime=0 -> delete
        natpmpresp_t r {};
        // best-effort; ignore result
        (void)readnatpmpresponseorretry(&p, &r);
        closenatpmp(&p);
    }
};

void acquire_endpoints_ipv6(const std::uint16_t local_port, const transport_protocol protocol, std::vector<endpoint_lease>& endpoints)
{

    // Ensure Winsock initialized (idempotent if app did it earlier).
    WSADATA w {};
    (void)WSAStartup(MAKEWORD(2, 2), &w);

    // Query adapter list (IPv6 only).
    ULONG flags = GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER
        | GAA_FLAG_INCLUDE_PREFIX; // to get OnLinkPrefixLength
    ULONG bufLen = 15 * 1024;
    std::vector<unsigned char> buf(bufLen);

    DWORD ret = ERROR_BUFFER_OVERFLOW;
    for (int attempts = 0; attempts < 3 && ret == ERROR_BUFFER_OVERFLOW; ++attempts) {
        buf.resize(bufLen);
        ret = GetAdaptersAddresses(AF_INET6, flags, nullptr,
            reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()),
            &bufLen);
        if (ret == ERROR_BUFFER_OVERFLOW)
            continue;
        break;
    }
    if (ret != NO_ERROR) {
        // Could log: std::error_code(ret, std::system_category())
        return;
    }

    auto* aa = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
    struct Candidate {
        std::string ip;
        uint8_t prefix = 0;
        bool temporary = false;
        // Optional: add metrics/IfIndex to break ties.
    };
    std::vector<Candidate> candidates;

    for (const IP_ADAPTER_ADDRESSES* a = aa; a; a = a->Next) {
        if (!is_operational_adapter_v6(a))
            continue;

        for (auto* u = a->FirstUnicastAddress; u; u = u->Next) {
            if (!u->Address.lpSockaddr)
                continue;
            if (u->Address.lpSockaddr->sa_family != AF_INET6)
                continue;

            const auto* sa6 = reinterpret_cast<const sockaddr_in6*>(u->Address.lpSockaddr);
            const in6_addr addr = sa6->sin6_addr;

            if (!is_global_unicast_v6(addr))
                continue;
            if (!dad_is_preferred(u))
                continue;

            Candidate c;
            c.ip = v6_to_string(addr, sa6->sin6_scope_id);
            c.prefix = u->OnLinkPrefixLength; // 0..128
            c.temporary = is_temporary_privacy(u);
            if (!c.ip.empty())
                candidates.emplace_back(std::move(c));
        }
    }

    if (candidates.empty())
        return;

    // Prefer stable (non-temporary) over temporary; tie-break: longer prefix (more specific).
    std::sort(candidates.begin(), candidates.end(), [](const Candidate& a, const Candidate& b) {
        if (a.temporary != b.temporary)
            return b.temporary; // false (stable) comes first
        if (a.prefix != b.prefix)
            return a.prefix > b.prefix;
        return a.ip < b.ip;
    });

    // Emit leases — you might want to export ALL; here we export all found.
    // out.reserve(candidates.size());
    for (const auto& c : candidates) {
        natp2p::endpoint_lease lease;
        lease.data.type = natp2p::endpoint_type::ipv6_global;
        lease.data.protocol = protocol;
        lease.data.external_ip = c.ip;
        lease.data.external_port = local_port;
        lease.data.prefix_length = static_cast<std::uint8_t>(c.prefix); // or rename to prefix_len as suggested
        lease.local_port = local_port;
        lease._impl = std::make_shared<endpoint_lease_impl>();
        endpoints.emplace_back(std::move(lease));
    }
}

void acquire_endpoints_natpmp(const std::uint16_t local_port, const transport_protocol protocol, std::vector<endpoint_lease>& endpoints)
{
    // Winsock init (idempotent)
    WSADATA wsa {};
    (void)WSAStartup(MAKEWORD(2, 2), &wsa);

    natpmp_t p {};
    if (initnatpmp(&p, 0, 0) != 0) {
        return; // no IPv4 gw or socket failure
    }

    // Always close the NAT-PMP handle on exit from this function
    struct CloseGuard {
        natpmp_t* p;
        ~CloseGuard()
        {
            if (p)
                closenatpmp(p);
        }
    } guard { &p };

    // 1) Query public address
    if (sendpublicaddressrequest(&p) < 0) {
        return;
    }
    natpmpresp_t resp {};
    if (!natpmp_wait_response(p, resp, NATPMP_RESPTYPE_PUBLICADDRESS)) {
        return; // gw doesn’t support NAT-PMP or timed out
    }

    // Convert public IPv4 to string
    in_addr pub {};
    // libnatpmp stores addr as a network-order uint32
    pub.s_addr = resp.pnu.publicaddress.addr.S_un.S_addr;
    std::string public_ip = v4_to_string(pub);
    if (public_ip.empty()) {
        return;
    }

    // 2) Request UDP port mapping: private=local_port, public=same (hint), lifetime=7200s
    constexpr std::uint32_t kLifetimeSec = 7200;
    const int nat_proto = (protocol == transport_protocol::udp) ? NATPMP_PROTOCOL_UDP
                                                                : NATPMP_PROTOCOL_TCP;
    const int wanted = (nat_proto == NATPMP_PROTOCOL_UDP) ? NATPMP_RESPTYPE_UDPPORTMAPPING
                                                          : NATPMP_RESPTYPE_TCPPORTMAPPING;

    if (sendnewportmappingrequest(&p, nat_proto, local_port, local_port, kLifetimeSec) < 0) {
        return;
    }
    if (!natpmp_wait_response(p, resp, wanted)) {
        return;
    }

    const std::uint16_t mapped_public_port = resp.pnu.newportmapping.mappedpublicport;
    // lifetime actually granted: resp.pnu.newportmapping.lifetime (seconds)
    // private port echoed:      resp.pnu.newportmapping.privateport
    const std::uint32_t granted_lifetime = resp.pnu.newportmapping.lifetime;
    std::uint32_t forced_gw = 0; // or your chosen GW (network order) if you force it

    endpoint_lease lease;
    lease.data.type = endpoint_type::ipv4_mapped_natpmp;
    lease.data.protocol = protocol;
    lease.data.external_ip = std::move(public_ip);
    lease.data.external_port = mapped_public_port; // host order
    lease.data.prefix_length = std::nullopt; // N/A for mapped endpoint
    lease.local_port = local_port;
    lease._impl = endpoint_lease_impl::make_natpmp_autorenew(
        /*priv*/ local_port,
        /*pub*/ mapped_public_port,
        /*proto*/ nat_proto,
        /*life*/ granted_lifetime ? granted_lifetime : 7200,
        /*forced_gw*/ forced_gw);

    endpoints.emplace_back(std::move(lease));
}

void acquire_endpoints_unpnp(const std::uint16_t local_port, const transport_protocol protocol, std::vector<endpoint_lease>& endpoints)
{
    const char* _protocol = (protocol == transport_protocol::udp) ? "UDP" : "TCP";
    // Discover devices (short, bounded)
    int discover_err = 0;
    UPNPDev* devlist = nullptr;

    devlist = upnpDiscover(1500, /*multicastif*/ nullptr, /*minissdpdsock*/ nullptr,
        /*sameport*/ 0);

    if (!devlist)
        return;

    UPNPUrls urls {};
    IGDdatas data {};
    char lanaddr[64] {}; // our LAN IPv4 on that IGD
    const int igd = UPNP_GetValidIGD(devlist, &urls, &data, lanaddr, sizeof(lanaddr));

    if (igd != 1 && igd != 2) { // 1 = connected IGD, 2 = found but not connected
        freeUPNPDevlist(devlist);
        return;
    }

    // Query external IPv4
    char externalIP[40] {};
    int r = UPNP_GetExternalIPAddress(urls.controlURL, data.servicetype, externalIP);
    if (r != UPNPCOMMAND_SUCCESS || externalIP[0] == '\0' || strcmp(externalIP, "0.0.0.0") == 0) {
        FreeUPNPUrls(&urls);
        freeUPNPDevlist(devlist);
        return;
    }

    // Try to add UDP mapping: external = local_port, internal = local_port
    char eport[16] {}, iport[16] {};
    _snprintf_s(eport, _TRUNCATE, "%u", static_cast<unsigned>(local_port));
    _snprintf_s(iport, _TRUNCATE, "%u", static_cast<unsigned>(local_port));

    // Description for router UI
    const char* desc = "natp2p";

    r = UPNP_AddPortMapping(urls.controlURL, data.servicetype,
        eport, iport, lanaddr, desc, _protocol,
        /*remoteHost*/ nullptr);

    if (r != UPNPCOMMAND_SUCCESS) {
        // Could try UPNP_AddAnyPortMapping here to auto-pick a free external port (if available in your miniupnpc)
        FreeUPNPUrls(&urls);
        freeUPNPDevlist(devlist);
        return;
    }

    // Success: build the lease. We can free URLs; store strings needed for DeletePortMapping.
    endpoint_lease lease;
    lease.data.type = endpoint_type::ipv4_mapped_upnp;
    lease.data.protocol = protocol;
    lease.data.external_ip = externalIP;
    lease.data.external_port = local_port; // we requested same external port
    lease.data.prefix_length = std::nullopt; // N/A for mapped endpoints
    lease.local_port = local_port;

    lease._impl = endpoint_lease_impl::make_upnp(
        /*control_url*/ urls.controlURL ? urls.controlURL : "",
        /*service_type*/ data.servicetype ? data.servicetype : "",
        /*public_port*/ local_port,
        /*proto*/ _protocol);

    endpoints.emplace_back(std::move(lease));

    FreeUPNPUrls(&urls);
    freeUPNPDevlist(devlist);
}

void acquire_endpoints_lan(const std::uint16_t local_port, const transport_protocol protocol, std::vector<endpoint_lease>& endpoints)
{
    // Ensure Winsock is initialized (safe if already done).
    WSADATA w {};
    (void)WSAStartup(MAKEWORD(2, 2), &w);

    ULONG flags = GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER
        | GAA_FLAG_INCLUDE_PREFIX; // gives OnLinkPrefixLength
    ULONG bufLen = 12 * 1024;
    std::vector<unsigned char> buf(bufLen);

    DWORD ret = ERROR_BUFFER_OVERFLOW;
    for (int attempts = 0; attempts < 3 && ret == ERROR_BUFFER_OVERFLOW; ++attempts) {
        buf.resize(bufLen);
        ret = GetAdaptersAddresses(AF_INET, flags, nullptr,
            reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()),
            &bufLen);
        if (ret == ERROR_BUFFER_OVERFLOW)
            continue;
        break;
    }
    if (ret != NO_ERROR)
        return;

    auto* aa = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
    for (const IP_ADAPTER_ADDRESSES* a = aa; a; a = a->Next) {
        if (!is_operational_adapter_v4(a))
            continue;

        for (auto* u = a->FirstUnicastAddress; u; u = u->Next) {
            if (!u->Address.lpSockaddr)
                continue;
            if (u->Address.lpSockaddr->sa_family != AF_INET)
                continue;

            const auto* sa4 = reinterpret_cast<const sockaddr_in*>(u->Address.lpSockaddr);
            const in_addr addr = sa4->sin_addr;

            // Skip APIPA (169.254/16) and anything not RFC1918
            const uint32_t ip_be = addr.S_un.S_addr;
            const bool is_apipa = (ip_be & htonl(0xFFFF0000u)) == htonl(0xA9FE0000u);
            if (is_apipa)
                continue;
            if (!is_rfc1918_ipv4(addr))
                continue;

            std::string ip = v4_to_string(addr);
            if (ip.empty())
                continue;

            endpoint_lease lease;
            lease.data.type = endpoint_type::ipv4_lan;
            lease.data.protocol = protocol;
            lease.data.external_ip = std::move(ip); // local LAN IP
            lease.data.external_port = local_port; // same port
            lease.data.prefix_length = static_cast<std::uint8_t>(u->OnLinkPrefixLength); // 0..32
            lease.local_port = local_port;
            lease._impl = std::make_shared<endpoint_lease_impl>();
            endpoints.emplace_back(std::move(lease));
        }
    }
}

std::vector<endpoint_lease> acquire_endpoints(const std::uint16_t local_port, const transport_protocol protocol)
{
    std::vector<endpoint_lease> _endpoints;
    acquire_endpoints_ipv6(local_port, protocol, _endpoints);
    acquire_endpoints_natpmp(local_port, protocol, _endpoints);
    acquire_endpoints_unpnp(local_port, protocol, _endpoints);
    acquire_endpoints_lan(local_port, protocol, _endpoints);
    return _endpoints;
}

std::string encode_endpoint(const endpoint_data& endpoint)
{
    // version tag for forward compatibility
    constexpr char SEP = '|';
    std::string out;
    out.reserve(32 + endpoint.external_ip.size()); // small optimization

    out.append("ep1");
    out.push_back(SEP);
    out.append(to_string(endpoint.type));
    out.push_back(SEP);
    out.append(to_string(endpoint.protocol));
    out.push_back(SEP);
    out.append(endpoint.external_ip);
    out.push_back(SEP);

    // port
    out.append(std::to_string(static_cast<unsigned>(endpoint.external_port)));
    out.push_back(SEP);

    // prefix (or '-')
    if (endpoint.prefix_length.has_value())
        out.append(std::to_string(static_cast<unsigned>(*endpoint.prefix_length)));
    else
        out.push_back('-');

    return out;
}

endpoint_data decode_endpoint(const std::string& endpoint)
{
    constexpr char SEP = '|';
    auto parts = split(endpoint, SEP);

    // Accept "ep1|..." (6 tokens) or raw (5 tokens) for leniency
    size_t idx = 0;
    if (!parts.empty() && parts[0] == "ep1") {
        idx = 1;
        if (parts.size() != 6) {
            throw std::invalid_argument("decode_endpoint: bad field count for ep1");
        }
    } else if (parts.size() != 5) {
        throw std::invalid_argument("decode_endpoint: bad field count");
    }

    auto get = [&](size_t i) -> std::string {
        return trim(parts[idx + i]);
    };

    endpoint_data _endpoint {};
    _endpoint.type = parse_endpoint_type(get(0));
    _endpoint.protocol = parse_transport_protocol(get(1));
    _endpoint.external_ip = get(2);
    if (_endpoint.external_ip.empty())
        throw std::invalid_argument("decode_endpoint: empty ip");

    // port
    {
        const std::string pstr = get(3);
        if (pstr.empty())
            throw std::invalid_argument("decode_endpoint: empty port");
        unsigned long v = 0;
        try {
            v = std::stoul(pstr);
        } catch (...) {
            throw std::invalid_argument("decode_endpoint: invalid port");
        }
        if (v > 65535u || v == 0u)
            throw std::invalid_argument("decode_endpoint: port out of range");
        _endpoint.external_port = static_cast<std::uint16_t>(v);
    }

    // prefix
    if ((idx ? parts[idx + 4] : parts[4]) == "-") {
        _endpoint.prefix_length = std::nullopt;
    } else {
        const std::string px = get(4);
        unsigned long v = 0;
        try {
            v = std::stoul(px);
        } catch (...) {
            throw std::invalid_argument("decode_endpoint: invalid prefix");
        }
        if (v > 128u)
            throw std::invalid_argument("decode_endpoint: prefix out of range");
        _endpoint.prefix_length = static_cast<std::uint8_t>(v);
    }

    return _endpoint;
}

}