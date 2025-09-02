#include <natp2p/natp2p.hpp>

#include <iostream>

int main()
{
    std::vector<natp2p::endpoint_lease> _endpoints = natp2p::acquire_endpoints(1544, natp2p::transport_protocol::udp);
    for (const auto& _endpoint : _endpoints) {
        std::cout << natp2p::encode_endpoint(_endpoint.data) << std::endl;
    }
}