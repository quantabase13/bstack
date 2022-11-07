#include "ether.h"
#include "arp.h"
#include "netdevice.h"
#include "ip.h"
#include <stdio.h>


int ip_input(uint8_t *payload, struct ether_hdr *hdr, size_t len){
    printf("ip recv\n");
    return 0;
}

ETHER_PROTO_INPUT_HANDLER(ETHER_P_IPv4, ip_input);

int ip_config(int ether_handle, in_addr_t ip_addr, in_addr_t netmask)
{
    mac_addr_t mac;
    struct ip_route route = {
        .r_network = ip_addr & netmask,
        .r_netmask = netmask,
        .r_gw = 0, /* TODO GW support */
        .r_iface = ip_addr,
        .r_iface_handle = ether_handle,
    };

    netdevice_handle2addr(ether_handle, mac);
    arp_cache_insert(ip_addr, mac, ARP_CACHE_STATIC);

    ip_route_update(&route);

    // /* Announce that we are online. */
    // for (size_t i = 0; i < 3; i++)
    //     arp_gratuitous(ether_handle, ip_addr);

    return 0;
}