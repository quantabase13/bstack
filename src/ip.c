#include "ip.h"
#include <stdio.h>
#include <errno.h>
#include "logger.h"
#include "arp.h"
#include "ether.h"
#include "netdevice.h"
#include "tree.h"


SET_DECLARE(_ip_proto_handlers, struct _ip_proto_handler);

size_t ip_ntoh(const struct ip_hdr *net, struct ip_hdr *host)
{
    host->ip_vhl = net->ip_vhl;
    host->ip_tos = net->ip_tos;
    host->ip_len = ntohs(net->ip_len);
    host->ip_id = ntohs(net->ip_id);
    host->ip_foff = ntohs(net->ip_foff);
    host->ip_ttl = net->ip_ttl;
    host->ip_proto = net->ip_proto;
    host->ip_csum = net->ip_csum;
    host->ip_src = ntohl(net->ip_src);
    host->ip_dst = ntohl(net->ip_dst);

    return ip_hdr_hlen(host);
}

int ip_input(uint8_t *payload, struct ether_hdr *hdr, size_t len)
{
    printf("ip recv\n");
    struct ip_hdr *ip = (struct ip_hdr *)payload;
    struct _ip_proto_handler **tmpp;
    struct _ip_proto_handler *proto;
    size_t hlen;

    ip_ntoh(ip, ip);
    hlen = ip_hdr_hlen(ip);


    int retval;
    SET_FOREACH (tmpp, _ip_proto_handlers) {
        proto = *tmpp;
        if (proto->proto_id == (ip->ip_proto))
            break;
        proto = NULL;
    }
    LOG(LOG_DEBUG, "proto id: 0x%x", (unsigned) ip->ip_proto);
    if (proto) {
        proto->fn(payload + hlen, ip, len-hlen);
    }
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