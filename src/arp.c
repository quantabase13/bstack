#include <string.h>
#include <errno.h>
#include "ether.h"
#include "ip.h"
#include "arp.h"
#include "logger.h"
#include "netdevice.h"
#include "tree.h"

struct arp_cache_entry {
    in_addr_t ip_addr;
    mac_addr_t haddr;
    int age;
    RB_ENTRY(arp_cache_entry) _entry;
};

RB_HEAD(arp_cache_tree, arp_cache_entry);

static struct arp_cache_entry arp_cache[BSTACK_ARP_CACHE_SIZE];
static struct arp_cache_tree arp_cache_head = RB_INITIALIZER();


static int arp_cache_cmp(struct arp_cache_entry *a, struct arp_cache_entry *b)
{
    return a->ip_addr - b->ip_addr;
}

RB_GENERATE_STATIC(arp_cache_tree, arp_cache_entry, _entry, arp_cache_cmp);


static int arp_request(int ether_handle, in_addr_t spa, in_addr_t tpa);
static struct arp_cache_entry *arp_cache_get_entry(in_addr_t ip_addr);

static void arp_hton(const struct arp_ip *host, struct arp_ip *net)
{
    net->arp_htype = htons(host->arp_htype);
    net->arp_ptype = htons(host->arp_ptype);
    net->arp_hlen = host->arp_hlen;
    net->arp_plen = host->arp_plen;
    net->arp_oper = htons(host->arp_oper);
    memmove(net->arp_sha, host->arp_sha, sizeof(mac_addr_t));
    net->arp_spa = ntohl(host->arp_spa);
    memmove(net->arp_tha, host->arp_tha, sizeof(mac_addr_t));
    net->arp_tpa = ntohl(host->arp_tpa);
}

static void arp_ntoh(const struct arp_ip *net, struct arp_ip *host)
{
    host->arp_htype = htons(net->arp_htype);
    host->arp_ptype = htons(net->arp_ptype);
    host->arp_hlen = net->arp_hlen;
    host->arp_plen = net->arp_plen;
    host->arp_oper = htons(net->arp_oper);
    memmove(host->arp_sha, net->arp_sha, sizeof(mac_addr_t));
    host->arp_spa = ntohl(net->arp_spa);
    memmove(host->arp_tha, net->arp_tha, sizeof(mac_addr_t));
    host->arp_tpa = ntohl(net->arp_tpa);
}

int arp_cache_insert(in_addr_t ip_addr,
                     const mac_addr_t haddr,
                     enum arp_cache_entry_type type)
{
    struct arp_cache_entry *it;
    struct arp_cache_entry *entry = NULL;

    if (ip_addr == 0)
        return 0;

    if ((entry = arp_cache_get_entry(ip_addr)) > 0) {
        entry->age = (int) type;
        return 0;
    }

    it = arp_cache;
    for (size_t i = 0; i < num_elem(arp_cache); i++) {
        if (it->age == ARP_CACHE_FREE) {
            entry = it;
        } else if ((entry && entry->age > it->age) ||
                   (!entry && it->age >= 0)) {
            entry = it;
        }
        it++;
    }
    if (!entry) {
        errno = ENOMEM;
        return -1;
    }
    if (entry->age >= 0)
        RB_REMOVE(arp_cache_tree, &arp_cache_head, entry);

    entry->ip_addr = ip_addr;
    memcpy(entry->haddr, haddr, sizeof(mac_addr_t));
    entry->age = (int) type;
    RB_INSERT(arp_cache_tree, &arp_cache_head, entry);

    return 0;
}


static struct arp_cache_entry *arp_cache_get_entry(in_addr_t ip_addr)
{
    struct arp_cache_entry find = {
        .ip_addr = ip_addr,
    };

    return RB_FIND(arp_cache_tree, &arp_cache_head, &find);
}

void arp_cache_remove(in_addr_t ip_addr)
{
    struct arp_cache_entry *entry = arp_cache_get_entry(ip_addr);

    RB_REMOVE(arp_cache_tree, &arp_cache_head, entry);
    if (entry)
        entry->age = ARP_CACHE_FREE;
}

int arp_cache_get_haddr(in_addr_t iface, in_addr_t ip_addr, mac_addr_t haddr)
{
    struct arp_cache_entry *entry = arp_cache_get_entry(ip_addr);
    struct ip_route route;

    if (entry && entry->age >= 0) {
        memcpy(haddr, entry->haddr, sizeof(mac_addr_t));
        return 0;
    }

    if (!ip_route_find_by_iface(iface, &route) &&
        !arp_request(route.r_iface_handle, route.r_iface, ip_addr)) {
        errno = EHOSTUNREACH;
    }

    return -1;
}


int arp_input(uint8_t *payload, struct ether_hdr *hdr, size_t len)
{
    struct arp_ip *arp_net = (struct arp_ip *)payload;
    struct arp_ip arp;
    struct ip_route route;
    arp_ntoh(arp_net, &arp);
    arp_cache_insert(arp.arp_spa, arp.arp_sha, ARP_CACHE_DYN);

    switch(arp.arp_oper){
        case ARP_OPER_REQUEST:
        if (!ip_route_find_by_iface(arp.arp_tpa, &route)){
            arp_net->arp_oper = htons(ARP_OPER_REPLY);
            arp_net->arp_tpa = arp_net->arp_spa;
            arp_net->arp_spa = htonl(route.r_iface); 
            memcpy(arp_net->arp_tha, arp_net->arp_sha, sizeof(mac_addr_t));
            netdevice_handle2addr(route.r_iface_handle, arp_net->arp_sha);
            netdevice_send(route.r_iface_handle, hdr->h_src, ETHER_P_ARP, payload, len);
            break;       
        }
        case ARP_OPER_REPLY:
            break;
        default:
            LOG(LOG_WARN, "Invalid ARP op: %d", arp.arp_oper);
            break;

    }
    return 0;
}

static int arp_request(int ether_handle, in_addr_t spa, in_addr_t tpa)
{
    struct arp_ip msg = {
        .arp_htype = ARP_HTYPE_ETHER,
        .arp_ptype = ETHER_P_IPv4,
        .arp_hlen = ETHER_ALEN,
        .arp_plen = sizeof(in_addr_t),
        .arp_oper = ARP_OPER_REQUEST,
        .arp_spa = spa,
        .arp_tpa = tpa,
    };
    int retval;

    netdevice_handle2addr(ether_handle, msg.arp_sha);
    memset(msg.arp_tha, 0, sizeof(mac_addr_t));

    arp_hton(&msg, &msg);
    retval = netdevice_send(ether_handle, mac_broadcast_addr, ETHER_P_ARP,
                        (uint8_t *) (&msg), sizeof(msg));

    return (retval < 0) ? retval : 0;
}

ETHER_PROTO_INPUT_HANDLER(ETHER_P_ARP, arp_input);