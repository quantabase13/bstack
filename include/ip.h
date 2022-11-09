
#include <netinet/in.h>
#include "linker_set.h"
#define BSTACK_IP_RIB_SIZE 5


/**
 * IP Route descriptor.
 */
struct ip_route {
    in_addr_t r_network; /*!< Network address. */
    in_addr_t r_netmask; /*!< Network mask. */
    in_addr_t r_gw;      /*!< Gateway IP. */
    in_addr_t r_iface;   /*!< Interface address. */
    int r_iface_handle;  /*!< Interface ether_handle. */
};

/**
 * IP Packet Header.
 */
struct ip_hdr {
    uint8_t ip_vhl;
    uint8_t ip_tos;
    uint16_t ip_len;
    uint16_t ip_id;
    uint16_t ip_foff;
    uint8_t ip_ttl;
    uint8_t ip_proto;
    uint16_t ip_csum;
    uint32_t ip_src;
    uint32_t ip_dst;
    uint8_t ip_opt[0];

} __attribute__((packed, aligned(4)));

#define IP_PROTO_UDP 17

struct _ip_proto_handler {
    uint16_t proto_id;
    int (*fn)(uint8_t *payload, struct ip_hdr *hdr, size_t len);
};


#define IP_PROTO_INPUT_HANDLER(_proto_id_, _handler_fn_)                    \
    static struct _ip_proto_handler _ip_proto_handler_##_handler_fn_ = { \
        .proto_id = _proto_id_,                                                \
        .fn = _handler_fn_,                                                    \
    };                                                                         \
    DATA_SET(_ip_proto_handlers, _ip_proto_handler_##_handler_fn_)


/**
 * Get routing information for a source IP addess.
 * The function can be also used for source IP address validation by setting
 * route pointer argument to NULL.
 */
int ip_route_find_by_iface(in_addr_t addr, struct ip_route *route);

int ip_route_update(struct ip_route *route);
int ip_config(int ether_handle, in_addr_t ip_addr, in_addr_t netmask);

static inline size_t ip_hdr_hlen(const struct ip_hdr *ip)
{
    return (ip->ip_vhl & 0x0f) * 4;
}
