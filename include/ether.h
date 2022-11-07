#ifndef ETHER
#define ETHER
#include <stddef.h>
#include "bstack_link.h"
#include "bstack_util.h"
#include "linker_set.h"



#define ETHER_MAXLEN 1514
#define ETHER_ALEN LINK_MAC_ALEN
#define ETHER_HEADER_LEN 14
#define ETHER_FCS_LEN 4
#define ETHER_MINLEN 50

#define ETHER_P_ARP 0x0806
#define ETHER_P_IPv4 0x0800
/**
 * Ethernet frame header.
 */

struct ether_hdr {
    mac_addr_t h_dst; /*!< Destination ethernet address */
    mac_addr_t h_src; /*!< Source ethernet address */
    uint16_t h_proto; /*!< Packet type ID */
} __attribute__((packed));

struct _ether_proto_handler {
    uint16_t proto_id;
    int (*fn)(uint8_t *payload, struct ether_hdr *hdr, size_t len);
};


#define ETHER_PROTO_INPUT_HANDLER(_proto_id_, _handler_fn_)                    \
    static struct _ether_proto_handler _ether_proto_handler_##_handler_fn_ = { \
        .proto_id = _proto_id_,                                                \
        .fn = _handler_fn_,                                                    \
    };                                                                         \
    DATA_SET(_ether_proto_handlers, _ether_proto_handler_##_handler_fn_)


mac_addr_t mac_broadcast_addr;
int ether_input(uint8_t *payload, struct ether_hdr *hdr, size_t len);
uint32_t ether_fcs(uint8_t *frame, size_t len);

#endif