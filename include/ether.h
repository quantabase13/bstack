
#include <stddef.h>
#include "bstack_link.h"
#include "bstack_util.h"
#include "linker_set.h"
#define ETHER_MAXLEN 1500
#define ETHER_ALEN LINK_MAC_ALEN

/**
 * Ethernet frame header.
 */
#define ETHER_P_ARP 0x0806
struct ether_hdr {
    mac_addr_t h_dst; /*!< Destination ethernet address */
    mac_addr_t h_src; /*!< Source ethernet address */
    uint16_t h_proto; /*!< Packet type ID */
} __attribute__((packed));

struct _ether_proto_handler {
    uint16_t proto_id;
    int (*fn)(void);
};


#define ETHER_PROTO_INPUT_HANDLER(_proto_id_, _handler_fn_)                    \
    static struct _ether_proto_handler _ether_proto_handler_##_handler_fn_ = { \
        .proto_id = _proto_id_,                                                \
        .fn = _handler_fn_,                                                    \
    };                                                                         \
    DATA_SET(_ether_proto_handlers, _ether_proto_handler_##_handler_fn_)

int ether_input(uint8_t *frame);