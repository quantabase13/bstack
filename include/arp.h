#include <netinet/in.h>
#include "bstack_link.h"


#define BSTACK_ARP_CACHE_SIZE 50

/**
 * ARP IP protocol message.
 */
struct arp_ip {
    uint16_t arp_htype; /*!< HW type */
    uint16_t arp_ptype; /*!< Protocol type */
    uint8_t arp_hlen;   /*!< HW addr len */
    uint8_t arp_plen;   /*!< Proto addr len */
    uint16_t arp_oper;  /*!< Opcode */
    mac_addr_t arp_sha; /*!< Sender HW addr */
    in_addr_t arp_spa;  /*!< Sender IP addr */
    mac_addr_t arp_tha; /*!< Target HW addr */
    in_addr_t arp_tpa;  /*!< Target IP addr */
} __attribute__((packed, aligned(2)));


#define ARP_HTYPE_ETHER 1
/**
 * arp_oper
 * @{
 */
#define ARP_OPER_REQUEST 1 /*!< Request */
#define ARP_OPER_REPLY 2   /*!< Reply */
/**
 * @}
 */

/**
 * ARP Cache Operations.
 */

/**
 * ARP Cache entry type.
 */
enum arp_cache_entry_type {
    ARP_CACHE_FREE = -2,   /*!< Unused entry. */
    ARP_CACHE_STATIC = -1, /*!< Static entry. */
    ARP_CACHE_DYN = 0,     /*!< Dynamic entry. */
};

int arp_cache_insert(in_addr_t ip_addr,
                     const mac_addr_t ether_addr,
                     enum arp_cache_entry_type type);
void arp_cache_remove(in_addr_t ip_addr);
int arp_cache_get_haddr(in_addr_t iface, in_addr_t ip_addr, mac_addr_t haddr);