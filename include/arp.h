#include <stdint.h>
#include "list.h"

#define ARP_ETHERNET    0x0001
#define ARP_IPV4        0x0800

#define ARP_REQUEST 0x0001
#define ARP_REPLY 0x0002

#define ARP_HDR_LEN sizeof(struct arp_hdr)
#define ARP_DATA_LEN sizeof(struct arp_ipv4)

struct arp_hdr
{
    uint16_t hwtype;
    uint16_t protype;
    unsigned char hwsize;
    unsigned char prosize;
    uint16_t opcode;
    unsigned char data[];
}__attribute__((packed));

struct arp_ipv4
{
    unsigned char smac[6];
    uint32_t sip;
    unsigned char dmac[6];
    uint32_t dip;
}__attribute__((packed));

struct arp_entry{
    uint16_t protype;
    uint32_t sender_ip;
    unsigned char sender_mac[6];
    struct list_head list;
};

static LIST_HEAD(arp_table);

void arp_rcv(struct sk_buff * skb);
