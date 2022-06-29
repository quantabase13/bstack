#include <stdint.h>

#define ETH_ARP 0x0806
#define ETH_P_IP 0x0800

#define ETH_HDR_LEN sizeof(struct eth_hdr)

struct eth_hdr
{
    unsigned char dmac[6];
    unsigned char smac[6];
    uint16_t ethertype;
    unsigned char payload[];
}__attribute__((packed));

