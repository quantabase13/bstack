#include <stdint.h>

struct sk_buff;

struct netdev{
    uint32_t addr;
    uint8_t addr_len;
    uint8_t hwaddr[6];
    uint32_t mtu;
};

void netdev_tap_init(void);
void netdev_init(char *addr, char *hwaddr, uint32_t mtu);
int netdev_transmit(struct sk_buff *skb, uint8_t *dst_hw, uint16_t ethertype);
void netdev_rx_loop(void);
