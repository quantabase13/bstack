#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>


#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "skbuff.h"
#include "ether.h"
#include "arp.h"
#include "tap_init.h"
#include "ip.h"
#include "netdev.h"

#define IFNAMESIZE 5

static int tun_fd;
struct netdev *net_dev;

void netdev_init(char *addr, char *hwaddr, uint32_t mtu)
{
    struct netdev *dev = malloc(sizeof(struct netdev));
    dev->addr = ip_parse(addr);
    sscanf(hwaddr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &dev->hwaddr[0],
                                                    &dev->hwaddr[1],
                                                    &dev->hwaddr[2],
                                                    &dev->hwaddr[3],
                                                    &dev->hwaddr[4],
                                                    &dev->hwaddr[5]);
    dev->addr_len = 6;
    dev->mtu = mtu;
    net_dev = dev;
}

void netdev_tap_init()
{
    char tun_name[IFNAMESIZE];
    strcpy(tun_name, "tap2");
    tun_fd = tun_alloc(tun_name, IFF_TAP|IFF_NO_PI);  
    if (tun_fd < 0){
        perror("Allocating interface");
        exit(1);
    }

}

int netdev_transmit(struct sk_buff *skb, uint8_t *dst_hw, uint16_t ethertype)
{
    struct netdev *dev;
    struct eth_hdr *hdr;
    int ret = 0;

    // skb->data -= sizeof(struct eth_hdr);
    hdr = (struct eth_hdr*)skb->data;
    memcpy(hdr->dmac, dst_hw, net_dev->addr_len);
    memcpy(hdr->smac, net_dev->hwaddr, net_dev->addr_len);
    hdr->ethertype = htons(ethertype);
    ret = write(tun_fd, (char *)skb->data, 150);
    return ret;
}

static int netdev_receive(struct sk_buff *skb)
{
    struct eth_hdr *hdr = (struct eth_hdr*) skb->data;
    hdr->ethertype = ntohs(hdr->ethertype);
    switch(hdr->ethertype){
        case ETH_ARP:
            arp_rcv(skb);
            break;
        default:
            printf("Unsupported ethertype %x\n", hdr->ethertype);
            break;
    }
    return 0;
}

void netdev_rx_loop()
{
    while(1){
        struct sk_buff *skb = skb_alloc(BUFLEN);
        if (read(tun_fd, (char *)skb->data, BUFLEN) < 0) {
            perror("ERR: Read from tun_fd");
        }
        netdev_receive(skb);
    }
}

       
