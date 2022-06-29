#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "skbuff.h"
#include "netdev.h"
#include "ether.h"
#include "arp.h"


static uint8_t broadcast_hw[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
extern struct netdev *net_dev;
extern uint32_t ip_parse(char *addr);

static void arp_update_table(struct arp_ipv4 *arp_ipv4, struct arp_entry *arp_entry)
{
    memcpy(arp_entry->sender_mac, arp_ipv4->smac, 6);
}

static void arp_insert_table(struct arp_hdr *arphdr, struct arp_ipv4 *arp_ipv4)
{
    struct arp_entry *new_entry = malloc(sizeof(struct arp_entry));
    INIT_LIST_HEAD(&new_entry->list);
    new_entry -> protype = arphdr->protype;
    new_entry -> sender_ip = arp_ipv4 -> sip;
    memcpy(new_entry->sender_mac, arp_ipv4->smac, 6);
    list_add_tail(&new_entry->list, &arp_table);
}


int arp_request(uint32_t sip, uint32_t dip, struct netdev *netdev)
{
    struct sk_buff * skb;
    struct arp_hdr *arp;
    struct arp_ipv4 *payload;
    int rc = 0;

    skb = skb_alloc(ETH_HDR_LEN + ARP_HDR_LEN + ARP_DATA_LEN);
    if (!skb){
        return -1;
    }
    skb->len += sizeof(struct arp_ipv4);
    skb->data -= sizeof(struct arp_ipv4);
    payload = (struct arp_ipv4 *)(skb->data);
    
    

    memcpy(payload->smac, net_dev->hwaddr, net_dev->addr_len);
    payload->sip = sip;
    memcpy(payload->dmac, broadcast_hw, net_dev->addr_len);
    payload->dip = dip;

    skb->len += sizeof(struct arp_hdr);
    skb->data -= sizeof(struct arp_hdr);
    arp = (struct arp_hdr *)(skb->data);

    skb->data -= sizeof(struct eth_hdr);
    
    
    

    arp->opcode = htons(ARP_REQUEST);
    arp->hwtype = htons(ARP_ETHERNET);
    arp->protype = htons(ETH_P_IP);
    arp->hwsize = netdev->addr_len;
    arp->prosize = 4;

    payload->sip = htonl(payload->sip);
    payload->dip = htonl(payload->dip);
    

    netdev_transmit(skb, broadcast_hw, ETH_ARP);
    return rc;


}

static void arp_reply(struct sk_buff* skb)
{
    struct arp_hdr *arphdr;
    struct arp_ipv4 *arpdata;

    arphdr =  (struct arp_hdr *)(skb->data+ sizeof(struct eth_hdr));
    arpdata = (struct arp_ipv4 *)arphdr->data;

    memcpy(arpdata->dmac, arpdata->smac, 6);
    arpdata->dip = arpdata->sip;
    memcpy(arpdata->smac, net_dev->hwaddr, 6);
    arpdata->sip = htonl(net_dev->addr);
    arphdr->opcode = ARP_REPLY;

    arphdr->opcode = htons(arphdr->opcode);
   

    printf("send\n");
    netdev_transmit(skb, arpdata->dmac, ETH_ARP);
}


void arp_rcv(struct sk_buff* skb)
{
    printf("ARP_RCV test\n");
    struct arp_hdr *arphdr;
    struct arp_ipv4 *arpdata;
    struct arp_entry *cur;
    bool merge = false;

    arphdr = (struct arp_hdr *)(skb->data + sizeof(struct eth_hdr));
    arphdr->opcode = ntohs(arphdr->opcode);
    arpdata = (struct arp_ipv4 *)arphdr->data;

    if (list_empty(&arp_table)){
        // if (net_dev->addr == arpdata->dip){
            arp_insert_table(arphdr, arpdata);
            printf("ARP INSERT\n");
        // }
    } else {
       if (net_dev->addr == arpdata->dip){
            list_for_each_entry(cur, &arp_table, list){
                if (cur->protype == arphdr->protype && cur->sender_ip == arpdata->sip){
                    arp_update_table(arpdata, cur);
                    printf("ARP UPDATE\n");
                    merge = true;
                }        
            }
            if (merge == false){
                arp_insert_table(arphdr, arpdata);
                printf("ARP INSERT\n");
            }
        }      
    }




    switch(arphdr->opcode){
    case ARP_REQUEST:
        arp_reply(skb);
        arp_request(ip_parse("10.0.0.2"), ip_parse("10.0.0.1"), net_dev);
        return;

}

}

