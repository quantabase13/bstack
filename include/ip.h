#include <arpa/inet.h>

struct iphdr {
    uint8_t version : 4;
    uint8_t ihl : 4;
    uint8_t tos;
    uint16_t len;
    uint16_t id;
    uint16_t flags :3;
    uint16_t frag_offset : 13;
    uint8_t ttl;
    uint8_t proto;
    uint16_t csum;
    uint32_t saddr;
    uint32_t daddr;
} __attribute__((packed));

uint32_t ip_parse(char *addr)
{
    uint32_t dst = 0;
    if (inet_pton(AF_INET, addr, &dst)!=1){
        perror("ERR: Parsing inet address failed");
        exit(1);
    }
    return ntohl(dst);
}

uint16_t checksum(void *addr, int count)
{
    uint32_t sum = 0;
    uint16_t *ptr = addr;
    /*one's complement sum part start*/
    while (count > 0){
        sum += ((*ptr) & 0xff) << 8; //little endian to big endian
        sum += ((*ptr) >> 8) & 0xff;
        ptr++;
        count -=2; 
    }
    uint16_t sum_h = *((uint16_t *)(void *)(&sum)+1);
    sum += sum_h;
    /*one's complement sum part end*/

    return ~(uint16_t)(sum & 0xffff);
}