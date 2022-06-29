#include <arpa/inet.h>

uint32_t ip_parse(char *addr)
{
    uint32_t dst = 0;
    if (inet_pton(AF_INET, addr, &dst)!=1){
        perror("ERR: Parsing inet address failed");
        exit(1);
    }
    return ntohl(dst);
}
