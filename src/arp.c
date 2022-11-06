#include "arp.h"
#include <stdio.h>
#include "ether.h"
int arp_input(void)
{
    printf("arp receive\n");
    return 0;
}

ETHER_PROTO_INPUT_HANDLER(ETHER_P_ARP, arp_input);