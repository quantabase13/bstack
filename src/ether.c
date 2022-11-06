#include "ether.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include "logger.h"

SET_DECLARE(_ether_proto_handlers, struct _ether_proto_handler);
int ether_input(uint8_t *frame)
{
    struct _ether_proto_handler **tmpp;
    struct _ether_proto_handler *proto;
    struct ether_hdr *hdr = (struct ether_hdr *) frame;
    int retval;
    SET_FOREACH (tmpp, _ether_proto_handlers) {
        proto = *tmpp;
        if (proto->proto_id == ntohs(hdr->h_proto))
            break;
        proto = NULL;
    }
    LOG(LOG_DEBUG, "proto id: 0x%x", (unsigned) hdr->h_proto);
    if (proto) {
        proto->fn();
    }
    return 0;
}