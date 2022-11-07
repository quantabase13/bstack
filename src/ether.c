#include "ether.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include "logger.h"

SET_DECLARE(_ether_proto_handlers, struct _ether_proto_handler);

mac_addr_t mac_broadcast_addr = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
int ether_input(uint8_t *payload, struct ether_hdr *hdr, size_t len)
{
    struct _ether_proto_handler **tmpp;
    struct _ether_proto_handler *proto;

    int retval;
    SET_FOREACH (tmpp, _ether_proto_handlers) {
        proto = *tmpp;
        if (proto->proto_id == (hdr->h_proto))
            break;
        proto = NULL;
    }
    LOG(LOG_DEBUG, "proto id: 0x%x", (unsigned) hdr->h_proto);
    if (proto) {
        proto->fn(payload, hdr, len);
    }
    return 0;
}


uint32_t ether_fcs(uint8_t *data, size_t len)
{
    const uint8_t *dp = data;
    const uint32_t crc_table[] = {
        0x4DBDF21C, 0x500AE278, 0x76D3D2D4, 0x6B64C2B0, 0x3B61B38C, 0x26D6A3E8,
        0x000F9344, 0x1DB88320, 0xA005713C, 0xBDB26158, 0x9B6B51F4, 0x86DC4190,
        0xD6D930AC, 0xCB6E20C8, 0xEDB71064, 0xF0000000};
    uint32_t crc = 0;

    for (size_t i = 0; i < len; i++) {
        crc = (crc >> 4) ^ crc_table[(crc ^ (dp[i] >> 0)) & 0x0F];
        crc = (crc >> 4) ^ crc_table[(crc ^ (dp[i] >> 4)) & 0x0F];
    }

    return crc;
}
