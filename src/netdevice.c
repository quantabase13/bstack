
#include "netdevice.h"
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include "bstack_link.h"
#include "ether.h"
#include "logger.h"
#include "queue_r.h"

#define MAX_IF 1

struct ether_linux {
    int el_fd;
    mac_addr_t el_mac;
    struct queue_cb *ingress_q;
    uint8_t *ingress_data;
    struct ifreq el_if_idx;
};

static struct ether_linux ether_if[MAX_IF];

static int netdevice_bind(struct ether_linux *eth);

int netdevice_init(char *const args[])
{
    struct ifreq if_mac = {0};
    struct ether_linux *eth;
    int retval;
    char if_name[IFNAMSIZ];

    if (args[0]) {
        if (strnlen(args[0], IFNAMSIZ) < IFNAMSIZ) {
            strcpy(if_name, args[0]);
        } else {
            return -2;
        }
    }
    eth = &ether_if[0];
    if ((eth->el_fd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
        return -1;
    }
    memset(&eth->el_if_idx, 0, sizeof(struct ifreq));
    strncpy(eth->el_if_idx.ifr_name, if_name, IFNAMSIZ - 1);
    if (ioctl(eth->el_fd, SIOCGIFINDEX, &eth->el_if_idx) < 0) {
        goto fail;
    }
    memset(&if_mac, 0, sizeof(struct ifreq));
    strncpy(if_mac.ifr_name, if_name, IFNAMSIZ - 1);
    if (ioctl(eth->el_fd, SIOCGIFHWADDR, &if_mac) < 0) {
        goto fail;
    }

    for (int i = 0; i < LINK_MAC_ALEN; i++) {
        eth->el_mac[i] = ((uint8_t *) &if_mac.ifr_hwaddr.sa_data)[i];
    }
    eth->ingress_q = (struct queue_cb *) ((uintptr_t) malloc(
        sizeof(struct queue_cb) + 16384));
    eth->ingress_data =
        (uint8_t *) ((uintptr_t)(eth->ingress_q) + sizeof(struct queue_cb));
    *eth->ingress_q = queue_create(4096, 16384);
    if (netdevice_bind(eth)) {
        goto fail;
    }
    return 1;
fail:
    close(eth->el_fd);
    return -1;
}
static int netdevice_bind(struct ether_linux *eth)
{
    struct ifreq ifopts = {0};
    struct sockaddr_ll socket_address = {0};
    int sockopt, retval;

    strncpy(ifopts.ifr_name, eth->el_if_idx.ifr_name, IFNAMSIZ - 1);
    ioctl(eth->el_fd, SIOCGIFFLAGS, &ifopts);
    ifopts.ifr_flags |= IFF_PROMISC;
    ioctl(eth->el_fd, SIOCSIFFLAGS, &ifopts);
    retval = setsockopt(eth->el_fd, SOL_SOCKET, SO_REUSEADDR, &sockopt,
                        sizeof(sockopt));
    if (retval == -1) {
        return -1;
    }
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ALL);
    socket_address.sll_ifindex = eth->el_if_idx.ifr_ifindex;
    socket_address.sll_pkttype =
        PACKET_OTHERHOST | PACKET_BROADCAST | PACKET_MULTICAST | PACKET_HOST;
    socket_address.sll_halen = ETHER_ALEN;
    for (int i = 0; i < ETHER_ALEN; i++) {
        socket_address.sll_addr[i] = eth->el_mac[i];
    }
    if (bind(eth->el_fd, (struct sockaddr *) &socket_address,
             sizeof(socket_address)) < 0) {
        LOG(LOG_ERR, "bind failed: %d", errno);
    }
    return 0;
}
int netdevice_receive(int handle, uint8_t buffer[], size_t len)
{
    struct ether_linux *eth;
    int retval;
    int frame_index;
    uint8_t frame[ETHER_MAXLEN] __attribute__((aligned));
    eth = &ether_if[handle];
    while ((frame_index = queue_alloc(eth->ingress_q)) == -1) {
        ;
    }
    retval = recvfrom(eth->el_fd, frame, sizeof(frame), 0, NULL, NULL);
    if (retval == -1) {
        LOG(LOG_ERR, "recv failed: %d", errno);
    }
    memcpy(eth->ingress_data + frame_index, frame, sizeof(frame));
    queue_commit(eth->ingress_q);
    return 1;
}

int netdevice_rx_read(int handle, uint8_t *buffer)
{
    struct ether_linux *eth;
    int frame_index;
    eth = &ether_if[handle];
    if (!queue_isempty(eth->ingress_q)) {
        while (!queue_peek(eth->ingress_q, &frame_index)) {
            ;
        }
        memcpy(buffer, eth->ingress_data + frame_index, ETHER_MAXLEN);
        queue_discard(eth->ingress_q, 1);
        return 0;
    } else {
        return -1;
    }
}
int netdevice_send(int handle, uint8_t buffer[], size_t len)
{
    return 1;
}