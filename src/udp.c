#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <errno.h>
#include "udp.h"
#include "ip.h"
#include "socket.h"
#include "bstack_internal.h"

RB_HEAD(udp_sock_tree, bstack_sock);

static struct udp_sock_tree udp_sock_tree_head = RB_INITIALIZER();

static int udp_socket_cmp(struct bstack_sock *a, struct bstack_sock *b)
{
    return memcmp(&a->info.sock_addr, &b->info.sock_addr,
                  sizeof(struct bstack_sockaddr));
}

RB_GENERATE_STATIC(udp_sock_tree, bstack_sock, data.udp._entry, udp_socket_cmp);

static struct bstack_sock *find_udp_socket(const struct bstack_sockaddr *addr)
{
    struct bstack_sock_info find = {
        .sock_addr = *addr,
    };

    return RB_FIND(udp_sock_tree, &udp_sock_tree_head,
                   (struct bstack_sock *) (&find));
}

static void udp_hton(const struct udp_hdr *host, struct udp_hdr *net)
{
    net->udp_sport = htons(host->udp_sport);
    net->udp_dport = htons(host->udp_dport);
    net->udp_len = htons(host->udp_len);
}

static void udp_ntoh(const struct udp_hdr *net, struct udp_hdr *host)
{
    host->udp_sport = ntohs(net->udp_sport);
    host->udp_dport = ntohs(net->udp_dport);
    host->udp_len = ntohs(net->udp_len);
}

int bstack_udp_bind(struct bstack_sock *sock)
{

    if (find_udp_socket(&sock->info.sock_addr)) {
        errno = EADDRINUSE;
        return -1;
    }

    RB_INSERT(udp_sock_tree, &udp_sock_tree_head, sock);
    asm volatile("": : :"memory");
    sock->ctrl->intree = true;
    return 0;
}



int udp_input(uint8_t *payload, struct ip_hdr *hdr, size_t len){
    struct udp_hdr *udp = (struct udp_hdr *)payload;
    struct bstack_sockaddr sockaddr;
    struct bstack_sock *sock;
    udp_ntoh(udp,udp);
    sockaddr.inet4_addr = hdr->ip_dst;
    sockaddr.port = udp->udp_dport;
    sock = find_udp_socket(&sockaddr);
    if (sock) {
        int retval;
        struct bstack_sockaddr srcaddr = {
            .inet4_addr = hdr->ip_src,
            .port = udp->udp_sport,
        };
        retval = bstack_sock_dgram_input(sock, &srcaddr, payload + sizeof(struct udp_hdr), len - sizeof(struct udp_hdr));
    }

    printf("udp recv\n");
    return 0;
}

IP_PROTO_INPUT_HANDLER(IP_PROTO_UDP, udp_input);