#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "socket.h"

static char buf[2048];

int main(void)
{
    struct bstack_sock sock_send = {
        .info.sock_dom = XF_INET4,
        .info.sock_type = XSOCK_DGRAM,
        .info.sock_proto = XIP_PROTO_UDP,
        .info.sock_addr =
            (struct bstack_sockaddr){
                .inet4_addr = 167772162,
                .port = 20,
            },
        .shmem_path = "/tmp/unetcat2.sock",
    };
    int retval = bstack_sockd_send(sock_send);
    if (retval < 0) {
        perror("send fail");
        exit(1);
    }
    void *sock = bstack_listen("/tmp/unetcat2.sock");
    if (!sock) {
        perror("Failed to open sock");
        exit(1);
    }

    while (1) {
        struct bstack_sockaddr addr;
        size_t r;

        memset(buf, 0, sizeof(buf));
        r = bstack_recvfrom(sock, buf, sizeof(buf) - 1, 0, &addr);
        if (r > 0)
            write(STDOUT_FILENO, buf, r);
    }
}