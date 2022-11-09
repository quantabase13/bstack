#include "socket.h"
#include "udp.h"

int bstack_sock_dgram_input(struct bstack_sock *sock, struct bstack_sockaddr *srcaddr ,uint8_t *payload, size_t len);
int bstack_udp_bind(struct bstack_sock *sock);
