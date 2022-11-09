
#ifndef SOCK
#define SOCK
#include <netinet/in.h>
#include <sys/types.h>
#include <stdbool.h>
#include "queue_r.h"
#include "tree.h"

#define BSTACK_MSG_PEEK 0x1

#define BSTACK_DATAGRAM_SIZE_MAX 4096
#define BSTACK_DATAGRAM_BUF_SIZE 16384

#define BSTACK_SHMEM_SIZE                                            \
    (sizeof(struct bstack_sock_ctrl) + 2 * sizeof(struct queue_cb) + \
     2 * BSTACK_DATAGRAM_BUF_SIZE)

#define BSTACK_SOCK_CTRL(x) ((struct bstack_sock_ctrl *) (x))

#define BSTACK_INGRESS_QADDR(x)                             \
    ((struct queue_cb *) ((uintptr_t) BSTACK_SOCK_CTRL(x) + \
                          sizeof(struct bstack_sock_ctrl)))

#define BSTACK_INGRESS_DADDR(x)                         \
    ((uint8_t *) ((uintptr_t) BSTACK_INGRESS_QADDR(x) + \
                  sizeof(struct queue_cb)))

#define BSTACK_EGRESS_QADDR(x)                                  \
    ((struct queue_cb *) ((uintptr_t) BSTACK_INGRESS_DADDR(x) + \
                          BSTACK_DATAGRAM_BUF_SIZE))

#define BSTACK_EGRESS_DADDR(x) \
    ((uint8_t *) ((uintptr_t) BSTACK_EGRESS_QADDR(x) + sizeof(struct queue_cb)))
/**
 * Socket domain.
 */
enum bstack_sock_dom {
    XF_INET4, /*!< IPv4 address. */
    XF_INET6, /*!< IPv6 address. */
};

/**
 * Socket type.
 */
enum bstack_sock_type {
    XSOCK_DGRAM,  /*!< Unreliable datagram oriented service. */
    XSOCK_STREAM, /*!< Reliable stream oriented service. */
};

/**
 * Socket protocol.
 */
enum bstack_sock_proto {
    XIP_PROTO_NONE = 0,
    XIP_PROTO_TCP, /*!< TCP/IP. */
    XIP_PROTO_UDP, /*!< UDP/IP. */
    XIP_PROTO_LAST
};

/**
 * Max port number.
 */
#define BSTACK_SOCK_PORT_MAX 49151

/**
 * Socket addresss descriptor.
 */
struct bstack_sockaddr {
    union {
        in_addr_t inet4_addr; /*!< IPv4 address. */
    };
    union {
        int port; /*!< Protocol port. */
    };
};

struct bstack_sock_ctrl {
    pid_t pid_inetd;
    pid_t pid_end;
    bool intree;
};

struct bstack_sock_info {
    enum bstack_sock_dom sock_dom;
    enum bstack_sock_type sock_type;
    enum bstack_sock_proto sock_proto;
    struct bstack_sockaddr sock_addr;
} info;

struct bstack_dgram {
    struct bstack_sockaddr srcaddr;
    struct bstack_sockaddr dstaddr;
    size_t buf_size;
    uint8_t buf[0];
};

/**
 * A generic socket descriptor.
 */
struct bstack_sock {
    struct bstack_sock_info info; /* Must be first */

    struct bstack_sock_ctrl *ctrl;
    uint8_t *ingress_data;
    struct queue_cb *ingress_q;
    uint8_t *egress_data;
    struct queue_cb *egress_q;

    union {
        struct {
            RB_ENTRY(bstack_sock) _entry;
        } udp;
        struct {
            RB_ENTRY(bstack_sock) _entry;
        } tcp;
    } data;
    char shmem_path[80];
};

void *bstack_listen(const char *socket_path);
ssize_t bstack_recvfrom(void *socket,
                        void *restrict buffer,
                        size_t length,
                        int flags,
                        struct bstack_sockaddr *restrict address);
int bstack_sockd_send(struct bstack_sock sock);

#endif