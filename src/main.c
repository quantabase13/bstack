#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include "bstack_internal.h"
#include "ether.h"
#include "ip.h"
#include "logger.h"
#include "netdevice.h"

char *SOCK_PATH_SERVER = "unix-dgram-server.temp";

static pthread_t ingress_tid, egress_tid, sockd_tid, rx_read_tid;
static int netdevice_handle;
int sock_d;



bstack_sock_dgram_input(struct bstack_sock *sock,
                        struct bstack_sockaddr *srcaddr,
                        uint8_t *payload,
                        size_t len)
{
    LOG(LOG_ERR, "dgrame recv!");
    int dgram_index;
    struct bstack_dgram *dgram;
    while ((dgram_index = queue_alloc(sock->ingress_q)) == -1) {
        ;
    }
    dgram = (struct bstack_dgram *) (sock->ingress_data + dgram_index);
    dgram->srcaddr = *srcaddr;
    dgram->dstaddr = sock->info.sock_addr;
    dgram->buf_size = len;
    memcpy(dgram->buf, payload, len);
    queue_commit(sock->ingress_q);
    return 0;
}

void bstack_sockd_init()
{
    int retval;
    sock_d = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sock_d < 0) {
        perror("socket");
        exit(1);
    }
    struct sockaddr_un sock_local;
    sock_local.sun_family = AF_UNIX;
    strcpy(sock_local.sun_path, SOCK_PATH_SERVER);
    int len = strlen(sock_local.sun_path) + sizeof(sock_local.sun_family);
    retval = bind(sock_d, (struct sockaddr *) &sock_local, len);
    if (retval == -1) {
        perror("bind");
        exit(1);
    }
    LOG(LOG_ERR, "unix sock bound success!");
}

void bstack_sock_init(struct bstack_sock *sock_new)
{
    pid_t mypid = getpid();
    struct bstack_sock *sock = sock_new;
    int fd;
    void *pa;

    fd = open(sock->shmem_path, O_CREAT|O_RDWR, 0664);
    if (fd == -1) {
        perror("Failed to open shmem file");
        exit(1);
    }
    ftruncate(fd, (1<<20));

    pa = mmap(0, BSTACK_SHMEM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (pa == MAP_FAILED) {
        perror("Failed to mmap() shared mem");
        exit(1);
    }
    close(fd);
    LOG(LOG_ERR, "sock file create sucessful");
    memset(pa, 0, BSTACK_SHMEM_SIZE);

    sock->ctrl = BSTACK_SOCK_CTRL(pa);
    *sock->ctrl = (struct bstack_sock_ctrl){
        .pid_inetd = mypid,
        .pid_end = 0,
    };

    sock->ingress_data = BSTACK_INGRESS_DADDR(pa);
    sock->ingress_q = BSTACK_INGRESS_QADDR(pa);
    *sock->ingress_q =
        queue_create(BSTACK_DATAGRAM_SIZE_MAX, BSTACK_DATAGRAM_BUF_SIZE);

    sock->egress_data = BSTACK_EGRESS_DADDR(pa);
    sock->egress_q = BSTACK_EGRESS_QADDR(pa);
    *sock->egress_q =
        queue_create(BSTACK_DATAGRAM_SIZE_MAX, BSTACK_DATAGRAM_BUF_SIZE);
}

void *bstack_sockd(void *arg)
{
    int fd = sock_d;
    int retval;
    uint8_t buf[1024];
    while (1) {
        retval = recvfrom(fd, buf, sizeof(struct bstack_sock), 0, NULL, NULL);
        if (retval < 0) {
            perror("recv sock error");
            exit(1);
        }
        struct bstack_sock *sock_rcv = (struct bstack_sock *) buf;
        bstack_sock_init(sock_rcv);
        bstack_udp_bind(sock_rcv);
    }
}
void *bstack_rx_read(void *arg)
{
    static uint8_t rx_buffer[ETHER_MAXLEN];
    struct ether_hdr hdr;
    while (1) {
        int retval;
        if ((retval = netdevice_rx_read(netdevice_handle, &hdr, rx_buffer)) ==
            -1) {
            continue;
        } else {
            retval = ether_input(rx_buffer, &hdr, retval);
        }
    }
}
void *bstack_ingress(void *arg)
{
    static uint8_t rx_buffer[ETHER_MAXLEN];
    while (1) {
        int retval;
        retval =
            netdevice_receive(netdevice_handle, rx_buffer, sizeof(rx_buffer));
        if (retval == -1) {
            LOG(LOG_ERR, "Rx failed: %d", errno);
        } else if (retval > 0) {
            LOG(LOG_ERR, "Frame Receive!");
        }
    }
}

void *bstack_egress(void *arg)
{
    while (1) {
        ;
    }
}

int bstack_start()
{
    if (pthread_create(&ingress_tid, NULL, bstack_ingress, NULL)) {
        return -1;
    }
    if (pthread_create(&egress_tid, NULL, bstack_egress, NULL)) {
        return -1;
    }
    if (pthread_create(&sockd_tid, NULL, bstack_sockd, NULL)) {
        return -1;
    }
    if (pthread_create(&rx_read_tid, NULL, bstack_rx_read, NULL)) {
        return -1;
    }
    return 0;
}
int bstack_stop()
{
    pthread_join(ingress_tid, NULL);
    pthread_join(egress_tid, NULL);
    pthread_join(sockd_tid, NULL);
    pthread_join(rx_read_tid, NULL);
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc == 1) {
        fprintf(stderr, "Usage: %s INTERFACE\n", argv[0]);
        exit(1);
    }
    char *const ether_args[] = {
        argv[1],
        NULL,
    };

    if (netdevice_init(ether_args) < 0) {
        LOG(LOG_ERR, "init failed: %d", errno);
        return 0;
    }
    ip_config(netdevice_fd, 167772162, 4294967040);
    bstack_sockd_init();
    bstack_start();
    bstack_stop();
    return 0;
}