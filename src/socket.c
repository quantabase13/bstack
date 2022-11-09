#include "socket.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "queue_r.h"
#include "logger.h"


char *SOCK_D_ADDRESS = "unix-dgram-server.temp";


static void block_sigusr2(void)
{
    sigset_t sigset;

    sigemptyset(&sigset);
    sigaddset(&sigset, SIGUSR2);

    if (pthread_sigmask(SIG_BLOCK, &sigset, NULL) == -1)
        abort();
}

void *bstack_listen(const char *socket_path)
{
    int fd;
    void *pa;

    fd = open(socket_path, O_RDWR);
    if (fd == -1){
        LOG(LOG_ERR, "open failed!");
        return NULL;
    }
    pa = mmap(0, BSTACK_SHMEM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (pa == MAP_FAILED){
        perror ("map failed");
        return NULL;
    }
    
    block_sigusr2();
    BSTACK_SOCK_CTRL(pa)->pid_end = getpid();
    
    return pa;
}

ssize_t bstack_recvfrom(void *socket,
                        void *restrict buffer,
                        size_t length,
                        int flags,
                        struct bstack_sockaddr *restrict address)
{
    struct queue_cb *ingress_q = BSTACK_INGRESS_QADDR(socket);
    struct bstack_dgram *dgram;
    sigset_t sigset;
    int dgram_index;
    ssize_t rd;

    sigemptyset(&sigset);
    sigaddset(&sigset, SIGUSR2);
    while(!BSTACK_SOCK_CTRL(socket)->intree){
        struct timespec timeout = {
            .tv_sec = 1,
            .tv_nsec = 0,
        };   
        sigtimedwait(&sigset, NULL, &timeout);
    }
    do {
        struct timespec timeout = {
            .tv_sec = 1,
            .tv_nsec = 0,
        };

        sigtimedwait(&sigset, NULL, &timeout);
    } while (!queue_peek(ingress_q, &dgram_index));
    dgram =
        (struct bstack_dgram *) (BSTACK_INGRESS_DADDR(socket) + dgram_index);

    if (address)
        *address = dgram->srcaddr;
    rd = smin(length, dgram->buf_size);
    memcpy(buffer, dgram->buf, rd);
    dgram = NULL;

    if (!(flags & BSTACK_MSG_PEEK))
        queue_discard(ingress_q, 1);

    return rd;
}

int bstack_sockd_send(struct bstack_sock sock)
{
    int fd;
    int retval;
    struct sockaddr_un sockd;
    if ((fd = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1){
        perror("socket");
        exit(1);
    }
    int sock_fd = open(sock.shmem_path, O_CREAT|O_RDWR, 0664);
    if (sock_fd == -1) {
        LOG(LOG_ERR, "Failed to open shmem file");
        exit(1);
    }
    ftruncate(sock_fd, (1<<20));
    close(sock_fd);

    sockd.sun_family = AF_UNIX;
    strcpy(sockd.sun_path, SOCK_D_ADDRESS);
    int len = strlen(sockd.sun_path) + sizeof(sockd.sun_family);
    retval = sendto(fd, (uint8_t *)(&sock), sizeof(sock), 0, (struct sockaddr *)(&sockd), len);
    if (retval < 0){
        perror("sendto");
        exit(1);
    }
    return retval;


}
