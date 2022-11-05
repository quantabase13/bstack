#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "logger.h"
#include "netdevice.h"
#include "ether.h"

static pthread_t ingress_tid, egress_tid, sockd_tid;
static int netdevice_handle;
void *bstack_sockd(void *arg){
    while(1){
       ;
    }

}
void *bstack_ingress(void *arg){
    static uint8_t rx_buffer[ETHER_MAXLEN];
    while(1){
        int retval;
        retval = netdevice_receive(netdevice_handle, rx_buffer,sizeof(rx_buffer));
        if (retval == -1){
            LOG(LOG_ERR, "Rx failed: %d", errno);
        }else if (retval > 0){
            LOG(LOG_ERR, "Frame Receive!");
        }
    }
}

void *bstack_egress(void *arg){
    while(1){
        ;
    }
}

int bstack_start(){

    if (pthread_create(&ingress_tid, NULL, bstack_ingress, NULL)){
        return -1;
    }
    if (pthread_create(&egress_tid, NULL, bstack_egress, NULL)){
        return -1;
    }
    if (pthread_create(&sockd_tid, NULL, bstack_sockd, NULL)){
        return -1;
    }
    return 0;
}
int bstack_stop(){
    pthread_join(ingress_tid, NULL);
    pthread_join(egress_tid, NULL);
    return 0;
}

int main(int argc, char *argv[]){
    if (argc == 1){
        fprintf(stderr, "Usage: %s INTERFACE\n", argv[0]);
        exit(1);
    }
    char *const ether_args[] = {
        argv[1],
        NULL,
    };

    if (netdevice_init(ether_args) < 0){
        LOG(LOG_ERR, "init failed: %d", errno);
        return 0;
    }
    bstack_start();
    bstack_stop();
    return 0;
}