#include <linux/if.h>
#include <linux/if_tun.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "tap_init.h"



int tun_alloc(char *dev, int flags)
{
    struct ifreq ifr;
    int fd, err;

    if ((fd = open(clonedev, O_RDWR))<0){
        printf("err open\n");
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = flags;

    if (*dev){
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ){
        close(fd);
        printf("err\n");
        return err;
    }

    strcpy(dev, ifr.ifr_name);

    return fd;

}