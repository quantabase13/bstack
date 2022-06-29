#include <stdio.h>
#include "netdev.h"

int main()
{
    netdev_tap_init();
    netdev_init("10.0.0.2", "00:01:02:03:04:05", 1500);
    netdev_rx_loop();
    return 0;
}