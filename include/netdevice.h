#include <stddef.h>
#include <stdint.h>
#include "ether.h"


int netdevice_fd;
int netdevice_init(char *const args[]);
int netdevice_rx_read(int handle, struct ether_hdr *hdr, uint8_t *buffer);
int netdevice_receive(int sd, uint8_t buffer[], size_t len);
int netdevice_send(int handle,
                   mac_addr_t dst,
                   uint16_t proto,
                   uint8_t buffer[],
                   size_t len);
int netdevice_handle2addr(int handle, mac_addr_t addr);