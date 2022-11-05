#include <stddef.h>
#include <stdint.h>

int netdevice_fd;
int netdevice_init(char *const args[]);
int netdevice_receive(int sd, uint8_t buffer[], size_t len);