#include "ether.h"
struct mbuf {
    int len;
    uint8_t data[ETHER_MAXLEN];
};