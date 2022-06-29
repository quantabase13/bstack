#include <stdint.h>

#define BUFLEN 100

struct sk_buff {
    uint8_t *data;
    uint32_t len;
};

struct sk_buff *skb_alloc(int);