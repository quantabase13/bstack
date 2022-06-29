#include <stdlib.h>
#include <string.h>
#include "skbuff.h"



struct sk_buff *skb_alloc(int size)
{
    struct sk_buff *skb = malloc(sizeof(struct sk_buff));
    memset(skb, 0, sizeof(struct sk_buff));
    skb->data = malloc(size);
    memset(skb->data, 0, size);
    skb->data = skb->data + size;
    return skb;
}