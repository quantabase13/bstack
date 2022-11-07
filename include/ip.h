
#include <netinet/in.h>
#define BSTACK_IP_RIB_SIZE 5


/**
 * IP Route descriptor.
 */
struct ip_route {
    in_addr_t r_network; /*!< Network address. */
    in_addr_t r_netmask; /*!< Network mask. */
    in_addr_t r_gw;      /*!< Gateway IP. */
    in_addr_t r_iface;   /*!< Interface address. */
    int r_iface_handle;  /*!< Interface ether_handle. */
};


/**
 * Get routing information for a source IP addess.
 * The function can be also used for source IP address validation by setting
 * route pointer argument to NULL.
 */
int ip_route_find_by_iface(in_addr_t addr, struct ip_route *route);

int ip_route_update(struct ip_route *route);
int ip_config(int ether_handle, in_addr_t ip_addr, in_addr_t netmask);