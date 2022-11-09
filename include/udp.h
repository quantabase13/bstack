#ifndef UDP
#define UDP
/**
 * Type for an UDP port number.
 */
typedef uint16_t udp_port_t;

struct udp_hdr {
    udp_port_t udp_sport; /*!< UDP Source port. */
    udp_port_t udp_dport; /*!< UDP Destination port. */
    uint16_t udp_len;     /*!< UDP datagram length. */
    uint16_t udp_csum;    /*!< UDP Checksum. */
    uint8_t data[0];      /*!< Datagram contents. */
};

#endif