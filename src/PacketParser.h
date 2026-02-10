#ifndef PACKETPARSER_H
#define PACKETPARSER_H

#include "Packet.h"

// Platform-specific includes
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <netinet/in.h>
#endif

// Ethernet Header
#define ETHER_ADDR_LEN 6
struct sniff_ethernet
{
    u_char ether_dhost[ETHER_ADDR_LEN];
    u_char ether_shost[ETHER_ADDR_LEN];
    u_short ether_type;
};

// IP Header
struct sniff_ip
{
    u_char ip_vhl;
    u_char ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
    u_char ip_ttl;
    u_char ip_p;
    u_short ip_sum;
    struct in_addr ip_src, ip_dst;
};

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

// TCP Header
typedef u_int tcp_seq;

struct sniff_tcp
{
    u_short th_sport;
    u_short th_dport;
    tcp_seq th_seq;
    tcp_seq th_ack;
    u_char th_offx2;
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
};

// UDP Header
struct sniff_udp
{
    u_short uh_sport;
    u_short uh_dport;
    u_short uh_ulen;
    u_short uh_sum;
};

class PacketParser
{
public:
    static void parsePacket(Packet &packet);
    
private:
    static std::string formatFlags(u_char flags);
};

#endif // PACKETPARSER_H