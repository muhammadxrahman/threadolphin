#include "PacketParser.h"
#include <arpa/inet.h>
#include <sstream>
#include <iomanip>

void PacketParser::parsePacket(Packet &packet)
{
    if (packet.rawData.size() < 14) // Minimum ethernet header
        return;
    
    const u_char *data = packet.rawData.data();
    
    // Parse Ethernet header
    const sniff_ethernet *ethernet = (const sniff_ethernet *)data;
    
    if (ntohs(ethernet->ether_type) != 0x0800) // Not IP
    {
        packet.protocol = "Non-IP";
        return;
    }
    
    // Parse IP header
    if (packet.rawData.size() < 14 + 20) // Ethernet + minimum IP
        return;
    
    const sniff_ip *ip = (const sniff_ip *)(data + 14);
    int size_ip = IP_HL(ip) * 4;
    
    if (size_ip < 20)
        return;
    
    // Extract IP addresses
    packet.srcIP = inet_ntoa(ip->ip_src);
    packet.dstIP = inet_ntoa(ip->ip_dst);
    
    // Check protocol
    if (ip->ip_p == 6) // TCP
    {
        if (packet.rawData.size() < 14 + size_ip + 20) // + minimum TCP
            return;
        
        const sniff_tcp *tcp = (const sniff_tcp *)(data + 14 + size_ip);
        int size_tcp = TH_OFF(tcp) * 4;
        
        if (size_tcp < 20)
            return;
        
        packet.srcPort = std::to_string(ntohs(tcp->th_sport));
        packet.dstPort = std::to_string(ntohs(tcp->th_dport));
        packet.protocol = "TCP";
        
        // Build info string with flags
        std::ostringstream info;
        info << packet.srcPort << " → " << packet.dstPort;
        
        std::string flags = formatFlags(tcp->th_flags);
        if (!flags.empty())
            info << " [" << flags << "]";
        
        info << " Seq=" << ntohl(tcp->th_seq);
        
        if (tcp->th_flags & TH_ACK)
            info << " Ack=" << ntohl(tcp->th_ack);
        
        info << " Win=" << ntohs(tcp->th_win);
        
        int payloadSize = ntohs(ip->ip_len) - (size_ip + size_tcp);
        if (payloadSize > 0)
            info << " Len=" << payloadSize;
        
        packet.info = info.str();
    }
    else if (ip->ip_p == 17) // UDP
    {
        if (packet.rawData.size() < 14 + size_ip + 8) // + UDP header
            return;
        
        const sniff_udp *udp = (const sniff_udp *)(data + 14 + size_ip);
        
        packet.srcPort = std::to_string(ntohs(udp->uh_sport));
        packet.dstPort = std::to_string(ntohs(udp->uh_dport));
        packet.protocol = "UDP";
        
        std::ostringstream info;
        info << packet.srcPort << " → " << packet.dstPort;
        info << " Len=" << (ntohs(udp->uh_ulen) - 8); // Minus UDP header
        
        packet.info = info.str();
    }
    else if (ip->ip_p == 1) // ICMP
    {
        packet.protocol = "ICMP";
        packet.info = "ICMP packet";
    }
    else
    {
        packet.protocol = "Other (" + std::to_string(ip->ip_p) + ")";
        packet.info = "Protocol " + std::to_string(ip->ip_p);
    }
}

std::string PacketParser::formatFlags(u_char flags)
{
    std::string result;
    
    if (flags & TH_SYN) result += "SYN ";
    if (flags & TH_ACK) result += "ACK ";
    if (flags & TH_FIN) result += "FIN ";
    if (flags & TH_RST) result += "RST ";
    if (flags & TH_PUSH) result += "PSH ";
    if (flags & TH_URG) result += "URG ";
    
    // Remove trailing space
    if (!result.empty())
        result.pop_back();
    
    return result;
}