#ifndef PACKET_H
#define PACKET_H

#include <vector>
#include <string>

// Platform-specific time includes
#ifdef _WIN32
    #include <winsock2.h>
    // Windows doesn't have timeval in the same place
    // but pcap.h will provide it
#else
    #include <sys/time.h>
#endif

struct Packet
{
    int number;                      
    struct timeval timestamp;        
    std::vector<unsigned char> rawData; // Use unsigned char instead of u_char
    int length;                  
    
    // parsed fields 
    std::string srcIP;
    std::string dstIP;
    std::string srcPort;
    std::string dstPort;
    std::string protocol;
    std::string info;
    
    Packet() : number(0), length(0) 
    {
        timestamp.tv_sec = 0;
        timestamp.tv_usec = 0;
    }
};

#endif // PACKET_H