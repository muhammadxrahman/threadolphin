#ifndef PACKET_H
#define PACKET_H

#include <vector>
#include <string>
#include <ctime>

struct Packet
{
    int number;                      
    struct timeval timestamp;        
    std::vector<u_char> rawData; // bytes
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