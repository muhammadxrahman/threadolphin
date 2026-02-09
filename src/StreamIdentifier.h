#ifndef STREAMIDENTIFIER_H
#define STREAMIDENTIFIER_H

#include <string>

struct StreamIdentifier
{
    std::string srcIP;
    std::string dstIP;
    std::string srcPort;
    std::string dstPort;
    
    // Check if a packet matches this stream (in either direction)
    bool matches(const std::string &ip1, const std::string &port1,
                 const std::string &ip2, const std::string &port2) const
    {
        // Forward direction
        if (ip1 == srcIP && port1 == srcPort && ip2 == dstIP && port2 == dstPort)
            return true;
        
        // Reverse direction
        if (ip1 == dstIP && port1 == dstPort && ip2 == srcIP && port2 == srcPort)
            return true;
        
        return false;
    }
    
    // Check if this is the client->server direction
    bool isClientToServer(const std::string &ip, const std::string &port) const
    {
        return (ip == srcIP && port == srcPort);
    }
    
    std::string toString() const
    {
        return srcIP + ":" + srcPort + " ↔ " + dstIP + ":" + dstPort;
    }
};

#endif // STREAMIDENTIFIER_H