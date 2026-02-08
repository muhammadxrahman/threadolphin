#ifndef PACKETCAPTURE_H
#define PACKETCAPTURE_H

#include <string>
#include <vector>
#include <pcap.h>

struct NetworkDevice
{
    std::string name;
    std::string description;
};

class PacketCapture
{
public:
    PacketCapture();
    ~PacketCapture();

    // Get list of available network devices
    std::vector<NetworkDevice> getDevices(std::string &errorMsg);

    // Open a device for capture
    bool openDevice(const std::string &deviceName, std::string &errorMsg);

    // Close the current device
    void closeDevice();

    // Check if a device is currently open
    bool isOpen() const;

private:
    pcap_t *handle;
    pcap_if_t *allDevices;

    void freeDevices();
};

#endif // PACKETCAPTURE_H