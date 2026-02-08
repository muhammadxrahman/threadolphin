#include "PacketCapture.h"
#include <iostream>

PacketCapture::PacketCapture()
    : handle(nullptr), allDevices(nullptr)
{
}

PacketCapture::~PacketCapture()
{
    closeDevice();
    freeDevices();
}

std::vector<NetworkDevice> PacketCapture::getDevices(std::string &errorMsg)
{
    std::vector<NetworkDevice> devices;
    char errorBuffer[PCAP_ERRBUF_SIZE];
    
    // Free any previously found devices
    freeDevices();
    
    // Find all devices
    if (pcap_findalldevs(&allDevices, errorBuffer) == -1)
    {
        errorMsg = std::string("Error finding devices: ") + errorBuffer;
        return devices;
    }
    
    // Convert to vector
    pcap_if_t *device = allDevices;
    while (device != nullptr)
    {
        NetworkDevice netDevice;
        netDevice.name = device->name;
        netDevice.description = device->description ? device->description : "No description";
        
        devices.push_back(netDevice);
        device = device->next;
    }
    
    return devices;
}

bool PacketCapture::openDevice(const std::string &deviceName, std::string &errorMsg)
{
    // Close any existing device
    closeDevice();
    
    char errorBuffer[PCAP_ERRBUF_SIZE];
    
    // Open the device
    // Arguments: device name, snaplen (65535 = whole packet), 
    //            promiscuous (1 = on), timeout (1000ms), error buffer
    handle = pcap_open_live(deviceName.c_str(), 65535, 1, 1000, errorBuffer);
    
    if (handle == nullptr)
    {
        errorMsg = std::string("Error opening device: ") + errorBuffer;
        return false;
    }
    
    return true;
}

void PacketCapture::closeDevice()
{
    if (handle != nullptr)
    {
        pcap_close(handle);
        handle = nullptr;
    }
}

bool PacketCapture::isOpen() const
{
    return handle != nullptr;
}

void PacketCapture::freeDevices()
{
    if (allDevices != nullptr)
    {
        pcap_freealldevs(allDevices);
        allDevices = nullptr;
    }
}