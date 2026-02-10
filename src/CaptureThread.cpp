#include "CaptureThread.h"
// #include <iostream>

// Platform-specific includes
#ifdef _WIN32
    #include <winsock2.h>
#else
    #include <sys/time.h>
#endif

#include <cstring>

CaptureThread::CaptureThread(QObject *parent)
    : QThread(parent), handle(nullptr), stopRequested(false)
{
}

CaptureThread::~CaptureThread()
{
    stopCapture();
    wait(); // Wait for thread to finish
}

bool CaptureThread::startCapture(const std::string &devName, std::string &errorMsg)
{
    QMutexLocker locker(&mutex);
    
    if (handle != nullptr)
    {
        errorMsg = "Capture already running";
        return false;
    }
    
    deviceName = devName;
    char errorBuffer[PCAP_ERRBUF_SIZE];
    
    // Open the device
    handle = pcap_open_live(deviceName.c_str(), 65535, 1, 1000, errorBuffer);
    
    if (handle == nullptr)
    {
        errorMsg = std::string(errorBuffer);
        
        // Check if it's a permission error
        std::string errStr(errorBuffer);
        if (errStr.find("permission") != std::string::npos || 
            errStr.find("Operation not permitted") != std::string::npos ||
            errStr.find("access") != std::string::npos)
        {
            emit permissionError(QString::fromStdString(deviceName));
        }
        
        return false;
    }
    
    stopRequested = false;
    start(); // Start the thread
    return true;
}

void CaptureThread::stopCapture()
{
    QMutexLocker locker(&mutex);
    
    if (handle != nullptr)
    {
        stopRequested = true;
        pcap_breakloop(handle); // Break out of pcap_loop
    }
}

bool CaptureThread::isCapturing()
{
    QMutexLocker locker(&mutex);
    return handle != nullptr && !stopRequested;
}

void CaptureThread::run()
{
    // std::cout << "CaptureThread::run() - Thread started" << std::endl;
    
    if (handle == nullptr)
    {
        // std::cout << "CaptureThread::run() - Handle is null!" << std::endl;
        return;
    }
    
    // std::cout << "CaptureThread::run() - Starting pcap_loop" << std::endl;
    
    // Use pcap_loop with our callback
    // We use -1 to loop indefinitely until pcap_breakloop is called
    int result = pcap_loop(handle, -1, packetHandler, (u_char *)this);
    
    // std::cout << "CaptureThread::run() - pcap_loop exited with result: " << result << std::endl;
    
    // Clean up
    {
        QMutexLocker locker(&mutex);
        if (handle != nullptr)
        {
            pcap_close(handle);
            handle = nullptr;
        }
    }
    
    // Emit stopped signal
    QString reason;
    if (result == -1)
    {
        reason = "Error: " + QString(pcap_geterr(handle));
    }
    else if (result == -2)
    {
        reason = "Stopped by user";
    }
    else
    {
        reason = "Capture ended";
    }
    
    // std::cout << "CaptureThread::run() - Emitting captureStopped" << std::endl;
    emit captureStopped(reason);
}

void CaptureThread::packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, 
                                   const u_char *packet)
{
    // static int count = 0;
    // if (++count <= 5) // Only print first 5 to avoid spam
    // {
    //     std::cout << "Packet captured! Length: " << pkthdr->caplen << std::endl;
    // }

    CaptureThread *thread = reinterpret_cast<CaptureThread *>(userData);
    
    // Make a copy of the packet data since pcap reuses the buffer
    int length = pkthdr->caplen;
    u_char *packetCopy = new u_char[length];
    std::memcpy(packetCopy, packet, length);
    
    // Emit with the copy (MainWindow will delete it)
    emit thread->packetCaptured(packetCopy, length, pkthdr->ts);
}