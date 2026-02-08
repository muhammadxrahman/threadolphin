#ifndef CAPTURETHREAD_H
#define CAPTURETHREAD_H

#include <QThread>
#include <QMutex>
#include <pcap.h>
#include <string>

class CaptureThread : public QThread
{
    Q_OBJECT

public:
    explicit CaptureThread(QObject *parent = nullptr);
    ~CaptureThread();
    
    // Start capturing on a specific device
    bool startCapture(const std::string &deviceName, std::string &errorMsg);
    
    // Stop the capture
    void stopCapture();
    
    // Check if currently capturing
    bool isCapturing();

signals:
    // Emitted when a packet is captured (receiver must delete the data)
    void packetCaptured(const u_char *data, int length, const struct timeval &timestamp);
    
    // Emitted when capture stops (error or user stop)
    void captureStopped(const QString &reason);
    
    // Emitted on permission error
    void permissionError(const QString &deviceName);

protected:
    void run() override;

private:
    pcap_t *handle;
    std::string deviceName;
    mutable QMutex mutex;
    bool stopRequested;
    
    static void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, 
                              const u_char *packet);
};

#endif // CAPTURETHREAD_H