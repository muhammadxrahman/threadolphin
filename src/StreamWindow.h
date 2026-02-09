#ifndef STREAMWINDOW_H
#define STREAMWINDOW_H

#include <QDialog>
#include <QTableWidget>
#include <QTextEdit>
#include <QSplitter>
#include "Packet.h"
#include "StreamIdentifier.h"
#include <vector>

class StreamWindow : public QDialog
{
    Q_OBJECT

public:
    explicit StreamWindow(const StreamIdentifier &stream, 
                         const std::vector<const Packet*> &packets,
                         QWidget *parent = nullptr);

private:
    void setupUI();
    void populatePackets();
    void reassembleStream();
    QString formatConversation(const std::string &data, bool isClient) const;
    
    StreamIdentifier streamId;
    std::vector<const Packet*> streamPackets;
    
    QTableWidget *packetTable;
    QTextEdit *conversationView;
    QSplitter *splitter;
};

#endif // STREAMWINDOW_H