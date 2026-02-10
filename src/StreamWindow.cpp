#include "StreamWindow.h"
#include <QVBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <sstream>
#include <iomanip>
#include <cctype>

StreamWindow::StreamWindow(const StreamIdentifier &stream, 
                          const std::vector<const Packet*> &packets,
                          QWidget *parent)
    : QDialog(parent), streamId(stream), streamPackets(packets)
{
    setWindowTitle("Follow TCP Stream - " + QString::fromStdString(stream.toString()));
    resize(1000, 700);
    
    setupUI();
    populatePackets();
    reassembleStream();
}

void StreamWindow::setupUI()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    
    // Stream info label
    QLabel *infoLabel = new QLabel(
        "TCP Stream: " + QString::fromStdString(streamId.toString()), this);
    infoLabel->setStyleSheet("font-weight: bold; padding: 5px;");
    mainLayout->addWidget(infoLabel);
    
    // Splitter for packets and conversation
    splitter = new QSplitter(Qt::Vertical, this);
    
    // Top: Packet table
    packetTable = new QTableWidget(this);
    packetTable->setColumnCount(6);
    packetTable->setHorizontalHeaderLabels({"No.", "Time", "Source", "Destination", "Length", "Info"});
    packetTable->setAlternatingRowColors(true);
    packetTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    packetTable->horizontalHeader()->setStretchLastSection(true);
    packetTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    splitter->addWidget(packetTable);
    
    // Bottom: Conversation view
    conversationView = new QTextEdit(this);
    conversationView->setReadOnly(true);
    conversationView->setFont(QFont("Courier", 11));
    splitter->addWidget(conversationView);
    
    splitter->setStretchFactor(0, 2);
    splitter->setStretchFactor(1, 3);
    
    mainLayout->addWidget(splitter);
}

void StreamWindow::populatePackets()
{
    packetTable->setRowCount(streamPackets.size());
    
    for (size_t i = 0; i < streamPackets.size(); i++)
    {
        const Packet *packet = streamPackets[i];
        
        // Packet number
        packetTable->setItem(i, 0, new QTableWidgetItem(QString::number(packet->number)));
        
        // Time
        QString timeStr = QString("%1.%2")
            .arg(packet->timestamp.tv_sec)
            .arg(packet->timestamp.tv_usec, 6, 10, QChar('0'));
        packetTable->setItem(i, 1, new QTableWidgetItem(timeStr));
        
        // Source
        QString src = QString::fromStdString(packet->srcIP);
        if (!packet->srcPort.empty())
            src += ":" + QString::fromStdString(packet->srcPort);
        packetTable->setItem(i, 2, new QTableWidgetItem(src));
        
        // Destination
        QString dst = QString::fromStdString(packet->dstIP);
        if (!packet->dstPort.empty())
            dst += ":" + QString::fromStdString(packet->dstPort);
        packetTable->setItem(i, 3, new QTableWidgetItem(dst));
        
        // Length
        packetTable->setItem(i, 4, new QTableWidgetItem(QString::number(packet->length)));
        
        // Info
        packetTable->setItem(i, 5, new QTableWidgetItem(QString::fromStdString(packet->info)));
        
        // Color code by direction - DARK THEME
        QColor bgColor, textColor;
        if (streamId.isClientToServer(packet->srcIP, packet->srcPort))
        {
            // Client -> Server: Dark blue background, light blue text
            bgColor = QColor(25, 35, 60);
            textColor = QColor(150, 200, 255);
        }
        else
        {
            // Server -> Client: Dark orange background, light orange text
            bgColor = QColor(60, 40, 25);
            textColor = QColor(255, 200, 150);
        }
        
        for (int col = 0; col < 6; col++)
        {
            packetTable->item(i, col)->setBackground(bgColor);
            packetTable->item(i, col)->setForeground(textColor);
        }
    }
    
    packetTable->resizeColumnsToContents();
}

void StreamWindow::reassembleStream()
{
    std::string clientData;
    std::string serverData;
    
    // Extract payloads from each packet
    for (const Packet *packet : streamPackets)
    {
        if (packet->rawData.size() < 14)
            continue;
        
        // Calculate payload start (similar to detail view logic)
        int payloadStart = 14;  // Ethernet header
        
        if (!packet->srcIP.empty())
        {
            const u_char *data = packet->rawData.data();
            const u_char *ip = data + 14;
            int ipHeaderLen = (ip[0] & 0x0f) * 4;
            payloadStart += ipHeaderLen;
            
            if (packet->protocol == "TCP" && packet->rawData.size() > payloadStart + 12)
            {
                const u_char *tcp = data + 14 + ipHeaderLen;
                int tcpHeaderLen = ((tcp[12] & 0xf0) >> 4) * 4;
                payloadStart += tcpHeaderLen;
            }
        }
        
        int payloadLen = packet->length - payloadStart;
        
        if (payloadLen > 0 && payloadStart < packet->rawData.size())
        {
            const u_char *payload = packet->rawData.data() + payloadStart;
            std::string payloadStr(payload, payload + payloadLen);
            
            // Add to appropriate stream
            if (streamId.isClientToServer(packet->srcIP, packet->srcPort))
                clientData += payloadStr;
            else
                serverData += payloadStr;
        }
    }
    
    // Format and display
    QString conversation;
    
    conversation += "════════════════════════════════════════════════════════════════\n";
    conversation += QString("Stream: %1\n").arg(QString::fromStdString(streamId.toString()));
    conversation += QString("Packets: %1 | Client Data: %2 bytes | Server Data: %3 bytes\n")
        .arg(streamPackets.size())
        .arg(clientData.size())
        .arg(serverData.size());
    conversation += "════════════════════════════════════════════════════════════════\n\n";
    
    if (!clientData.empty())
    {
        conversation += formatConversation(clientData, true);
        conversation += "\n";
    }
    
    if (!serverData.empty())
    {
        conversation += formatConversation(serverData, false);
    }
    
    if (clientData.empty() && serverData.empty())
    {
        conversation += "No application data in this stream (only TCP handshake/ACKs)\n";
    }
    
    conversationView->setPlainText(conversation);
}

QString StreamWindow::formatConversation(const std::string &data, bool isClient) const
{
    QString result;
    
    if (isClient)
        result += "┌─ CLIENT → SERVER\n";
    else
        result += "┌─ SERVER → CLIENT\n";
    
    // Try to display as text if mostly printable
    int printableCount = 0;
    for (char c : data)
    {
        if (isprint(c) || c == '\n' || c == '\r' || c == '\t')
            printableCount++;
    }
    
    bool isText = (data.size() > 0 && printableCount > data.size() * 0.7);
    
    if (isText)
    {
        // Display as text
        std::istringstream stream(data);
        std::string line;
        while (std::getline(stream, line))
        {
            result += "│  " + QString::fromStdString(line) + "\n";
        }
    }
    else
    {
        // Display as hex dump
        result += "│  [Binary data - showing hex dump]\n│\n";
        
        size_t maxSize = (data.size() < 256) ? data.size() : 256;
        for (size_t i = 0; i < maxSize; i += 16)
        {
            result += QString("│  %1  ").arg(i, 4, 16, QChar('0'));
            
            // Hex bytes
            for (size_t j = 0; j < 16; j++)
            {
                if (i + j < data.size())
                {
                    result += QString("%1 ").arg((unsigned char)data[i + j], 2, 16, QChar('0'));
                }
                else
                {
                    result += "   ";
                }
                
                if (j == 7) result += " ";
            }
            
            result += " | ";
            
            // ASCII
            for (size_t j = 0; j < 16 && (i + j) < data.size(); j++)
            {
                char c = data[i + j];
                result += isprint(c) ? c : '.';
            }
            
            result += "\n";
        }
        
        if (data.size() > 256)
        {
            result += QString("│  ... (%1 more bytes)\n").arg(data.size() - 256);
        }
    }
    
    result += "└─\n";
    
    return result;
}