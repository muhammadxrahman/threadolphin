#ifndef PACKETMODEL_H
#define PACKETMODEL_H

#include <QAbstractTableModel>
#include <QList>
#include <QColor>
#include "Packet.h"

class PacketModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    explicit PacketModel(QObject *parent = nullptr);
    
    // QAbstractTableModel interface
    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;
    
    // Custom methods
    void addPacket(const Packet &packet);
    void clear();
    const Packet* getPacket(int row) const;
    int getPacketCount() const;

    // Statistics methods
    int getTcpCount() const;
    int getUdpCount() const;
    int getIcmpCount() const;
    int getNonIpCount() const;
    int getOtherCount() const;
    qint64 getTotalBytes() const;
    
    // Set maximum packet limit
    void setMaxPackets(int max);

private:
    QList<Packet> packets;
    int maxPackets;
    int nextPacketNumber;

    // Statistics
    int tcpCount;
    int udpCount;
    int icmpCount;
    int nonIpCount;
    int otherCount;
    qint64 totalBytes;
    
    QString formatTimestamp(const struct timeval &ts) const;
    QColor getProtocolColor(const QString &protocol) const;
};

#endif // PACKETMODEL_H