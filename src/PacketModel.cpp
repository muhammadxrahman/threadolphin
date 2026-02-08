#include "PacketModel.h"
#include <QDateTime>

PacketModel::PacketModel(QObject *parent)
    : QAbstractTableModel(parent), maxPackets(10000), nextPacketNumber(1),
      tcpCount(0), udpCount(0), icmpCount(0), nonIpCount(0), otherCount(0), totalBytes(0)
{
}

int PacketModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid())
        return 0;

    return packets.size(); // Remove mutex - Qt handles this
}

int PacketModel::columnCount(const QModelIndex &parent) const
{
    if (parent.isValid())
        return 0;

    return 7;
}

QVariant PacketModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid())
        return QVariant();

    if (index.row() >= packets.size()) // Remove mutex
        return QVariant();

    const Packet &packet = packets[index.row()];

    // Handle background color
    if (role == Qt::BackgroundRole)
    {
        return getProtocolColor(QString::fromStdString(packet.protocol));
    }

    // Handle display text
    if (role != Qt::DisplayRole)
        return QVariant();

    switch (index.column())
    {
    case 0: // Number
        return packet.number;
    case 1: // Time
        return formatTimestamp(packet.timestamp);
    case 2: // Source
        if (!packet.srcIP.empty())
        {
            if (!packet.srcPort.empty())
                return QString::fromStdString(packet.srcIP + ":" + packet.srcPort);
            return QString::fromStdString(packet.srcIP);
        }
        return "N/A";
    case 3: // Destination
        if (!packet.dstIP.empty())
        {
            if (!packet.dstPort.empty())
                return QString::fromStdString(packet.dstIP + ":" + packet.dstPort);
            return QString::fromStdString(packet.dstIP);
        }
        return "N/A";
    case 4: // Protocol
        return QString::fromStdString(packet.protocol.empty() ? "Unknown" : packet.protocol);
    case 5: // Length
        return packet.length;
    case 6: // Info
        return QString::fromStdString(packet.info);
    default:
        return QVariant();
    }
}

QVariant PacketModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role != Qt::DisplayRole || orientation != Qt::Horizontal)
        return QVariant();

    switch (section)
    {
    case 0:
        return "No.";
    case 1:
        return "Time";
    case 2:
        return "Source";
    case 3:
        return "Destination";
    case 4:
        return "Protocol";
    case 5:
        return "Length";
    case 6:
        return "Info";
    default:
        return QVariant();
    }
}

void PacketModel::addPacket(const Packet &packet)
{

    // Check if we've hit the limit (only if maxPackets > 0)
    if (maxPackets > 0 && packets.size() >= maxPackets)
    {
        // Update statistics for removed packet
        const Packet &oldPacket = packets.first();
        QString oldProtocol = QString::fromStdString(oldPacket.protocol);
        
        if (oldProtocol == "TCP") tcpCount--;
        else if (oldProtocol == "UDP") udpCount--;
        else if (oldProtocol == "ICMP") icmpCount--;
        else if (oldProtocol == "Non-IP") nonIpCount--;
        else otherCount--;
        
        totalBytes -= oldPacket.length;
        
        beginRemoveRows(QModelIndex(), 0, 0);
        packets.removeFirst();
        endRemoveRows();
    }

    // Update statistics for new packet
    QString protocol = QString::fromStdString(packet.protocol);

    if (protocol == "TCP")
        tcpCount++;
    else if (protocol == "UDP")
        udpCount++;
    else if (protocol == "ICMP")
        icmpCount++;
    else if (protocol == "Non-IP")
        nonIpCount++;
    else
        otherCount++;

    totalBytes += packet.length;

    // Add new packet
    int row = packets.size();
    beginInsertRows(QModelIndex(), row, row);
    packets.append(packet);
    endInsertRows();
}

void PacketModel::clear()
{
    if (packets.isEmpty())
        return;

    beginResetModel();
    packets.clear();
    nextPacketNumber = 1;

    // Reset statistics
    tcpCount = 0;
    udpCount = 0;
    icmpCount = 0;
    nonIpCount = 0;
    otherCount = 0;
    totalBytes = 0;

    endResetModel();
}

const Packet *PacketModel::getPacket(int row) const
{
    if (row < 0 || row >= packets.size())
        return nullptr;

    return &packets[row];
}

int PacketModel::getPacketCount() const
{
    return packets.size();
}

void PacketModel::setMaxPackets(int max)
{
    maxPackets = max;
}

QString PacketModel::formatTimestamp(const struct timeval &ts) const
{
    QDateTime dateTime = QDateTime::fromSecsSinceEpoch(ts.tv_sec);
    int microseconds = ts.tv_usec;

    return dateTime.toString("hh:mm:ss") +
           QString(".%1").arg(microseconds / 1000, 3, 10, QChar('0'));
}

QColor PacketModel::getProtocolColor(const QString &protocol) const
{
    if (protocol == "TCP")
        return QColor(25, 35, 60); // Dark blue
    else if (protocol == "UDP")
        return QColor(25, 50, 35); // Dark green
    else if (protocol == "ICMP")
        return QColor(60, 50, 25); // Dark yellow/gold
    else if (protocol == "Non-IP")
        return QColor(45, 45, 45); // Dark gray
    else if (protocol.startsWith("Other"))
        return QColor(55, 35, 45); // Dark purple
    else
        return QColor(30, 30, 30); // Dark default
}

int PacketModel::getTcpCount() const
{
    return tcpCount;
}

int PacketModel::getUdpCount() const
{
    return udpCount;
}

int PacketModel::getIcmpCount() const
{
    return icmpCount;
}

int PacketModel::getNonIpCount() const
{
    return nonIpCount;
}

int PacketModel::getOtherCount() const
{
    return otherCount;
}

qint64 PacketModel::getTotalBytes() const
{
    return totalBytes;
}