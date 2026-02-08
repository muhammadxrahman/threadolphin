#include "PacketModel.h"
#include <QDateTime>

PacketModel::PacketModel(QObject *parent)
    : QAbstractTableModel(parent), maxPackets(10000), nextPacketNumber(1)
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
    // No mutex needed - this is called on main thread via queued connection

    // Check if we've hit the limit
    if (packets.size() >= maxPackets)
    {
        beginRemoveRows(QModelIndex(), 0, 0);
        packets.removeFirst();
        endRemoveRows();
    }

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