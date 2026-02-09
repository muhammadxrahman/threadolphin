#include "MainWindow.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QMessageBox>
#include <QCheckBox>
#include <QSettings>
#include <QFileDialog>
#include <QFileInfo>
#include <QDir>
#include <QDebug>
#include <QClipboard>
#include <QMenu>
#include <QApplication>
#include <QShortcut>
#include "PacketParser.h"
#include <cstring>
// #include <iostream>
#include <sstream>
#include <iomanip>
#include <cctype>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setWindowTitle("ThreaDolphin - Packet Analyzer");
    qRegisterMetaType<struct timeval>("struct timeval");

    capture = new PacketCapture();
    captureThread = new CaptureThread(this);
    packetModel = new PacketModel(this);

    // Load saved packet limit
    QSettings settings("ThreaDolphin", "PacketAnalyzer");
    int savedLimit = settings.value("packetLimit", 10000).toInt();
    packetModel->setMaxPackets(savedLimit);

    // Create proxy model for filtering
    proxyModel = new QSortFilterProxyModel(this);
    proxyModel->setSourceModel(packetModel);
    proxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    proxyModel->setFilterKeyColumn(-1); // Filter all columns

    // Connect signals
    connect(captureThread, &CaptureThread::captureStopped,
            this, &MainWindow::onCaptureStopped);
    connect(captureThread, &CaptureThread::permissionError,
            this, &MainWindow::onPermissionError);
    connect(captureThread, &CaptureThread::packetCaptured,
            this, &MainWindow::onPacketCaptured);

    setupUI();
    setupShortcuts();
}

MainWindow::~MainWindow()
{
    delete capture;
}

void MainWindow::setupUI()
{
    // Create central widget
    QWidget *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);

    // Main layout
    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);
    mainLayout->setContentsMargins(0, 0, 0, 0);

    createToolbar();

    // Create splitter for resizable panes
    splitter = new QSplitter(Qt::Vertical, this);

    // Top pane: Packet list table
    packetTable = new QTableView(this);
    packetTable->setModel(proxyModel);
    packetTable->setAlternatingRowColors(true);
    packetTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    packetTable->setSelectionMode(QAbstractItemView::SingleSelection);
    packetTable->horizontalHeader()->setStretchLastSection(true);

    // Enable context menu
    packetTable->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(packetTable, &QTableView::customContextMenuRequested,
            this, &MainWindow::onPacketTableContextMenu);

    // Connect selection signal
    connect(packetTable->selectionModel(), &QItemSelectionModel::currentRowChanged,
            this, &MainWindow::onPacketSelected);

    // Set column widths
    packetTable->setColumnWidth(0, 60);  // No.
    packetTable->setColumnWidth(1, 100); // Time
    packetTable->setColumnWidth(2, 150); // Source
    packetTable->setColumnWidth(3, 150); // Destination
    packetTable->setColumnWidth(4, 80);  // Protocol
    packetTable->setColumnWidth(5, 80);  // Length

    splitter->addWidget(packetTable);

    // Bottom pane: Packet details
    detailView = new QTextEdit(this);
    detailView->setReadOnly(true);
    detailView->setPlaceholderText("Select a packet to view details");
    detailView->setFont(QFont("Courier", 11));
    splitter->addWidget(detailView);

    // Set initial splitter sizes (60% top, 40% bottom)
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);

    mainLayout->addWidget(splitter);

    // Status bar
    statusBar = new QStatusBar(this);
    setStatusBar(statusBar);
    statusBar->showMessage("Ready");

    // Populate network devices
    populateDevices();
}

void MainWindow::createToolbar()
{
    QToolBar *toolbar = addToolBar("Main Toolbar");
    toolbar->setMovable(false);

    // Device selection
    QLabel *deviceLabel = new QLabel(" Interface: ", this);
    toolbar->addWidget(deviceLabel);

    deviceCombo = new QComboBox(this);
    deviceCombo->setMinimumWidth(200);
    deviceCombo->addItem("Select a device...");
    deviceCombo->setEnabled(false);
    connect(deviceCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::onDeviceChanged);
    toolbar->addWidget(deviceCombo);

    toolbar->addSeparator();

    // Start button
    startButton = new QPushButton("Start Capture", this);
    startButton->setEnabled(false); // Disabled until device selected
    connect(startButton, &QPushButton::clicked, this, &MainWindow::onStartClicked);
    toolbar->addWidget(startButton);

    // Stop button
    stopButton = new QPushButton("Stop Capture", this);
    stopButton->setEnabled(false);
    connect(stopButton, &QPushButton::clicked, this, &MainWindow::onStopClicked);
    toolbar->addWidget(stopButton);

    // Clear
    QPushButton *clearButton = new QPushButton("Clear", this);
    connect(clearButton, &QPushButton::clicked, [this]()
            {
        packetModel->clear();
        detailView->clear();
        statusBar->showMessage("Cleared"); });
    toolbar->addWidget(clearButton);

    toolbar->addSeparator();

    // Add Save/Open buttons
    QPushButton *openButton = new QPushButton("Open...", this);
    connect(openButton, &QPushButton::clicked, this, &MainWindow::onOpenPcapClicked);
    toolbar->addWidget(openButton);
    
    QPushButton *saveButton = new QPushButton("Save...", this);
    connect(saveButton, &QPushButton::clicked, this, &MainWindow::onSavePcapClicked);
    toolbar->addWidget(saveButton);
    
    toolbar->addSeparator();

    // Add filter box
    QLabel *filterLabel = new QLabel(" Filter: ", this);
    toolbar->addWidget(filterLabel);

    filterEdit = new QLineEdit(this);
    filterEdit->setPlaceholderText("tcp, 192.168.1.1, port 443...");
    filterEdit->setMinimumWidth(200);
    filterEdit->setClearButtonEnabled(true); // Adds clear X button
    connect(filterEdit, &QLineEdit::textChanged, this, &MainWindow::onFilterChanged);
    toolbar->addWidget(filterEdit);

    toolbar->addSeparator();

    // Add auto-scroll checkbox
    autoScrollCheckbox = new QCheckBox("Auto-scroll", this);
    autoScrollCheckbox->setChecked(true); // Enabled by default
    toolbar->addWidget(autoScrollCheckbox);

    toolbar->addSeparator();

    // Add Settings button
    QPushButton *settingsButton = new QPushButton("Settings", this);
    connect(settingsButton, &QPushButton::clicked, this, &MainWindow::onSettingsClicked);
    toolbar->addWidget(settingsButton);

    toolbar->addSeparator();

    // Add stretch to push everything to the left
    QWidget *spacer = new QWidget();
    spacer->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    toolbar->addWidget(spacer);
}

void MainWindow::populateDevices()
{
    std::string errorMsg;
    std::vector<NetworkDevice> devices = capture->getDevices(errorMsg);

    if (!errorMsg.empty())
    {
        QMessageBox::warning(this, "Error", QString::fromStdString(errorMsg));
        return;
    }

    if (devices.empty())
    {
        statusBar->showMessage("No network devices found");
        return;
    }

    // Clear and populate combo box
    deviceCombo->clear();
    deviceCombo->addItem("Select a device...");

    for (const auto &device : devices)
    {
        QString displayText = QString::fromStdString(device.name);
        if (!device.description.empty() && device.description != "No description")
        {
            displayText += " (" + QString::fromStdString(device.description) + ")";
        }
        deviceCombo->addItem(displayText, QString::fromStdString(device.name));
    }

    deviceCombo->setEnabled(true);
    statusBar->showMessage("Found " + QString::number(devices.size()) + " network device(s)");
}

void MainWindow::onStartClicked()
{

    // Clear previous capture when starting new one
    packetModel->clear();
    detailView->clear();

    // Get selected device name from combo box data
    int index = deviceCombo->currentIndex();
    if (index <= 0)
        return;

    QString deviceName = deviceCombo->itemData(index).toString();
    std::string errorMsg;

    if (captureThread->startCapture(deviceName.toStdString(), errorMsg))
    {
        statusBar->showMessage("Capturing on " + deviceName + "...");
        startButton->setEnabled(false);
        stopButton->setEnabled(true);
        deviceCombo->setEnabled(false);
    }
    else
    {
        // Don't show error here if it's a permission error -
        // the permissionError signal will handle it
        if (errorMsg.find("permission") == std::string::npos &&
            errorMsg.find("Operation not permitted") == std::string::npos)
        {
            QMessageBox::warning(this, "Capture Error",
                                 QString::fromStdString(errorMsg));
        }
    }
}

void MainWindow::onStopClicked()
{
    captureThread->stopCapture();
    // packetModel->clear();
    // UI will be updated when captureStopped signal is received
    statusBar->showMessage("Stopping capture...");
}

void MainWindow::onDeviceChanged(int index)
{
    if (index > 0)
    {
        startButton->setEnabled(true);
        statusBar->showMessage("Device selected");
    }
    else
    {
        startButton->setEnabled(false);
        statusBar->showMessage("Ready");
    }
}

void MainWindow::onCaptureStopped(const QString &reason)
{
    int displayed = packetModel->getPacketCount();
    int total = packetModel->getTotalPacketsSeen();
    qint64 bytes = packetModel->getTotalBytes();

    QString bytesStr;
    if (bytes < 1024)
        bytesStr = QString::number(bytes) + " B";
    else if (bytes < 1024 * 1024)
        bytesStr = QString::number(bytes / 1024.0, 'f', 1) + " KB";
    else if (bytes < 1024 * 1024 * 1024)
        bytesStr = QString::number(bytes / (1024.0 * 1024.0), 'f', 1) + " MB";
    else
        bytesStr = QString::number(bytes / (1024.0 * 1024.0 * 1024.0), 'f', 2) + " GB";
    
    QString stats;
    if (displayed < total)
        stats = QString("Stopped - %1 packets captured (showing last %2)").arg(total).arg(displayed);
    else
        stats = QString("Stopped - %1 packets captured").arg(total);
    
    if (displayed > 0)
    {
        int tcp = packetModel->getTcpCount();
        int udp = packetModel->getUdpCount();
        int icmp = packetModel->getIcmpCount();
        int nonIp = packetModel->getNonIpCount();
        int other = packetModel->getOtherCount();
        
        stats += " | ";
        
        if (tcp > 0)
            stats += QString("TCP: %1% | ").arg(tcp * 100 / displayed);
        if (udp > 0)
            stats += QString("UDP: %1% | ").arg(udp * 100 / displayed);
        if (icmp > 0)
            stats += QString("ICMP: %1% | ").arg(icmp * 100 / displayed);
        if (nonIp > 0)
            stats += QString("Non-IP: %1% | ").arg(nonIp * 100 / displayed);
        if (other > 0)
            stats += QString("Other: %1% | ").arg(other * 100 / displayed);
        
        stats += bytesStr;
    }
    
    statusBar->showMessage(stats);
    startButton->setEnabled(true);
    stopButton->setEnabled(false);
    deviceCombo->setEnabled(true);
}

void MainWindow::onPermissionError(const QString &deviceName)
{
    QString message = "Permission denied to capture on " + deviceName + ".\n\n";

#ifdef __APPLE__
    message += "On macOS, you need to run ThreaDolphin with administrator privileges:\n\n";
    message += "1. Close this application\n";
    message += "2. Open Terminal\n";
    message += "3. Run: sudo ./ThreaDolphin\n";
    message += "4. Enter your password when prompted\n\n";
    message += "Alternatively, you can grant capture permissions to your user account.";
#elif _WIN32
    message += "On Windows, you need to run ThreaDolphin as Administrator:\n\n";
    message += "1. Close this application\n";
    message += "2. Right-click on ThreaDolphin\n";
    message += "3. Select 'Run as Administrator'\n";
#else
    message += "You may need to run this application with elevated privileges (sudo).";
#endif

    QMessageBox::critical(this, "Permission Error", message);

    // Reset UI
    startButton->setEnabled(true);
    stopButton->setEnabled(false);
    deviceCombo->setEnabled(true);
}

void MainWindow::onPacketCaptured(const u_char *data, int length, const struct timeval &timestamp)
{
    // static int count = 0;
    // if (++count <= 5)
    // {
    //     std::cout << "MainWindow::onPacketCaptured called! Packet #" << count << std::endl;
    // }

    // Create a packet and store raw data
    Packet packet;
    packet.number = 0; // Will be assigned by model
    packet.timestamp = timestamp;
    packet.length = length;

    // Copy raw packet data
    packet.rawData.resize(length);
    std::memcpy(packet.rawData.data(), data, length);

    // Clean up the copy made by CaptureThread
    delete[] data;

    // Parse the packet to extract IP, ports, protocol, etc.
    PacketParser::parsePacket(packet);

    // Add to model
    packetModel->addPacket(packet);

    // Auto-scroll to newest packet if enabled
    if (autoScrollCheckbox->isChecked())
    {
        packetTable->scrollToBottom();
    }

    // Update status bar with statistics
    int displayed = packetModel->getPacketCount();
    int total = packetModel->getTotalPacketsSeen();
    qint64 bytes = packetModel->getTotalBytes();

    QString bytesStr;
    if (bytes < 1024)
        bytesStr = QString::number(bytes) + " B";
    else if (bytes < 1024 * 1024)
        bytesStr = QString::number(bytes / 1024.0, 'f', 1) + " KB";
    else if (bytes < 1024 * 1024 * 1024)
        bytesStr = QString::number(bytes / (1024.0 * 1024.0), 'f', 1) + " MB";
    else
        bytesStr = QString::number(bytes / (1024.0 * 1024.0 * 1024.0), 'f', 2) + " GB";

    QString stats;
    if (displayed < total)
        stats = QString("Capturing... %1 packets (showing last %2)").arg(total).arg(displayed);
    else
        stats = QString("Capturing... %1 packets").arg(total);

    if (total > 0)
    {
        int tcp = packetModel->getTcpCount();
        int udp = packetModel->getUdpCount();
        int icmp = packetModel->getIcmpCount();
        int nonIp = packetModel->getNonIpCount();
        int other = packetModel->getOtherCount();

        stats += " | ";

        if (tcp > 0)
            stats += QString("TCP: %1% | ").arg(tcp * 100 / displayed);
        if (udp > 0)
            stats += QString("UDP: %1% | ").arg(udp * 100 / displayed);
        if (icmp > 0)
            stats += QString("ICMP: %1% | ").arg(icmp * 100 / displayed);
        if (nonIp > 0)
            stats += QString("Non-IP: %1% | ").arg(nonIp * 100 / displayed);
        if (other > 0)
            stats += QString("Other: %1% | ").arg(other * 100 / displayed);

        stats += bytesStr;
    }

    statusBar->showMessage(stats);
}

void MainWindow::onPacketSelected(const QModelIndex &index)
{
    if (!index.isValid())
    {
        detailView->clear();
        return;
    }

    // Map proxy index to source model index
    QModelIndex sourceIndex = proxyModel->mapToSource(index);
    const Packet *packet = packetModel->getPacket(sourceIndex.row());

    if (!packet)
    {
        detailView->clear();
        return;
    }

    // Build detailed packet information
    std::ostringstream details;

    details << "═══════════════════════════════════════════════════════════════\n";
    details << "Packet #" << packet->number << " - " << packet->length << " bytes\n";
    details << "═══════════════════════════════════════════════════════════════\n\n";

    // Ethernet Layer
    if (packet->rawData.size() >= 14)
    {
        const u_char *data = packet->rawData.data();
        const u_char *srcMac = data + 6;
        const u_char *dstMac = data;
        u_short etherType = ntohs(*(u_short *)(data + 12));

        details << "┌─ ETHERNET II\n";
        details << "│  Source MAC:      ";
        for (int i = 0; i < 6; i++)
        {
            details << std::hex << std::setfill('0') << std::setw(2)
                    << (int)srcMac[i] << std::dec;
            if (i < 5)
                details << ":";
        }
        details << "\n│  Destination MAC: ";
        for (int i = 0; i < 6; i++)
        {
            details << std::hex << std::setfill('0') << std::setw(2)
                    << (int)dstMac[i] << std::dec;
            if (i < 5)
                details << ":";
        }
        details << "\n│  Type:            0x" << std::hex << std::setw(4)
                << std::setfill('0') << etherType << std::dec;

        if (etherType == 0x0800)
            details << " (IPv4)";
        else if (etherType == 0x0806)
            details << " (ARP)";
        else if (etherType == 0x86DD)
            details << " (IPv6)";

        details << "\n└─\n\n";
    }

    // IP Layer
    if (!packet->srcIP.empty() && !packet->dstIP.empty())
    {
        details << "┌─ INTERNET PROTOCOL (IP)\n";
        details << "│  Source IP:       " << packet->srcIP << "\n";
        details << "│  Destination IP:  " << packet->dstIP << "\n";
        details << "│  Protocol:        " << packet->protocol << "\n";
        details << "└─\n\n";
    }

    // Transport Layer (TCP/UDP)
    if (!packet->srcPort.empty() && !packet->dstPort.empty())
    {
        if (packet->protocol == "TCP")
        {
            details << "┌─ TRANSMISSION CONTROL PROTOCOL (TCP)\n";
            details << "│  Source Port:     " << packet->srcPort << "\n";
            details << "│  Dest Port:       " << packet->dstPort << "\n";
            details << "│  Info:            " << packet->info << "\n";
            details << "└─\n\n";
        }
        else if (packet->protocol == "UDP")
        {
            details << "┌─ USER DATAGRAM PROTOCOL (UDP)\n";
            details << "│  Source Port:     " << packet->srcPort << "\n";
            details << "│  Dest Port:       " << packet->dstPort << "\n";
            details << "│  Info:            " << packet->info << "\n";
            details << "└─\n\n";
        }
    }

    // Payload (hex dump)
    details << "┌─ PAYLOAD\n";

    // Calculate payload start
    int payloadStart = 14; // Ethernet

    if (packet->rawData.size() > 14 && !packet->srcIP.empty())
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
        else if (packet->protocol == "UDP")
        {
            payloadStart += 8; // UDP header is always 8 bytes
        }
    }

    int payloadLen = packet->length - payloadStart;

    if (payloadLen > 0 && payloadStart < packet->rawData.size())
    {
        const u_char *payload = packet->rawData.data() + payloadStart;
        int displayLen = std::min(payloadLen, 256); // Show first 256 bytes

        details << "│  Length: " << payloadLen << " bytes";
        if (payloadLen > 256)
            details << " (showing first 256)";
        details << "\n│\n";

        // Hex dump with ASCII
        for (int i = 0; i < displayLen; i += 16)
        {
            details << "│  " << std::hex << std::setw(4) << std::setfill('0') << i << "  ";

            // Hex bytes
            for (int j = 0; j < 16; j++)
            {
                if (i + j < displayLen)
                {
                    details << std::hex << std::setw(2) << std::setfill('0')
                            << (int)payload[i + j] << " ";
                }
                else
                {
                    details << "   ";
                }

                if (j == 7)
                    details << " ";
            }

            details << " │ ";

            // ASCII representation
            for (int j = 0; j < 16 && (i + j) < displayLen; j++)
            {
                char c = payload[i + j];
                details << (isprint(c) ? c : '.');
            }

            details << std::dec << "\n";
        }

        if (payloadLen > 256)
        {
            details << "│  ... (" << (payloadLen - 256) << " more bytes)\n";
        }
    }
    else
    {
        details << "│  No payload data\n";
    }

    details << "└─\n";

    // Set the text
    detailView->setPlainText(QString::fromStdString(details.str()));
}

void MainWindow::onFilterChanged(const QString &text)
{
    proxyModel->setFilterFixedString(text);

    // Update status to show filtered count
    if (text.isEmpty())
    {
        statusBar->showMessage(QString("Showing all %1 packets").arg(packetModel->getPacketCount()));
    }
    else
    {
        int visibleCount = proxyModel->rowCount();
        int totalCount = packetModel->getPacketCount();
        statusBar->showMessage(QString("Showing %1 of %2 packets (filtered by: %3)")
                                   .arg(visibleCount)
                                   .arg(totalCount)
                                   .arg(text));
    }
}

void MainWindow::onSettingsClicked()
{
    SettingsDialog dialog(this);

    // Load current setting
    QSettings settings("ThreaDolphin", "PacketAnalyzer");
    int currentLimit = settings.value("packetLimit", 10000).toInt();
    dialog.setPacketLimit(currentLimit);

    if (dialog.exec() == QDialog::Accepted)
    {
        int newLimit = dialog.getPacketLimit();

        // Save setting
        settings.setValue("packetLimit", newLimit);

        // Update model
        packetModel->setMaxPackets(newLimit < 0 ? 1000000 : newLimit);

        // Show confirmation
        if (newLimit < 0)
            statusBar->showMessage("Packet limit set to unlimited");
        else
            statusBar->showMessage(QString("Packet limit set to %1").arg(newLimit));
    }
}

void MainWindow::onSavePcapClicked()
{
    if (packetModel->getPacketCount() == 0)
    {
        QMessageBox::information(this, "No Packets", "There are no packets to save.");
        return;
    }
    
    QString filename = QFileDialog::getSaveFileName(
        this,
        "Save Packet Capture",
        QDir::homePath() + "/capture.pcap",
        "PCAP Files (*.pcap);;All Files (*)"
    );
    
    if (filename.isEmpty())
        return;
    
    if (!filename.endsWith(".pcap", Qt::CaseInsensitive))
        filename += ".pcap";
    
    if (savePcapFile(filename))
    {
        statusBar->showMessage(QString("Saved %1 packets to %2")
                              .arg(packetModel->getPacketCount())
                              .arg(QFileInfo(filename).fileName()));
    }
    else
    {
        QMessageBox::critical(this, "Save Failed", 
                            "Failed to save PCAP file. Check permissions.");
    }
}

void MainWindow::onOpenPcapClicked()
{
    QString filename = QFileDialog::getOpenFileName(
        this,
        "Open Packet Capture",
        QDir::homePath(),
        "PCAP Files (*.pcap *.cap *.pcapng);;All Files (*)"
    );
    
    if (filename.isEmpty())
        return;
    
    // Clear existing packets
    packetModel->clear();
    detailView->clear();
    
    if (loadPcapFile(filename))
    {
        statusBar->showMessage(QString("Loaded %1 packets from %2")
                              .arg(packetModel->getPacketCount())
                              .arg(QFileInfo(filename).fileName()));
    }
    else
    {
        QMessageBox::critical(this, "Open Failed", 
                            "Failed to open PCAP file. File may be corrupted or in an unsupported format.");
    }
}

bool MainWindow::savePcapFile(const QString &filename)
{
    // Open a dummy pcap handle for writing (we need this for pcap_dump_open)
    pcap_t *dummy = pcap_open_dead(DLT_EN10MB, 65535);
    if (!dummy)
        return false;
    
    pcap_dumper_t *dumper = pcap_dump_open(dummy, filename.toStdString().c_str());
    if (!dumper)
    {
        pcap_close(dummy);
        return false;
    }
    
    // Write each packet
    for (int i = 0; i < packetModel->getPacketCount(); i++)
    {
        const Packet *packet = packetModel->getPacket(i);
        if (!packet)
            continue;
        
        // Create pcap packet header
        struct pcap_pkthdr header;
        header.ts = packet->timestamp;
        header.caplen = packet->length;
        header.len = packet->length;
        
        // Write packet
        pcap_dump((u_char *)dumper, &header, packet->rawData.data());
    }
    
    pcap_dump_close(dumper);
    pcap_close(dummy);
    
    return true;
}

bool MainWindow::loadPcapFile(const QString &filename)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    
    pcap_t *handle = pcap_open_offline(filename.toStdString().c_str(), errbuf);
    if (!handle)
    {
        qDebug() << "Error opening file:" << errbuf;
        return false;
    }
    
    struct pcap_pkthdr *header;
    const u_char *data;
    int result;
    
    // Read packets one by one
    while ((result = pcap_next_ex(handle, &header, &data)) >= 0)
    {
        if (result == 0)
            continue; // Timeout
        
        // Create packet
        Packet packet;
        packet.number = 0; // Will be assigned by model
        packet.timestamp = header->ts;
        packet.length = header->caplen;
        
        // Copy packet data
        packet.rawData.resize(header->caplen);
        std::memcpy(packet.rawData.data(), data, header->caplen);
        
        // Parse packet
        PacketParser::parsePacket(packet);
        
        // Add to model
        packetModel->addPacket(packet);
    }
    
    pcap_close(handle);
    
    return packetModel->getPacketCount() > 0;
}

void MainWindow::onPacketTableContextMenu(const QPoint &pos)
{
    QModelIndex index = packetTable->indexAt(pos);
    if (!index.isValid())
        return;
    
    // Map to source model
    QModelIndex sourceIndex = proxyModel->mapToSource(index);
    const Packet *packet = packetModel->getPacket(sourceIndex.row());
    
    if (!packet)
        return;
    
    QMenu menu(this);
    
    QAction *copySummary = menu.addAction("Copy Summary");
    QAction *copyDetails = menu.addAction("Copy Details");
    QAction *copyHex = menu.addAction("Copy as Hex");
    QAction *copyInfo = menu.addAction("Copy Info");
    
    QAction *selected = menu.exec(packetTable->viewport()->mapToGlobal(pos));
    
    if (!selected)
        return;
    
    QClipboard *clipboard = QApplication::clipboard();
    
    if (selected == copySummary)
    {
        clipboard->setText(getPacketSummary(packet));
        statusBar->showMessage("Copied packet summary to clipboard");
    }
    else if (selected == copyDetails)
    {
        clipboard->setText(getPacketDetails(packet));
        statusBar->showMessage("Copied packet details to clipboard");
    }
    else if (selected == copyHex)
    {
        clipboard->setText(getPacketHex(packet));
        statusBar->showMessage("Copied hex dump to clipboard");
    }
    else if (selected == copyInfo)
    {
        clipboard->setText(QString::fromStdString(packet->info));
        statusBar->showMessage("Copied packet info to clipboard");
    }
}

QString MainWindow::getPacketSummary(const Packet *packet) const
{
    QString summary;
    summary += QString("Packet #%1\n").arg(packet->number);
    summary += QString("Time: %1.%2\n")
              .arg(packet->timestamp.tv_sec)
              .arg(packet->timestamp.tv_usec, 6, 10, QChar('0'));
    summary += QString("Length: %1 bytes\n").arg(packet->length);
    summary += QString("Protocol: %1\n").arg(QString::fromStdString(packet->protocol));
    
    if (!packet->srcIP.empty() && !packet->dstIP.empty())
    {
        summary += QString("Source: %1").arg(QString::fromStdString(packet->srcIP));
        if (!packet->srcPort.empty())
            summary += QString(":%1").arg(QString::fromStdString(packet->srcPort));
        summary += "\n";
        
        summary += QString("Destination: %1").arg(QString::fromStdString(packet->dstIP));
        if (!packet->dstPort.empty())
            summary += QString(":%1").arg(QString::fromStdString(packet->dstPort));
        summary += "\n";
    }
    
    if (!packet->info.empty())
        summary += QString("Info: %1\n").arg(QString::fromStdString(packet->info));
    
    return summary;
}

QString MainWindow::getPacketDetails(const Packet *packet) const
{
    // This is the same content shown in the detail view
    std::ostringstream details;
    
    details << "═══════════════════════════════════════════════════════════════\n";
    details << "Packet #" << packet->number << " - " << packet->length << " bytes\n";
    details << "═══════════════════════════════════════════════════════════════\n\n";
    
    // Ethernet Layer
    if (packet->rawData.size() >= 14)
    {
        const u_char *data = packet->rawData.data();
        const u_char *srcMac = data + 6;
        const u_char *dstMac = data;
        u_short etherType = ntohs(*(u_short*)(data + 12));
        
        details << "┌─ ETHERNET II\n";
        details << "│  Source MAC:      ";
        for (int i = 0; i < 6; i++)
        {
            details << std::hex << std::setfill('0') << std::setw(2) 
                   << (int)srcMac[i] << std::dec;
            if (i < 5) details << ":";
        }
        details << "\n│  Destination MAC: ";
        for (int i = 0; i < 6; i++)
        {
            details << std::hex << std::setfill('0') << std::setw(2) 
                   << (int)dstMac[i] << std::dec;
            if (i < 5) details << ":";
        }
        details << "\n│  Type:            0x" << std::hex << std::setw(4) 
               << std::setfill('0') << etherType << std::dec;
        
        if (etherType == 0x0800)
            details << " (IPv4)";
        else if (etherType == 0x0806)
            details << " (ARP)";
        else if (etherType == 0x86DD)
            details << " (IPv6)";
        
        details << "\n└─\n\n";
    }
    
    // IP Layer
    if (!packet->srcIP.empty() && !packet->dstIP.empty())
    {
        details << "┌─ INTERNET PROTOCOL (IP)\n";
        details << "│  Source IP:       " << packet->srcIP << "\n";
        details << "│  Destination IP:  " << packet->dstIP << "\n";
        details << "│  Protocol:        " << packet->protocol << "\n";
        details << "└─\n\n";
    }
    
    // Transport Layer
    if (!packet->srcPort.empty() && !packet->dstPort.empty())
    {
        if (packet->protocol == "TCP")
        {
            details << "┌─ TRANSMISSION CONTROL PROTOCOL (TCP)\n";
            details << "│  Source Port:     " << packet->srcPort << "\n";
            details << "│  Dest Port:       " << packet->dstPort << "\n";
            details << "│  Info:            " << packet->info << "\n";
            details << "└─\n\n";
        }
        else if (packet->protocol == "UDP")
        {
            details << "┌─ USER DATAGRAM PROTOCOL (UDP)\n";
            details << "│  Source Port:     " << packet->srcPort << "\n";
            details << "│  Dest Port:       " << packet->dstPort << "\n";
            details << "│  Info:            " << packet->info << "\n";
            details << "└─\n\n";
        }
    }
    
    return QString::fromStdString(details.str());
}

QString MainWindow::getPacketHex(const Packet *packet) const
{
    QString hex;
    const u_char *data = packet->rawData.data();
    int length = packet->rawData.size();
    
    for (int i = 0; i < length; i += 16)
    {
        // Offset
        hex += QString("%1  ").arg(i, 4, 16, QChar('0'));
        
        // Hex bytes
        for (int j = 0; j < 16; j++)
        {
            if (i + j < length)
            {
                hex += QString("%1 ").arg(data[i + j], 2, 16, QChar('0'));
            }
            else
            {
                hex += "   ";
            }
            
            if (j == 7) hex += " ";
        }
        
        hex += " | ";
        
        // ASCII representation
        for (int j = 0; j < 16 && (i + j) < length; j++)
        {
            char c = data[i + j];
            hex += (isprint(c) ? c : '.');
        }
        
        hex += "\n";
    }
    
    return hex;
}

void MainWindow::setupShortcuts()
{
    // Start/Stop capture (toggle)
    QShortcut *startStopShortcut2 = new QShortcut(QKeySequence("Ctrl+R"), this);
    connect(startStopShortcut2, &QShortcut::activated, [this]() {
        if (captureThread->isCapturing())
            onStopClicked();
        else if (startButton->isEnabled())
            onStartClicked();
    });
    
    // Clear packets
    QShortcut *clearShortcut = new QShortcut(QKeySequence("Ctrl+K"), this);
    connect(clearShortcut, &QShortcut::activated, [this]() {
        packetModel->clear();
        detailView->clear();
        statusBar->showMessage("Cleared");
    });
    
    // Focus filter box
    QShortcut *filterShortcut = new QShortcut(QKeySequence("Ctrl+F"), this);
    connect(filterShortcut, &QShortcut::activated, [this]() {
        filterEdit->setFocus();
        filterEdit->selectAll();
    });
    
    // Open PCAP file
    QShortcut *openShortcut = new QShortcut(QKeySequence::Open, this);  // Ctrl+O
    connect(openShortcut, &QShortcut::activated, this, &MainWindow::onOpenPcapClicked);
    
    // Save PCAP file - Use Ctrl+E (E for Export)
    QShortcut *saveShortcut = new QShortcut(QKeySequence("Ctrl+E"), this);
    connect(saveShortcut, &QShortcut::activated, this, &MainWindow::onSavePcapClicked);
    
    // Settings
    QShortcut *settingsShortcut = new QShortcut(QKeySequence("Ctrl+,"), this);
    connect(settingsShortcut, &QShortcut::activated, this, &MainWindow::onSettingsClicked);
    
    // Copy selected packet
    QShortcut *copyShortcut = new QShortcut(QKeySequence::Copy, this);  // Ctrl+C
    connect(copyShortcut, &QShortcut::activated, [this]() {
        QModelIndex currentIndex = packetTable->currentIndex();
        if (!currentIndex.isValid())
            return;
        
        QModelIndex sourceIndex = proxyModel->mapToSource(currentIndex);
        const Packet *packet = packetModel->getPacket(sourceIndex.row());
        
        if (packet)
        {
            QClipboard *clipboard = QApplication::clipboard();
            clipboard->setText(getPacketSummary(packet));
            statusBar->showMessage("Copied packet summary to clipboard");
        }
    });
}