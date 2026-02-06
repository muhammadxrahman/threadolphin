#include "MainWindow.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setWindowTitle("ThreaDolphin - Packet Analyzer");
    setupUI();
}

MainWindow::~MainWindow()
{
}

void MainWindow::setupUI()
{
    // Create central widget
    QWidget *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);
    
    // Main layout
    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    
    // Create toolbar
    createToolbar();
    
    // Create splitter for resizable panes
    splitter = new QSplitter(Qt::Vertical, this);
    
    // Top pane: Packet list table
    packetTable = new QTableView(this);
    packetTable->setAlternatingRowColors(true);
    packetTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    packetTable->setSelectionMode(QAbstractItemView::SingleSelection);
    packetTable->horizontalHeader()->setStretchLastSection(true);
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
    
    toolbar->addSeparator();
    
    // Add stretch to push everything to the left
    QWidget* spacer = new QWidget();
    spacer->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    toolbar->addWidget(spacer);
}

void MainWindow::onStartClicked()
{
    // Placeholder for now
    statusBar->showMessage("Starting capture...");
    startButton->setEnabled(false);
    stopButton->setEnabled(true);
    deviceCombo->setEnabled(false);
}

void MainWindow::onStopClicked()
{
    // Placeholder for now
    statusBar->showMessage("Stopped");
    startButton->setEnabled(true);
    stopButton->setEnabled(false);
    deviceCombo->setEnabled(true);
}

void MainWindow::onDeviceChanged(int index)
{
    // Placeholder for now
    if (index > 0) {
        startButton->setEnabled(true);
        statusBar->showMessage("Device selected");
    } else {
        startButton->setEnabled(false);
        statusBar->showMessage("Ready");
    }
}