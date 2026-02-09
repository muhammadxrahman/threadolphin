#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTableView>
#include <QTextEdit>
#include <QComboBox>
#include <QPushButton>
#include <QStatusBar>
#include <QToolBar>
#include <QSplitter>
#include <QCheckBox>
#include <QLineEdit>
#include <QSortFilterProxyModel>
#include "PacketCapture.h"
#include "CaptureThread.h"
#include "PacketModel.h"
#include "Packet.h"
#include "SettingsDialog.h"
#include "StreamWindow.h"
#include "StreamIdentifier.h"

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onStartClicked();
    void onStopClicked();
    void onDeviceChanged(int index);
    void onCaptureStopped(const QString &reason);     
    void onPermissionError(const QString &deviceName);
    void onPacketCaptured(const u_char *data, int length, const struct timeval &timestamp);
    void onPacketSelected(const QModelIndex &index);
    void onFilterChanged(const QString &text);
    void onSettingsClicked();
    void onSavePcapClicked();  
    void onOpenPcapClicked();
    void onPacketTableContextMenu(const QPoint &pos);

private:
    void setupUI();
    void createToolbar();
    void populateDevices();
    void setupShortcuts();
    bool savePcapFile(const QString &filename);   
    bool loadPcapFile(const QString &filename);

    // Helper methods for copying
    QString getPacketSummary(const Packet *packet) const;  
    QString getPacketDetails(const Packet *packet) const;  
    QString getPacketHex(const Packet *packet) const;

    // Packet capture
    PacketCapture *capture;
    CaptureThread *captureThread;
    PacketModel *packetModel;
    QSortFilterProxyModel *proxyModel;

    // UI Components
    QTableView *packetTable;
    QTextEdit *detailView;
    QComboBox *deviceCombo;
    QPushButton *startButton;
    QPushButton *stopButton;
    QStatusBar *statusBar;
    QSplitter *splitter;
    QCheckBox *autoScrollCheckbox;
    QLineEdit *filterEdit;
};

#endif // MAINWINDOW_H