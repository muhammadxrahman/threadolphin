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
#include "PacketCapture.h"
#include "CaptureThread.h"
#include "PacketModel.h"
#include "Packet.h"

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

private:
    void setupUI();
    void createToolbar();
    void populateDevices();
    // Packet capture
    PacketCapture *capture;
    CaptureThread *captureThread;
    PacketModel *packetModel;

    // UI Components
    QTableView *packetTable;
    QTextEdit *detailView;
    QComboBox *deviceCombo;
    QPushButton *startButton;
    QPushButton *stopButton;
    QStatusBar *statusBar;
    QSplitter *splitter;
};

#endif // MAINWINDOW_H