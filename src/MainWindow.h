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

private:
    void setupUI();
    void createToolbar();

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