#ifndef SETTINGSDIALOG_H
#define SETTINGSDIALOG_H

#include <QDialog>
#include <QSpinBox>
#include <QCheckBox>

class SettingsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SettingsDialog(QWidget *parent = nullptr);
    
    int getPacketLimit() const;
    void setPacketLimit(int limit);

private:
    QSpinBox *packetLimitSpinBox;
    QCheckBox *unlimitedCheckBox;
    
    void onUnlimitedToggled(bool checked);
};

#endif // SETTINGSDIALOG_H