#include "SettingsDialog.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QGroupBox>
#include <QDialogButtonBox>

SettingsDialog::SettingsDialog(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle("Settings");
    setModal(true);
    
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    
    // Packet limit group
    QGroupBox *limitGroup = new QGroupBox("Packet Capture Limit", this);
    QVBoxLayout *limitLayout = new QVBoxLayout(limitGroup);
    
    QLabel *descLabel = new QLabel("Maximum number of packets to keep in memory:", this);
    limitLayout->addWidget(descLabel);
    
    QHBoxLayout *spinLayout = new QHBoxLayout();
    packetLimitSpinBox = new QSpinBox(this);
    packetLimitSpinBox->setMinimum(100);
    packetLimitSpinBox->setMaximum(1000000);
    packetLimitSpinBox->setSingleStep(1000);
    packetLimitSpinBox->setValue(10000);
    packetLimitSpinBox->setSuffix(" packets");
    spinLayout->addWidget(packetLimitSpinBox);
    spinLayout->addStretch();
    limitLayout->addLayout(spinLayout);
    
    unlimitedCheckBox = new QCheckBox("Unlimited (may use lots of memory)", this);
    connect(unlimitedCheckBox, &QCheckBox::toggled, this, &SettingsDialog::onUnlimitedToggled);
    limitLayout->addWidget(unlimitedCheckBox);
    
    QLabel *presetLabel = new QLabel("Presets:", this);
    limitLayout->addWidget(presetLabel);
    
    QHBoxLayout *presetsLayout = new QHBoxLayout();
    QPushButton *preset1k = new QPushButton("1,000", this);
    QPushButton *preset5k = new QPushButton("5,000", this);
    QPushButton *preset10k = new QPushButton("10,000", this);
    QPushButton *preset50k = new QPushButton("50,000", this);
    QPushButton *preset100k = new QPushButton("100,000", this);
    
    connect(preset1k, &QPushButton::clicked, [this]() { 
        unlimitedCheckBox->setChecked(false);
        packetLimitSpinBox->setValue(1000); 
    });
    connect(preset5k, &QPushButton::clicked, [this]() { 
        unlimitedCheckBox->setChecked(false);
        packetLimitSpinBox->setValue(5000); 
    });
    connect(preset10k, &QPushButton::clicked, [this]() { 
        unlimitedCheckBox->setChecked(false);
        packetLimitSpinBox->setValue(10000); 
    });
    connect(preset50k, &QPushButton::clicked, [this]() { 
        unlimitedCheckBox->setChecked(false);
        packetLimitSpinBox->setValue(50000); 
    });
    connect(preset100k, &QPushButton::clicked, [this]() { 
        unlimitedCheckBox->setChecked(false);
        packetLimitSpinBox->setValue(100000); 
    });
    
    presetsLayout->addWidget(preset1k);
    presetsLayout->addWidget(preset5k);
    presetsLayout->addWidget(preset10k);
    presetsLayout->addWidget(preset50k);
    presetsLayout->addWidget(preset100k);
    presetsLayout->addStretch();
    limitLayout->addLayout(presetsLayout);
    
    mainLayout->addWidget(limitGroup);
    
    // Dialog buttons
    QDialogButtonBox *buttonBox = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    connect(buttonBox, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);
    mainLayout->addWidget(buttonBox);
    
    resize(400, 250);
}

int SettingsDialog::getPacketLimit() const
{
    if (unlimitedCheckBox->isChecked())
        return -1; // -1 means unlimited
    return packetLimitSpinBox->value();
}

void SettingsDialog::setPacketLimit(int limit)
{
    if (limit < 0)
    {
        unlimitedCheckBox->setChecked(true);
        packetLimitSpinBox->setEnabled(false);
    }
    else
    {
        unlimitedCheckBox->setChecked(false);
        packetLimitSpinBox->setValue(limit);
        packetLimitSpinBox->setEnabled(true);
    }
}

void SettingsDialog::onUnlimitedToggled(bool checked)
{
    packetLimitSpinBox->setEnabled(!checked);
}