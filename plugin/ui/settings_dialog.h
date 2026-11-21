/* settings_dialog.h
 *
 * Choose the LLM provider, server address, model and API key.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QDialog>

#include "core/settings.h"

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QSpinBox;

namespace smartshark {

class HttpBackend;

class SettingsDialog : public QDialog {
    Q_OBJECT
public:
    explicit SettingsDialog(QWidget *parent = nullptr);

    // Load from and save to the settings file and Credential Manager.
    void load();
    bool save();

private slots:
    void onProviderChanged(int index);
    void onFetchModels();
    void onAccepted();

private:
    QString currentProviderId() const;
    QString validateForm() const; // empty if the form is usable
    // False if the user declined to send a saved key to a server other than
    // the one it was saved for. Records the server on success.
    bool confirmKeyHost(const QString &providerId, const QString &baseUrl, const QString &key);
    void storeFormIntoCache(const QString &providerId);
    void showProvider(const QString &providerId);
    void setStatus(const QString &text, bool error = false);
    void updateForgetButton();

    Settings settings_;
    QHash<QString, QString> keyCache_; // provider id -> key edited in this session
    QString shownProvider_;

    QComboBox *provider_;
    QLineEdit *baseUrl_;
    QLineEdit *apiKey_;
    QLabel *keyHelp_;
    QComboBox *model_;
    QPushButton *fetchModels_;
    QSpinBox *timeout_;
    QSpinBox *treeChars_;
    QSpinBox *payloadBytes_;
    QCheckBox *masking_;
    QComboBox *lookups_;
    QPushButton *forgetApprovals_;
    QLabel *status_;
    HttpBackend *probe_ = nullptr;
};

} // namespace smartshark
