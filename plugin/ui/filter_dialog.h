/* filter_dialog.h
 *
 * Tools > SmartShark > Generate Display Filter.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <memory>

#include <QDialog>
#include <QElapsedTimer>

class QFrame;
class QLabel;
class QLineEdit;
class QPushButton;
class QTimer;
class QVBoxLayout;

namespace smartshark {

class FilterAssistant;
class HttpBackend;
struct FilterAdvice;

class FilterDialog : public QDialog {
    Q_OBJECT
public:
    explicit FilterDialog(QWidget *parent = nullptr);
    ~FilterDialog() override;

private slots:
    void onGenerateOrStop();
    void onFilterEdited(const QString &text);
    void onApply();
    void onCopy();
    void onSettings();
    void onThinkingTick();

private:
    void generate();
    void rebuildBackend();
    void setBusy(bool busy);
    void setStatus(const QString &text, bool error = false);
    void showAdvice(const FilterAdvice &advice, bool help);
    void clearAdvice();
    void setFilterText(const QString &text);

    QLineEdit *request_;
    QPushButton *generate_;
    QWidget *examples_;
    QLineEdit *filter_;
    QLabel *explanation_;
    QLabel *validity_;
    QLabel *status_;
    QFrame *advicePanel_;
    QVBoxLayout *adviceLayout_;
    QLabel *provider_;
    QPushButton *apply_;
    QPushButton *copy_;

    QTimer *thinkingTimer_;
    QElapsedTimer thinkingClock_;
    int thinkingFrame_ = 0;
    qsizetype reasoningChars_ = 0;

    bool busy_ = false;
    HttpBackend *backend_ = nullptr;
    std::unique_ptr<FilterAssistant> assistant_;
};

} // namespace smartshark
