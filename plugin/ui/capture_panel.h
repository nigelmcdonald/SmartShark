/* capture_panel.h
 *
 * The "Capture" tab of the SmartShark panel: summarises the displayed packets
 * and answers questions about them ("which server makes the most
 * connections?") from statistics SmartShark counts itself.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QElapsedTimer>
#include <QList>
#include <QWidget>

#include "core/capture_stats.h"
#include "core/chat.h"
#include "core/ip_facts.h"
#include "core/privacy.h"
#include "core/settings.h"

class QLabel;
class QLineEdit;
class QPushButton;
class QTimer;

namespace smartshark {

class CloudConsent;
class CollapsibleSection;
class IpLookup;
class HttpBackend;

class CapturePanel : public QWidget {
    Q_OBJECT
public:
    explicit CapturePanel(QWidget *parent = nullptr);
    ~CapturePanel() override;

    // Count the displayed packets and summarise them. With a question, answer
    // it first.
    void analyse(const QString &question = QString());

private slots:
    void onAsk();
    void onStop();
    void onTick();
    void render();

private:
    enum class Phase { Idle, Counting, LookingUp, Thinking, Answering };

    void rebuildBackend(const Settings &settings);
    void dropBackend();
    bool mayFollowUp(const Settings &settings); // false: the consent question is showing
    void setPhase(Phase phase);
    void setStatus(const QString &text, bool error = false);
    void scheduleRender();
    void startModel();

    CaptureStats stats_;
    QString displayFilter_;
    QString question_;               // the question that started this analysis, if any
    QList<IpFacts> addresses_;
    QList<ChatMessage> messages_;
    QString reply_;                  // first reply, split into sections
    QList<QPair<QString, QString>> followUps_;
    Phase phase_ = Phase::Idle;
    AddressMasker masker_;
    bool masking_ = false;
    bool renderPending_ = false;

    QLabel *title_;
    QLabel *provider_;
    QPushButton *summarize_;
    QPushButton *stop_;
    QLabel *status_;
    CloudConsent *cloud_;
    CollapsibleSection *answer_;
    CollapsibleSection *summary_;
    CollapsibleSection *talkers_;
    CollapsibleSection *connections_;
    CollapsibleSection *notable_;
    CollapsibleSection *statistics_;
    CollapsibleSection *sent_;
    CollapsibleSection *conversation_;
    QLineEdit *input_;
    QPushButton *ask_;

    QTimer *tick_;
    QElapsedTimer clock_;
    int frame_ = 0;
    qsizetype reasoningChars_ = 0;

    HttpBackend *backend_ = nullptr;
    IpLookup *lookup_;
};

} // namespace smartshark
