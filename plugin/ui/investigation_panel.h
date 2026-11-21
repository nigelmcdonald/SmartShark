/* investigation_panel.h
 *
 * The SmartShark side panel: explains the selected packet in collapsible
 * sections that fill in as the model writes (overview, layers, endpoints,
 * payload, notable), and takes follow-up questions.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QElapsedTimer>
#include <QList>
#include <QWidget>

#include "core/chat.h"
#include "core/packet_explainer.h"
#include "core/privacy.h"
#include "core/settings.h"

class QFrame;
class QLabel;
class QLineEdit;
class QPushButton;
class QTimer;

namespace smartshark {

class CloudConsent;
class CollapsibleSection;
class IpLookup;
class HttpBackend;

class InvestigationPanel : public QWidget {
    Q_OBJECT
public:
    explicit InvestigationPanel(QWidget *parent = nullptr);
    ~InvestigationPanel() override;

    // Start explaining the packet selected in the packet list.
    void explainSelectedPacket();

private slots:
    void onAsk();
    void onStop();
    void onTick();
    void render();

private:
    enum class Phase { Idle, LookingUp, Explaining, Answering };

    void rebuildBackend(const Settings &settings);
    void dropBackend();
    bool mayFollowUp(const Settings &settings); // false: the consent question is showing
    void setPhase(Phase phase);
    void setStatus(const QString &text, bool error = false);
    void scheduleRender();
    void resetSections();
    void showRawData();
    void askLookupPermission();
    void startLookups();
    void startModel();

    PacketSnapshot packet_;
    QList<ChatMessage> messages_;  // conversation about the current packet
    QString explanation_;          // the first reply, split into sections
    QList<QPair<QString, QString>> followUps_; // question, answer (answer grows while streaming)
    Phase phase_ = Phase::Idle;
    AddressMasker masker_;         // placeholders for addresses, when masking is on
    bool masking_ = false;
    bool renderPending_ = false;

    QLabel *title_;
    QLabel *provider_;
    QPushButton *stop_;
    QLabel *status_;
    QFrame *consent_;
    CloudConsent *cloud_;
    CollapsibleSection *overview_;
    CollapsibleSection *layers_;
    CollapsibleSection *endpoints_;
    CollapsibleSection *payload_;
    CollapsibleSection *notable_;
    CollapsibleSection *raw_;
    CollapsibleSection *sent_;
    CollapsibleSection *conversation_;
    QLineEdit *question_;
    QPushButton *ask_;

    QTimer *tick_;
    QElapsedTimer clock_;
    int frame_ = 0;
    qsizetype reasoningChars_ = 0; // reasoning streamed so far, for the progress line

    HttpBackend *backend_ = nullptr;
    IpLookup *lookup_;
};

} // namespace smartshark
