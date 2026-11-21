/* research_panel.h
 *
 * The "Research" tab of the SmartShark panel: Claude picks the most unusual
 * things in the selected packet or the displayed packets, looks them up on
 * the web, and reports with sources. The box at the bottom steers the
 * research or asks follow-up questions.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QElapsedTimer>
#include <QList>
#include <QSet>
#include <QWidget>

#include "core/anthropic_backend.h"
#include "core/chat.h"
#include "core/privacy.h"
#include "core/settings.h"

class QFrame;
class QLabel;
class QLineEdit;
class QPushButton;
class QTimer;

namespace smartshark {

class AnthropicBackend;
class CloudConsent;
class CollapsibleSection;

class ResearchPanel : public QWidget {
    Q_OBJECT
public:
    explicit ResearchPanel(QWidget *parent = nullptr);
    ~ResearchPanel() override;

    void researchSelectedPacket(const QString &guidance = QString());
    void researchDisplayedPackets(const QString &guidance = QString());

private slots:
    void onAsk();
    void onStop();
    void onTick();
    void render();

private:
    enum class Phase { Idle, Counting, Researching, Answering };

    bool prepare(const QString &guidance); // reset; false if web research is not available
    bool rebuildBackend(const Settings &settings); // false if the provider cannot search the web
    void dropBackend();
    void setPhase(Phase phase);
    void setStatus(const QString &text, bool error = false);
    void scheduleRender();
    void startModel();
    AnthropicBackend::ResearchCallbacks callbacks(bool followUp);
    QString explainError(const QString &error) const;

    QString contextData_;      // the packet or statistics message, before the research request
    bool wholeCapture_ = false;
    QString guidance_;
    QString title_;
    QList<ChatMessage> messages_;
    QString reply_;
    QList<QPair<QString, QString>> followUps_;
    QStringList searchLog_;    // one Markdown line per search
    QList<anthropic::WebSource> cited_, others_;
    QSet<QString> openableUrls_; // only URLs from search results can be opened
    AddressMasker masker_;
    bool masking_ = false;
    Phase phase_ = Phase::Idle;
    bool renderPending_ = false;

    QLabel *titleLabel_;
    QLabel *provider_;
    QPushButton *packetButton_;
    QPushButton *captureButton_;
    QPushButton *stop_;
    QLabel *status_;
    QFrame *notice_;          // shown when the provider cannot search the web
    CloudConsent *cloud_;
    CollapsibleSection *stoodOut_;
    CollapsibleSection *findings_;
    CollapsibleSection *meaning_;
    CollapsibleSection *nextSteps_;
    CollapsibleSection *searches_;
    CollapsibleSection *sources_;
    CollapsibleSection *sent_;
    CollapsibleSection *conversation_;
    QLineEdit *input_;
    QPushButton *ask_;

    QTimer *tick_;
    QElapsedTimer clock_;
    int frame_ = 0;
    qsizetype reasoningChars_ = 0;

    AnthropicBackend *backend_ = nullptr;
};

} // namespace smartshark
