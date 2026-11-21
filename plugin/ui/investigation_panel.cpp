/* investigation_panel.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ui/investigation_panel.h"

#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QLocale>
#include <QPushButton>
#include <QScrollArea>
#include <QTimer>
#include <QVBoxLayout>

#include "core/input_guard.h"
#include "core/settings.h"
#include "ui/backend_factory.h"
#include "ui/cloud_consent.h"
#include "ui/collapsible_section.h"
#include "ui/ip_lookup.h"
#include "ui/ws_services.h"

namespace smartshark {

namespace {

constexpr int kRawPreviewBytes = 4096;

bool hasPublicAddress(const PacketSnapshot &p)
{
    for (const IpFacts &f : p.addresses) {
        if (f.isPublic)
            return true;
    }
    return false;
}

} // namespace

InvestigationPanel::InvestigationPanel(QWidget *parent) : QWidget(parent)
{
    lookup_ = new IpLookup(this);

    title_ = new QLabel(QStringLiteral("No packet yet"), this);
    title_->setTextFormat(Qt::PlainText);
    title_->setStyleSheet(QStringLiteral("font-weight: bold;"));
    title_->setWordWrap(true);
    provider_ = new QLabel(this);
    provider_->setTextFormat(Qt::PlainText);
    provider_->setStyleSheet(QStringLiteral("color: palette(mid);"));
    stop_ = new QPushButton(QStringLiteral("Stop"), this);
    stop_->setEnabled(false);

    auto *top = new QHBoxLayout;
    auto *titles = new QVBoxLayout;
    titles->addWidget(title_);
    titles->addWidget(provider_);
    top->addLayout(titles, 1);
    top->addWidget(stop_, 0, Qt::AlignTop);

    status_ = new QLabel(this);
    status_->setTextFormat(Qt::PlainText);
    status_->setWordWrap(true);

    // One-time question before any address is sent to an outside service.
    consent_ = new QFrame(this);
    consent_->setFrameShape(QFrame::StyledPanel);
    auto *consentText = new QLabel(
        QStringLiteral("<b>Look up public IP addresses online?</b><br>"
                       "SmartShark can find out who owns the public addresses in a packet "
                       "(through rdap.org and the internet registries) and their DNS names "
                       "(through your DNS server). Only the addresses are sent, never packet data."),
        consent_);
    consentText->setWordWrap(true);
    auto *allow = new QPushButton(QStringLiteral("Allow"), consent_);
    allow->setToolTip(QStringLiteral("Look up public addresses automatically from now on"));
    auto *notNow = new QPushButton(QStringLiteral("Not now"), consent_);
    notNow->setToolTip(QStringLiteral("Explain without lookups; ask again next time"));
    auto *never = new QPushButton(QStringLiteral("Never"), consent_);
    never->setToolTip(QStringLiteral("Never look up addresses online (change this in Settings)"));
    auto *consentButtons = new QHBoxLayout;
    consentButtons->addStretch();
    consentButtons->addWidget(allow);
    consentButtons->addWidget(notNow);
    consentButtons->addWidget(never);
    auto *consentLayout = new QVBoxLayout(consent_);
    consentLayout->addWidget(consentText);
    consentLayout->addLayout(consentButtons);
    consent_->hide();
    cloud_ = new CloudConsent(this);

    overview_ =new CollapsibleSection(QStringLiteral("Overview"));
    layers_ = new CollapsibleSection(QStringLiteral("Layers"));
    endpoints_ = new CollapsibleSection(QStringLiteral("Endpoints"));
    payload_ = new CollapsibleSection(QStringLiteral("Payload"));
    notable_ = new CollapsibleSection(QStringLiteral("Notable"));
    raw_ = new CollapsibleSection(QStringLiteral("Raw data"));
    raw_->setExpanded(false);
    sent_ = new CollapsibleSection(QStringLiteral("Sent to the AI"));
    sent_->setExpanded(false);
    sent_->hide();
    conversation_ = new CollapsibleSection(QStringLiteral("Your questions"));
    conversation_->hide();

    auto *content = new QWidget;
    auto *contentLayout = new QVBoxLayout(content);
    contentLayout->setContentsMargins(4, 4, 4, 4);
    for (CollapsibleSection *s : {overview_, layers_, endpoints_, payload_, notable_, raw_, sent_, conversation_})
        contentLayout->addWidget(s);
    contentLayout->addStretch();

    auto *scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scroll->setWidget(content);

    question_ = new QLineEdit(this);
    question_->setPlaceholderText(QStringLiteral("Ask a follow-up question about this packet"));
    question_->setMaxLength(guard::kMaxRequestChars);
    question_->setClearButtonEnabled(true);
    ask_ = new QPushButton(QStringLiteral("Ask"), this);
    auto *askRow = new QHBoxLayout;
    askRow->addWidget(question_, 1);
    askRow->addWidget(ask_);

    auto *layout = new QVBoxLayout(this);
    layout->addLayout(top);
    layout->addWidget(status_);
    layout->addWidget(consent_);
    layout->addWidget(cloud_);
    layout->addWidget(scroll, 1);
    layout->addLayout(askRow);

    tick_ = new QTimer(this);
    tick_->setInterval(400);
    connect(tick_, &QTimer::timeout, this, &InvestigationPanel::onTick);
    connect(stop_, &QPushButton::clicked, this, &InvestigationPanel::onStop);
    connect(ask_, &QPushButton::clicked, this, &InvestigationPanel::onAsk);
    connect(question_, &QLineEdit::returnPressed, this, &InvestigationPanel::onAsk);

    auto decide = [this](Settings::OnlineLookups choice, bool remember) {
        consent_->hide();
        if (remember) {
            Settings s = Settings::load(ws::settingsFilePath());
            s.onlineLookups = choice;
            s.save(ws::settingsFilePath());
        }
        if (choice == Settings::OnlineLookups::Always)
            startLookups();
        else
            startModel();
    };
    connect(allow, &QPushButton::clicked, this, [decide]() { decide(Settings::OnlineLookups::Always, true); });
    connect(notNow, &QPushButton::clicked, this, [decide]() { decide(Settings::OnlineLookups::Ask, false); });
    connect(never, &QPushButton::clicked, this, [decide]() { decide(Settings::OnlineLookups::Never, true); });

    resetSections();
    setPhase(Phase::Idle);
}

InvestigationPanel::~InvestigationPanel()
{
    lookup_->cancel();
    if (backend_)
        backend_->cancel();
}

void InvestigationPanel::dropBackend()
{
    if (backend_) {
        backend_->cancel();
        backend_->deleteLater();
        backend_ = nullptr;
    }
}

void InvestigationPanel::rebuildBackend(const Settings &settings)
{
    dropBackend();
    backend_ = makeBackend(settings, this);
    provider_->setText(QStringLiteral("Using %1").arg(backend_->describe()));
}

bool InvestigationPanel::mayFollowUp(const Settings &settings)
{
    if (CloudConsent::approved(settings))
        return true;
    setStatus(QStringLiteral("SmartShark has a question before it sends anything:"));
    cloud_->ask(
        settings,
        QStringLiteral("<li>your question</li><li>the conversation so far: this packet's data and the earlier "
                       "answers</li>"),
        [this]() { onAsk(); }, [this]() { setStatus(cloudCancelledMessage()); });
    return false;
}

void InvestigationPanel::resetSections()
{
    sent_->setMarkdown(QString());
    sent_->hide();
    for (CollapsibleSection *s : {overview_, layers_, endpoints_, payload_, notable_, raw_}) {
        s->setMarkdown(QString());
        s->setState(CollapsibleSection::State::Idle);
    }
    conversation_->setMarkdown(QString());
    conversation_->hide();
    consent_->hide();
    cloud_->hide();
}

void InvestigationPanel::setStatus(const QString &text, bool error)
{
    status_->setText(text);
    status_->setStyleSheet(error ? QStringLiteral("color: #c0392b;") : QString());
}

void InvestigationPanel::setPhase(Phase phase)
{
    phase_ = phase;
    const bool busy = phase != Phase::Idle;
    stop_->setEnabled(busy);
    const bool canAsk = !busy && messages_.size() >= 3; // the explanation has arrived
    ask_->setEnabled(canAsk);
    question_->setEnabled(canAsk);
    if (busy) {
        frame_ = 0;
        reasoningChars_ = 0;
        clock_.start();
        onTick();
        tick_->start();
    } else {
        tick_->stop();
    }
}

void InvestigationPanel::onTick()
{
    static const char *const dots[] = {"", ".", "..", "..."};
    const qint64 secs = clock_.elapsed() / 1000;
    const QString d = QLatin1String(dots[frame_++ % 4]);
    QString text = phase_ == Phase::LookingUp ? QStringLiteral("Looking up addresses%1").arg(d, -3)
                                              : QStringLiteral("Thinking%1").arg(d, -3);
    if (reasoningChars_ > 0) // about six characters per English word
        text += QStringLiteral("  reasoning, about %1 words so far").arg(QLocale().toString(reasoningChars_ / 6));
    if (secs >= 2)
        text += QStringLiteral("  (%1 s)").arg(secs);
    setStatus(text);
}

void InvestigationPanel::scheduleRender()
{
    if (renderPending_)
        return;
    renderPending_ = true;
    QTimer::singleShot(80, this, &InvestigationPanel::render); // coalesce rapid deltas
}

void InvestigationPanel::showRawData()
{
    QString md;
    for (const PayloadSource &s : packet_.sources) {
        md += QStringLiteral("**%1** (%2 bytes%3)\n\n")
                  .arg(guard::singleLine(s.name, 80).remove(QLatin1Char('*')))
                  .arg(s.totalLength)
                  .arg(s.totalLength > kRawPreviewBytes ? QStringLiteral(", first %1 shown").arg(kRawPreviewBytes)
                                                         : QString());
        md += markdownCodeBlock(payloadPreview(s.bytes, kRawPreviewBytes)) + QStringLiteral("\n");
    }
    raw_->setMarkdown(md.isEmpty() ? QStringLiteral("No data.") : md);
}

void InvestigationPanel::render()
{
    renderPending_ = false;

    // With masking on, the model saw placeholders; show the real addresses.
    const QMap<ExplainSection, QString> parts = splitExplanation(masker_.unmask(explanation_));
    const QList<QPair<ExplainSection, CollapsibleSection *>> sections = {
        {ExplainSection::Overview, overview_}, {ExplainSection::Layers, layers_},
        {ExplainSection::Endpoints, endpoints_}, {ExplainSection::Payload, payload_},
        {ExplainSection::Notable, notable_},
    };

    // While streaming, the last section with text is the one being written.
    int writing = -1;
    if (phase_ == Phase::Explaining) {
        for (int i = 0; i < sections.size(); ++i) {
            if (!parts.value(sections[i].first).isEmpty())
                writing = i;
        }
    }

    for (int i = 0; i < sections.size(); ++i) {
        QString text = parts.value(sections[i].first);
        if (sections[i].first == ExplainSection::Endpoints) {
            // SmartShark's own facts come first: they are looked up, not guessed.
            const QString facts = packet_.addresses.isEmpty()
                                      ? QStringLiteral("*No IP addresses in this packet.*")
                                      : QStringLiteral("**What SmartShark found**\n\n") + factsTable(packet_.addresses);
            text = text.isEmpty() ? facts : facts + QStringLiteral("\n\n**What it means**\n\n") + text;
        } else if (sections[i].first == ExplainSection::Payload && packet_.encryptedWithoutKeys &&
                   phase_ != Phase::Explaining && !explanation_.isEmpty()) {
            text += QStringLiteral("\n\n---\n\n") + encryptedPayloadHelp();
        }
        sections[i].second->setMarkdown(text);
        if (phase_ == Phase::Explaining) {
            sections[i].second->setState(i == writing   ? CollapsibleSection::State::Working
                                         : i < writing ? CollapsibleSection::State::Done
                                                       : CollapsibleSection::State::Waiting);
        }
    }

    if (!followUps_.isEmpty()) {
        QString md;
        for (const auto &qa : followUps_) {
            // The question is the user's own text; escape Markdown so it shows literally.
            QString q = qa.first;
            q.replace(QLatin1Char('\\'), QStringLiteral("\\\\")).replace(QLatin1Char('*'), QStringLiteral("\\*"));
            md += QStringLiteral("**You:** ") + q + QStringLiteral("\n\n") + masker_.unmask(qa.second) +
                  QStringLiteral("\n\n---\n\n");
        }
        conversation_->setMarkdown(md);
        conversation_->show();
    }
}

void InvestigationPanel::explainSelectedPacket()
{
    lookup_->cancel();
    rebuildBackend(Settings::load(ws::settingsFilePath()));

    messages_.clear();
    explanation_.clear();
    followUps_.clear();
    masker_.clear();
    masking_ = false;
    resetSections();
    setPhase(Phase::Idle);

    packet_ = ws::selectedPacket(Settings::load(ws::settingsFilePath()).maxTreeChars + 1);
    if (!packet_.ok) {
        title_->setText(QStringLiteral("No packet to explain"));
        setStatus(packet_.error, true);
        return;
    }
    title_->setText(QStringLiteral("Frame %1  ·  %2").arg(packet_.frameNumber).arg(packet_.protocols));
    for (CollapsibleSection *s : {overview_, layers_, endpoints_, payload_, notable_})
        s->setState(CollapsibleSection::State::Waiting);
    showRawData();
    render(); // shows the address facts straight away

    if (!hasPublicAddress(packet_)) {
        startModel();
        return;
    }
    switch (Settings::load(ws::settingsFilePath()).onlineLookups) {
    case Settings::OnlineLookups::Always: startLookups(); break;
    case Settings::OnlineLookups::Never: startModel(); break;
    case Settings::OnlineLookups::Ask: askLookupPermission(); break;
    }
}

void InvestigationPanel::askLookupPermission()
{
    setStatus(QStringLiteral("SmartShark has a question before it starts:"));
    consent_->show();
}

void InvestigationPanel::startLookups()
{
    setPhase(Phase::LookingUp);
    endpoints_->setState(CollapsibleSection::State::Working, QStringLiteral("looking up..."));
    const quint32 frame = packet_.frameNumber;
    lookup_->lookup(packet_.addresses, [this, frame](const QList<IpFacts> &facts) {
        if (packet_.frameNumber != frame || phase_ != Phase::LookingUp)
            return;
        packet_.addresses = facts;
        render();
        startModel();
    }, ownAddressesToSkip(Settings::load(ws::settingsFilePath())));
}

void InvestigationPanel::startModel()
{
    const Settings settings = Settings::load(ws::settingsFilePath());
    if (!CloudConsent::approved(settings)) {
        setPhase(Phase::Idle);
        setStatus(QStringLiteral("SmartShark has a question before it sends anything:"));
        const QString payload =
            settings.payloadBytes > 0
                ? QStringLiteral("<li>up to %1 bytes of its decoded or decrypted payload</li>")
                      .arg(QLocale().toString(settings.payloadBytes))
                : QStringLiteral("<li>no payload data (turned off in Settings)</li>");
        const quint32 frame = packet_.frameNumber;
        cloud_->ask(
            settings,
            QStringLiteral("<li>this packet's decoded fields (up to %1 characters)</li>%2"
                           "<li>facts about its IP addresses, including names Wireshark resolved and any "
                           "online lookup results</li>"
                           "<li>the follow-up questions you ask</li>")
                .arg(QLocale().toString(settings.maxTreeChars), payload),
            [this, frame]() {
                if (packet_.frameNumber != frame)
                    return;
                startModel(); // checks again, with the settings as they are now
            },
            [this]() {
                for (CollapsibleSection *s : {overview_, layers_, endpoints_, payload_, notable_})
                    s->setState(CollapsibleSection::State::Idle, QStringLiteral("not sent"));
                setStatus(cloudCancelledMessage());
            });
        return;
    }
    // Send through a backend built from the same settings the check approved.
    rebuildBackend(settings);

    masking_ = setUpMasker(&masker_, settings);
    QString message = explainPacketMessage(packet_, settings.maxTreeChars, settings.payloadBytes);
    if (masking_) {
        message = masker_.mask(message);
        if (masker_.count() > 0)
            provider_->setText(provider_->text() + QStringLiteral("  ·  %1 address(es) hidden").arg(masker_.count()));
    }
    sent_->setMarkdown(sentToAiMarkdown(message, settings, masker_));
    sent_->show();
    messages_ = {
        {ChatMessage::Role::System, explainSystemPrompt()},
        {ChatMessage::Role::User, message},
    };
    setPhase(Phase::Explaining);

    backend_->chatStream(
        messages_,
        [this](const QString &delta) {
            explanation_ += delta;
            scheduleRender();
        },
        [this](const ChatResult &res) {
            if (res.ok) {
                explanation_ = res.text;
                messages_.append({ChatMessage::Role::Assistant, res.text});
                setPhase(Phase::Idle);
                render();
                for (CollapsibleSection *s : {overview_, layers_, endpoints_, payload_, notable_})
                    s->setState(CollapsibleSection::State::Done);
                setStatus(QString());
                question_->setFocus();
            } else {
                messages_.clear(); // no usable conversation to continue
                setPhase(Phase::Idle);
                render();
                for (CollapsibleSection *s : {overview_, layers_, endpoints_, payload_, notable_})
                    s->setState(CollapsibleSection::State::Failed);
                setStatus(res.error, true);
            }
        },
        [this](const QString &reasoning) { reasoningChars_ += reasoning.size(); });
}

void InvestigationPanel::onAsk()
{
    const QString question = explainFollowUpMessage(question_->text());
    if (question.isEmpty() || phase_ != Phase::Idle || messages_.size() < 3)
        return;
    const Settings settings = Settings::load(ws::settingsFilePath());
    if (hidingSwitchedOn(masking_, settings)) {
        setStatus(hidingSwitchedOnMessage(QStringLiteral("Right-click the packet and choose SmartShark > Explain "
                                                         "This Packet")),
                  true);
        return;
    }
    if (!mayFollowUp(settings))
        return; // the question stays in the box until the user decides
    rebuildBackend(settings);
    question_->clear();

    messages_.append({ChatMessage::Role::User, masking_ ? masker_.mask(question) : question});
    followUps_.append({question, QString()});
    conversation_->setExpanded(true);
    conversation_->setState(CollapsibleSection::State::Working);
    setPhase(Phase::Answering);
    render();

    backend_->chatStream(
        messages_,
        [this](const QString &delta) {
            followUps_.last().second += delta;
            scheduleRender();
        },
        [this](const ChatResult &res) {
            if (res.ok) {
                followUps_.last().second = res.text;
                messages_.append({ChatMessage::Role::Assistant, res.text});
                conversation_->setState(CollapsibleSection::State::Done);
                setPhase(Phase::Idle);
                setStatus(QString());
            } else {
                // Drop the unanswered question so the conversation stays consistent.
                messages_.removeLast();
                followUps_.last().second += QStringLiteral("\n\n*(No answer: %1)*").arg(res.error);
                conversation_->setState(CollapsibleSection::State::Failed);
                setPhase(Phase::Idle);
                setStatus(res.error, true);
            }
            render();
            question_->setFocus();
        },
        [this](const QString &reasoning) { reasoningChars_ += reasoning.size(); });
}

void InvestigationPanel::onStop()
{
    if (phase_ == Phase::Idle)
        return;
    const Phase was = phase_;
    lookup_->cancel();
    // Dropping the backend closes its connection, so nothing late can arrive.
    dropBackend();

    if (was == Phase::Explaining || was == Phase::LookingUp) {
        // Keep what arrived, but there is no complete reply to build on.
        if (!explanation_.isEmpty())
            messages_.append({ChatMessage::Role::Assistant, explanation_});
        else
            messages_.clear();
        setPhase(Phase::Idle);
        for (CollapsibleSection *s : {overview_, layers_, endpoints_, payload_, notable_})
            s->setState(CollapsibleSection::State::Idle, QStringLiteral("stopped"));
    } else {
        if (!followUps_.last().second.isEmpty())
            messages_.append({ChatMessage::Role::Assistant, followUps_.last().second});
        else
            messages_.removeLast();
        setPhase(Phase::Idle);
        conversation_->setState(CollapsibleSection::State::Idle, QStringLiteral("stopped"));
    }
    render();
    setStatus(QStringLiteral("Stopped."));
}

} // namespace smartshark
