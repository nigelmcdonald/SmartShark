/* research_panel.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ui/research_panel.h"

#include <QApplication>
#include <QDesktopServices>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QLocale>
#include <QPushButton>
#include <QScrollArea>
#include <QTimer>
#include <QUrl>
#include <QVBoxLayout>

#include "core/capture_explainer.h"
#include "core/capture_stats.h"
#include "core/input_guard.h"
#include "core/ip_facts.h"
#include "core/packet_explainer.h"
#include "core/research.h"
#include "core/secret_store.h"
#include "core/settings.h"
#include "ui/bridge.h"
#include "ui/cloud_consent.h"
#include "ui/collapsible_section.h"
#include "ui/ws_services.h"

namespace smartshark {

namespace {
constexpr int kMaxStatsChars = 12000;
constexpr int kAddressesToDescribe = 12;

QString escapeUserText(QString q)
{
    q.replace(QLatin1Char('\\'), QStringLiteral("\\\\")).replace(QLatin1Char('*'), QStringLiteral("\\*"));
    return q;
}
} // namespace

ResearchPanel::ResearchPanel(QWidget *parent) : QWidget(parent)
{
    titleLabel_ = new QLabel(QStringLiteral("Web research"), this);
    titleLabel_->setTextFormat(Qt::PlainText);
    titleLabel_->setStyleSheet(QStringLiteral("font-weight: bold;"));
    titleLabel_->setWordWrap(true);
    provider_ = new QLabel(this);
    provider_->setTextFormat(Qt::PlainText);
    provider_->setStyleSheet(QStringLiteral("color: palette(mid);"));
    provider_->setWordWrap(true);
    packetButton_ = new QPushButton(QStringLiteral("Packet"), this);
    packetButton_->setToolTip(QStringLiteral("Research the packet selected in the packet list"));
    captureButton_ = new QPushButton(QStringLiteral("Displayed packets"), this);
    captureButton_->setToolTip(QStringLiteral("Research the packets the current display filter shows"));
    stop_ = new QPushButton(QStringLiteral("Stop"), this);
    stop_->setEnabled(false);

    auto *top = new QHBoxLayout;
    auto *titles = new QVBoxLayout;
    titles->addWidget(titleLabel_);
    titles->addWidget(provider_);
    top->addLayout(titles, 1);
    top->addWidget(packetButton_, 0, Qt::AlignTop);
    top->addWidget(captureButton_, 0, Qt::AlignTop);
    top->addWidget(stop_, 0, Qt::AlignTop);

    status_ = new QLabel(
        QStringLiteral("Claude picks the most unusual things in a packet or in the displayed packets, looks them up "
                       "on the web and tells you what the sources say. Click Packet or Displayed packets, or type "
                       "what you want looked into below. Each research uses up to %1 web searches (Anthropic "
                       "charges about 1 cent per search) plus the usual token cost.")
            .arg(anthropic::kMaxSearches),
        this);
    status_->setTextFormat(Qt::PlainText);
    status_->setWordWrap(true);

    // Shown when the chosen provider cannot search the web.
    notice_ = new QFrame(this);
    notice_->setFrameShape(QFrame::StyledPanel);
    auto *noticeText = new QLabel(
        QStringLiteral("<b>In this version, web research needs Anthropic Claude.</b><br>It uses the web search "
                       "that Anthropic runs for Claude. SmartShark doesn't yet search the web for other providers "
                       "or local models. Choose Anthropic Claude in Settings to use this tab. The Packet and "
                       "Capture tabs work with every provider."),
        notice_);
    noticeText->setWordWrap(true);
    auto *openSettings = new QPushButton(QStringLiteral("Settings..."), notice_);
    auto *noticeButtons = new QHBoxLayout;
    noticeButtons->addStretch();
    noticeButtons->addWidget(openSettings);
    auto *noticeLayout = new QVBoxLayout(notice_);
    noticeLayout->addWidget(noticeText);
    noticeLayout->addLayout(noticeButtons);
    notice_->hide();
    connect(openSettings, &QPushButton::clicked, this, []() { smartshark_ui_settings(); });

    cloud_ = new CloudConsent(this);

    stoodOut_ = new CollapsibleSection(researchSectionTitle(ResearchSection::StoodOut));
    findings_ = new CollapsibleSection(researchSectionTitle(ResearchSection::Findings));
    meaning_ = new CollapsibleSection(researchSectionTitle(ResearchSection::Meaning));
    nextSteps_ = new CollapsibleSection(researchSectionTitle(ResearchSection::NextSteps));
    searches_ = new CollapsibleSection(QStringLiteral("Searches"));
    sources_ = new CollapsibleSection(QStringLiteral("Sources"));
    sources_->setLinkHandler([this](const QUrl &url) {
        // Only pages that came from the search results, never links in the AI's text.
        const QString u = sourceLinkTarget(QString::fromLatin1(url.toEncoded()));
        if (openableUrls_.contains(u) && isWebUrl(u))
            QDesktopServices::openUrl(url);
    });
    sent_ = new CollapsibleSection(QStringLiteral("Sent to the AI"));
    sent_->setExpanded(false);
    conversation_ = new CollapsibleSection(QStringLiteral("Your questions"));

    auto *content = new QWidget;
    auto *contentLayout = new QVBoxLayout(content);
    contentLayout->setContentsMargins(4, 4, 4, 4);
    for (CollapsibleSection *s :
         {stoodOut_, findings_, meaning_, nextSteps_, searches_, sources_, sent_, conversation_}) {
        contentLayout->addWidget(s);
        s->hide();
    }
    contentLayout->addStretch();

    auto *scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scroll->setWidget(content);

    input_ = new QLineEdit(this);
    input_->setPlaceholderText(QStringLiteral("Guide the research or ask a follow-up, e.g. who runs this server?"));
    input_->setMaxLength(guard::kMaxRequestChars);
    input_->setClearButtonEnabled(true);
    ask_ = new QPushButton(QStringLiteral("Ask"), this);
    auto *askRow = new QHBoxLayout;
    askRow->addWidget(input_, 1);
    askRow->addWidget(ask_);

    auto *layout = new QVBoxLayout(this);
    layout->addLayout(top);
    layout->addWidget(status_);
    layout->addWidget(notice_);
    layout->addWidget(cloud_);
    layout->addWidget(scroll, 1);
    layout->addLayout(askRow);

    tick_ = new QTimer(this);
    tick_->setInterval(400);
    connect(tick_, &QTimer::timeout, this, &ResearchPanel::onTick);
    connect(stop_, &QPushButton::clicked, this, &ResearchPanel::onStop);
    connect(packetButton_, &QPushButton::clicked, this, [this]() { researchSelectedPacket(); });
    connect(captureButton_, &QPushButton::clicked, this, [this]() { researchDisplayedPackets(); });
    connect(ask_, &QPushButton::clicked, this, &ResearchPanel::onAsk);
    connect(input_, &QLineEdit::returnPressed, this, &ResearchPanel::onAsk);

    setPhase(Phase::Idle);
}

ResearchPanel::~ResearchPanel()
{
    if (backend_)
        backend_->cancel();
}

void ResearchPanel::dropBackend()
{
    if (backend_) {
        backend_->cancel();
        backend_->deleteLater();
        backend_ = nullptr;
    }
}

bool ResearchPanel::rebuildBackend(const Settings &settings)
{
    dropBackend();
    ProviderConfig cfg = settings.activeConfig();
    if (cfg.api != ApiKind::AnthropicMessages) {
        const ProviderPreset *p = findPreset(cfg.providerId);
        provider_->setText(QStringLiteral("Current provider: %1").arg(p ? p->displayName : cfg.providerId));
        notice_->show();
        return false;
    }
    notice_->hide();
    cfg.apiKey = secrets::loadApiKey(cfg.providerId);
    backend_ = new AnthropicBackend(cfg, this);
    provider_->setText(QStringLiteral("Using %1").arg(backend_->describe()));
    return true;
}

void ResearchPanel::setStatus(const QString &text, bool error)
{
    status_->setText(text);
    status_->setStyleSheet(error ? QStringLiteral("color: #c0392b;") : QString());
}

void ResearchPanel::setPhase(Phase phase)
{
    phase_ = phase;
    const bool busy = phase != Phase::Idle;
    stop_->setEnabled(busy && phase != Phase::Counting);
    packetButton_->setEnabled(!busy);
    captureButton_->setEnabled(!busy);
    ask_->setEnabled(!busy);
    input_->setEnabled(!busy);
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

void ResearchPanel::onTick()
{
    static const char *const dots[] = {"", ".", "..", "..."};
    const QString d = QLatin1String(dots[frame_++ % 4]);
    QString text = phase_ == Phase::Counting ? QStringLiteral("Counting packets%1").arg(d, -3)
                                              : QStringLiteral("Researching%1").arg(d, -3);
    if (!searchLog_.isEmpty())
        text += QStringLiteral("  %1 search(es) so far").arg(searchLog_.size());
    if (reasoningChars_ > 0)
        text += QStringLiteral("  reasoning, about %1 words").arg(QLocale().toString(reasoningChars_ / 6));
    const qint64 secs = clock_.elapsed() / 1000;
    if (secs >= 2)
        text += QStringLiteral("  (%1 s)").arg(secs);
    setStatus(text);
}

void ResearchPanel::scheduleRender()
{
    if (renderPending_)
        return;
    renderPending_ = true;
    QTimer::singleShot(80, this, &ResearchPanel::render);
}

void ResearchPanel::render()
{
    renderPending_ = false;
    const QMap<ResearchSection, QString> parts = splitResearch(masker_.unmask(reply_));
    const QList<QPair<ResearchSection, CollapsibleSection *>> sections = {
        {ResearchSection::StoodOut, stoodOut_},
        {ResearchSection::Findings, findings_},
        {ResearchSection::Meaning, meaning_},
        {ResearchSection::NextSteps, nextSteps_},
    };
    int writing = -1;
    if (phase_ == Phase::Researching) {
        for (int i = 0; i < sections.size(); ++i) {
            if (!parts.value(sections[i].first).isEmpty())
                writing = i;
        }
    }
    for (int i = 0; i < sections.size(); ++i) {
        sections[i].second->setMarkdown(parts.value(sections[i].first));
        if (phase_ == Phase::Researching) {
            sections[i].second->setState(i == writing   ? CollapsibleSection::State::Working
                                         : i < writing ? CollapsibleSection::State::Done
                                                       : CollapsibleSection::State::Waiting);
        }
    }

    searches_->setMarkdown(searchLog_.isEmpty() ? QStringLiteral("*No searches yet.*")
                                                : searchLog_.join(QLatin1Char('\n')));
    const QString sources = sourcesMarkdown(cited_, others_);
    sources_->setMarkdown(sources.isEmpty() ? QStringLiteral("*No sources yet.*")
                                            : sources + QStringLiteral("\n*Click a source to open it in your "
                                                                       "browser.*"));

    if (!followUps_.isEmpty()) {
        QString md;
        for (const auto &qa : followUps_)
            md += QStringLiteral("**You:** ") + escapeUserText(qa.first) + QStringLiteral("\n\n") +
                  masker_.unmask(qa.second) + QStringLiteral("\n\n---\n\n");
        conversation_->setMarkdown(md);
        conversation_->show();
    }
}

QString ResearchPanel::explainError(const QString &error) const
{
    if (error.contains(QStringLiteral("web search"), Qt::CaseInsensitive) &&
        error.contains(QStringLiteral("not enabled"), Qt::CaseInsensitive))
        return error + QStringLiteral(" An administrator of your Claude Console organization can turn web search "
                                      "on under Settings > Capabilities (platform.claude.com/settings/capabilities).");
    return error;
}

bool ResearchPanel::prepare(const QString &guidance)
{
    if (phase_ == Phase::Counting)
        return false; // Wireshark's re-scan keeps menus live; ignore a second start
    dropBackend();
    guidance_ = guard::singleLine(guidance, guard::kMaxRequestChars);
    messages_.clear();
    reply_.clear();
    followUps_.clear();
    searchLog_.clear();
    cited_.clear();
    others_.clear();
    openableUrls_.clear();
    masker_.clear();
    masking_ = false;
    cloud_->hide();
    for (CollapsibleSection *s :
         {stoodOut_, findings_, meaning_, nextSteps_, searches_, sources_, sent_, conversation_}) {
        s->setMarkdown(QString());
        s->setState(CollapsibleSection::State::Idle);
        s->hide();
    }
    setPhase(Phase::Idle);
    if (!rebuildBackend(Settings::load(ws::settingsFilePath()))) {
        setStatus(QString());
        return false;
    }
    return true;
}

void ResearchPanel::researchSelectedPacket(const QString &guidance)
{
    if (!prepare(guidance))
        return;
    const Settings settings = Settings::load(ws::settingsFilePath());
    const PacketSnapshot packet = ws::selectedPacket(settings.maxTreeChars + 1);
    if (!packet.ok) {
        titleLabel_->setText(QStringLiteral("No packet to research"));
        setStatus(packet.error, true);
        return;
    }
    wholeCapture_ = false;
    title_ = QStringLiteral("Researching frame %1  ·  %2").arg(packet.frameNumber).arg(packet.protocols);
    titleLabel_->setText(title_);
    contextData_ = explainPacketMessage(packet, settings.maxTreeChars, settings.payloadBytes);
    startModel();
}

void ResearchPanel::researchDisplayedPackets(const QString &guidance)
{
    if (!prepare(guidance))
        return;
    setPhase(Phase::Counting);
    QApplication::processEvents(); // show "Counting..." before Wireshark's re-scan blocks the UI
    CaptureStats stats;
    QString filter, error;
    const bool ok = ws::collectDisplayedStats(&stats, &filter, &error);
    setPhase(Phase::Idle);
    if (!ok) {
        setStatus(error, true);
        return;
    }
    QList<IpFacts> addresses;
    for (const QString &a : stats.addresses(kAddressesToDescribe)) {
        const IpFacts f = classifyAddress(a);
        if (f.kind != QLatin1String("Not an IP address"))
            addresses.append(f);
    }
    wholeCapture_ = true;
    title_ = filter.isEmpty() ? QStringLiteral("Researching all %1 packets").arg(QLocale().toString(stats.packets()))
                              : QStringLiteral("Researching %1 packets matching: %2")
                                    .arg(QLocale().toString(stats.packets()), guard::singleLine(filter, 200));
    titleLabel_->setText(title_);
    contextData_ = captureMessage(stats, addresses, filter, QString(), kMaxStatsChars);
    startModel();
}

AnthropicBackend::ResearchCallbacks ResearchPanel::callbacks(bool followUp)
{
    AnthropicBackend::ResearchCallbacks cb;
    cb.onText = [this, followUp](const QString &delta) {
        if (followUp)
            followUps_.last().second += delta;
        else
            reply_ += delta;
        scheduleRender();
    };
    cb.onReasoning = [this](const QString &r) { reasoningChars_ += r.size(); };
    // Claude makes at most a few searches; these caps only stop a broken or
    // hostile server from growing the lists without end.
    constexpr int kMaxSearchLines = 50;
    constexpr int kMaxSources = 300;
    cb.onSearch = [this](const QString &query) {
        if (searchLog_.size() >= kMaxSearchLines)
            return;
        QString q = guard::singleLine(query, 300);
        q.replace(QLatin1Char('`'), QLatin1Char('\''));
        searchLog_.append(QStringLiteral("%1. `%2`  *searching...*").arg(searchLog_.size() + 1).arg(q));
        searches_->show();
        scheduleRender();
    };
    cb.onResults = [this](const QList<anthropic::WebSource> &results, const QString &error) {
        if (!searchLog_.isEmpty()) {
            QString &line = searchLog_.last();
            line.replace(QStringLiteral("*searching...*"),
                         error.isEmpty() ? QStringLiteral("%1 result(s)").arg(results.size())
                                         : QStringLiteral("*%1*").arg(anthropic::searchErrorText(error)));
        }
        for (const anthropic::WebSource &s : results) {
            if (isWebUrl(s.url) && others_.size() < kMaxSources) {
                others_.append(s);
                openableUrls_.insert(sourceLinkTarget(s.url));
            }
        }
        sources_->show();
        scheduleRender();
    };
    cb.onCitation = [this](const anthropic::WebSource &c) {
        if (isWebUrl(c.url) && cited_.size() < kMaxSources) {
            cited_.append(c);
            openableUrls_.insert(sourceLinkTarget(c.url));
        }
        sources_->show();
        scheduleRender();
    };
    return cb;
}

void ResearchPanel::startModel()
{
    const Settings settings = Settings::load(ws::settingsFilePath());
    if (!CloudConsent::approved(settings)) {
        setPhase(Phase::Idle);
        setStatus(QStringLiteral("SmartShark has a question before it sends anything:"));
        cloud_->ask(
            settings,
            wholeCapture_
                ? QStringLiteral("<li>packet, byte and connection counts for the displayed packets</li>"
                                 "<li>the busiest hosts and conversations, with their addresses</li>"
                                 "<li>names seen in the capture: DNS lookups, TLS server names and HTTP hosts</li>"
                                 "<li>Claude's web searches, which may include names from the capture</li>")
                : QStringLiteral("<li>this packet's decoded fields and payload, within your size limits</li>"
                                 "<li>facts about its IP addresses</li>"
                                 "<li>Claude's web searches, which may include names from the packet</li>"),
            [this]() { startModel(); }, // checks again, with the settings as they are now
            [this]() { setStatus(cloudCancelledMessage()); });
        return;
    }
    // Send through a backend built from the same settings the check approved.
    if (!rebuildBackend(settings))
        return;

    masking_ = setUpMasker(&masker_, settings);
    QString message = researchMessage(contextData_, wholeCapture_, guidance_);
    if (masking_) {
        message = masker_.mask(message);
        if (masker_.count() > 0)
            provider_->setText(provider_->text() + QStringLiteral("  ·  %1 address(es) hidden").arg(masker_.count()));
    }
    sent_->setMarkdown(sentToAiMarkdown(message, settings, masker_));
    messages_ = {
        {ChatMessage::Role::System, researchSystemPrompt()},
        {ChatMessage::Role::User, message},
    };
    for (CollapsibleSection *s : {stoodOut_, findings_, meaning_, nextSteps_, searches_, sources_, sent_}) {
        s->show();
        s->setState(CollapsibleSection::State::Waiting);
    }
    sent_->setState(CollapsibleSection::State::Idle);
    searches_->setState(CollapsibleSection::State::Idle);
    sources_->setState(CollapsibleSection::State::Idle);
    if (!guidance_.isEmpty())
        titleLabel_->setText(title_ + QStringLiteral("\nFocus: ") + guidance_);
    setPhase(Phase::Researching);
    render();

    backend_->research(messages_, callbacks(false), [this](const ChatResult &res) {
        const QList<CollapsibleSection *> main = {stoodOut_, findings_, meaning_, nextSteps_};
        if (res.ok) {
            reply_ = res.text;
            messages_.append({ChatMessage::Role::Assistant, res.text});
            setPhase(Phase::Idle);
            render();
            for (CollapsibleSection *s : main)
                s->setState(CollapsibleSection::State::Done);
            setStatus(QStringLiteral("Ask a follow-up or point Claude at something to look into."));
            input_->setFocus();
        } else {
            messages_.clear();
            setPhase(Phase::Idle);
            render();
            for (CollapsibleSection *s : main)
                s->setState(CollapsibleSection::State::Failed);
            setStatus(explainError(res.error), true);
        }
    });
}

void ResearchPanel::onAsk()
{
    const QString question = guard::singleLine(input_->text(), guard::kMaxRequestChars);
    if (question.isEmpty() || phase_ != Phase::Idle)
        return;

    // No research yet (or it failed): research with this as the focus.
    if (messages_.size() < 3) {
        input_->clear();
        if (wholeCapture_)
            researchDisplayedPackets(question);
        else
            researchSelectedPacket(question);
        return;
    }
    const Settings settings = Settings::load(ws::settingsFilePath());
    if (hidingSwitchedOn(masking_, settings)) {
        setStatus(hidingSwitchedOnMessage(QStringLiteral("Click Packet or Displayed packets")), true);
        return;
    }
    if (!CloudConsent::approved(settings)) {
        setStatus(QStringLiteral("SmartShark has a question before it sends anything:"));
        cloud_->ask(settings,
                    QStringLiteral("<li>your question</li><li>the conversation so far: the packet or capture data "
                                   "and the earlier answers</li><li>Claude's web searches</li>"),
                    [this]() { onAsk(); }, [this]() { setStatus(cloudCancelledMessage()); });
        return; // the question stays in the box until the user decides
    }
    if (!rebuildBackend(settings))
        return;
    input_->clear();

    messages_.append({ChatMessage::Role::User, masking_ ? masker_.mask(question) : question});
    followUps_.append({question, QString()});
    conversation_->show();
    conversation_->setExpanded(true);
    conversation_->setState(CollapsibleSection::State::Working);
    setPhase(Phase::Answering);
    render();

    backend_->research(messages_, callbacks(true), [this](const ChatResult &res) {
        if (res.ok) {
            followUps_.last().second = res.text;
            messages_.append({ChatMessage::Role::Assistant, res.text});
            conversation_->setState(CollapsibleSection::State::Done);
            setPhase(Phase::Idle);
            setStatus(QString());
        } else {
            messages_.removeLast();
            followUps_.last().second += QStringLiteral("\n\n*(No answer: %1)*").arg(explainError(res.error));
            conversation_->setState(CollapsibleSection::State::Failed);
            setPhase(Phase::Idle);
            setStatus(explainError(res.error), true);
        }
        render();
        input_->setFocus();
    });
}

void ResearchPanel::onStop()
{
    if (phase_ == Phase::Idle || phase_ == Phase::Counting)
        return;
    const Phase was = phase_;
    dropBackend(); // closes the connection, so nothing late can arrive
    if (was == Phase::Answering) {
        if (!followUps_.last().second.isEmpty())
            messages_.append({ChatMessage::Role::Assistant, followUps_.last().second});
        else
            messages_.removeLast();
        conversation_->setState(CollapsibleSection::State::Idle, QStringLiteral("stopped"));
    } else {
        if (!reply_.isEmpty() && messages_.size() == 2)
            messages_.append({ChatMessage::Role::Assistant, reply_});
        for (CollapsibleSection *s : {stoodOut_, findings_, meaning_, nextSteps_})
            s->setState(CollapsibleSection::State::Idle, QStringLiteral("stopped"));
    }
    setPhase(Phase::Idle);
    render();
    setStatus(QStringLiteral("Stopped."));
}

} // namespace smartshark
