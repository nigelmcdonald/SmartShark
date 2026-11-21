/* capture_panel.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ui/capture_panel.h"

#include <QApplication>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QLocale>
#include <QPushButton>
#include <QScrollArea>
#include <QTimer>
#include <QVBoxLayout>

#include "core/capture_explainer.h"
#include "core/input_guard.h"
#include "core/settings.h"
#include "ui/backend_factory.h"
#include "ui/cloud_consent.h"
#include "ui/collapsible_section.h"
#include "ui/ip_lookup.h"
#include "ui/ws_services.h"

namespace smartshark {

namespace {
constexpr int kMaxStatsChars = 12000;
constexpr int kAddressesToDescribe = 12;
} // namespace

CapturePanel::CapturePanel(QWidget *parent) : QWidget(parent)
{
    lookup_ = new IpLookup(this);

    title_ = new QLabel(QStringLiteral("Questions about the whole capture"), this);
    title_->setTextFormat(Qt::PlainText);
    title_->setStyleSheet(QStringLiteral("font-weight: bold;"));
    title_->setWordWrap(true);
    provider_ = new QLabel(this);
    provider_->setTextFormat(Qt::PlainText);
    provider_->setStyleSheet(QStringLiteral("color: palette(mid);"));
    summarize_ = new QPushButton(QStringLiteral("Summarize"), this);
    summarize_->setToolTip(QStringLiteral("Count and summarise the packets the current display filter shows"));
    stop_ = new QPushButton(QStringLiteral("Stop"), this);
    stop_->setEnabled(false);

    auto *top = new QHBoxLayout;
    auto *titles = new QVBoxLayout;
    titles->addWidget(title_);
    titles->addWidget(provider_);
    top->addLayout(titles, 1);
    top->addWidget(summarize_, 0, Qt::AlignTop);
    top->addWidget(stop_, 0, Qt::AlignTop);

    status_ = new QLabel(QStringLiteral("Ask a question below, or click Summarize. SmartShark counts the displayed "
                                        "packets itself and the AI explains what the numbers mean."),
                         this);
    status_->setTextFormat(Qt::PlainText);
    status_->setWordWrap(true);
    cloud_ = new CloudConsent(this);

    answer_ =new CollapsibleSection(QStringLiteral("Answer"));
    answer_->hide();
    summary_ = new CollapsibleSection(captureSectionTitle(CaptureSection::Summary));
    talkers_ = new CollapsibleSection(captureSectionTitle(CaptureSection::Talkers));
    connections_ = new CollapsibleSection(captureSectionTitle(CaptureSection::Connections));
    notable_ = new CollapsibleSection(captureSectionTitle(CaptureSection::Notable));
    statistics_ = new CollapsibleSection(QStringLiteral("Statistics (counted by SmartShark)"));
    statistics_->setExpanded(false);
    sent_ = new CollapsibleSection(QStringLiteral("Sent to the AI"));
    sent_->setExpanded(false);
    sent_->hide();
    conversation_ = new CollapsibleSection(QStringLiteral("Your questions"));
    conversation_->hide();

    auto *content = new QWidget;
    auto *contentLayout = new QVBoxLayout(content);
    contentLayout->setContentsMargins(4, 4, 4, 4);
    for (CollapsibleSection *s : {answer_, summary_, talkers_, connections_, notable_, statistics_, sent_, conversation_})
        contentLayout->addWidget(s);
    contentLayout->addStretch();

    auto *scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scroll->setWidget(content);

    input_ = new QLineEdit(this);
    input_->setPlaceholderText(QStringLiteral("e.g. Which server is making the most connections?"));
    input_->setMaxLength(guard::kMaxRequestChars);
    input_->setClearButtonEnabled(true);
    ask_ = new QPushButton(QStringLiteral("Ask"), this);
    auto *askRow = new QHBoxLayout;
    askRow->addWidget(input_, 1);
    askRow->addWidget(ask_);

    auto *layout = new QVBoxLayout(this);
    layout->addLayout(top);
    layout->addWidget(status_);
    layout->addWidget(cloud_);
    layout->addWidget(scroll, 1);
    layout->addLayout(askRow);

    tick_ = new QTimer(this);
    tick_->setInterval(400);
    connect(tick_, &QTimer::timeout, this, &CapturePanel::onTick);
    connect(stop_, &QPushButton::clicked, this, &CapturePanel::onStop);
    connect(summarize_, &QPushButton::clicked, this, [this]() { analyse(); });
    connect(ask_, &QPushButton::clicked, this, &CapturePanel::onAsk);
    connect(input_, &QLineEdit::returnPressed, this, &CapturePanel::onAsk);

    for (CollapsibleSection *s : {summary_, talkers_, connections_, notable_, statistics_})
        s->hide();
    setPhase(Phase::Idle);
}

CapturePanel::~CapturePanel()
{
    lookup_->cancel();
    if (backend_)
        backend_->cancel();
}

void CapturePanel::dropBackend()
{
    if (backend_) {
        backend_->cancel();
        backend_->deleteLater();
        backend_ = nullptr;
    }
}

void CapturePanel::rebuildBackend(const Settings &settings)
{
    dropBackend();
    backend_ = makeBackend(settings, this);
    provider_->setText(QStringLiteral("Using %1").arg(backend_->describe()));
}

bool CapturePanel::mayFollowUp(const Settings &settings)
{
    if (CloudConsent::approved(settings))
        return true;
    setStatus(QStringLiteral("SmartShark has a question before it sends anything:"));
    cloud_->ask(
        settings,
        QStringLiteral("<li>your question</li><li>the conversation so far: the capture statistics and the earlier "
                       "answers</li>"),
        [this]() { onAsk(); }, [this]() { setStatus(cloudCancelledMessage()); });
    return false;
}

void CapturePanel::setStatus(const QString &text, bool error)
{
    status_->setText(text);
    status_->setStyleSheet(error ? QStringLiteral("color: #c0392b;") : QString());
}

void CapturePanel::setPhase(Phase phase)
{
    phase_ = phase;
    const bool busy = phase != Phase::Idle;
    stop_->setEnabled(busy && phase != Phase::Counting);
    summarize_->setEnabled(!busy);
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

void CapturePanel::onTick()
{
    static const char *const dots[] = {"", ".", "..", "..."};
    const QString d = QLatin1String(dots[frame_++ % 4]);
    QString text;
    switch (phase_) {
    case Phase::Counting: text = QStringLiteral("Counting packets%1").arg(d, -3); break;
    case Phase::LookingUp: text = QStringLiteral("Looking up addresses%1").arg(d, -3); break;
    default: text = QStringLiteral("Thinking%1").arg(d, -3); break;
    }
    if (reasoningChars_ > 0)
        text += QStringLiteral("  reasoning, about %1 words so far").arg(QLocale().toString(reasoningChars_ / 6));
    const qint64 secs = clock_.elapsed() / 1000;
    if (secs >= 2)
        text += QStringLiteral("  (%1 s)").arg(secs);
    setStatus(text);
}

void CapturePanel::scheduleRender()
{
    if (renderPending_)
        return;
    renderPending_ = true;
    QTimer::singleShot(80, this, &CapturePanel::render);
}

void CapturePanel::render()
{
    renderPending_ = false;
    const QMap<int, QString> parts = splitCaptureReply(masker_.unmask(reply_));

    answer_->setVisible(!question_.isEmpty());
    if (!question_.isEmpty()) {
        QString q = question_;
        q.replace(QLatin1Char('\\'), QStringLiteral("\\\\")).replace(QLatin1Char('*'), QStringLiteral("\\*"));
        answer_->setMarkdown(QStringLiteral("**You asked:** ") + q + QStringLiteral("\n\n") + parts.value(-1));
    }
    const QList<QPair<CaptureSection, CollapsibleSection *>> sections = {
        {CaptureSection::Summary, summary_}, {CaptureSection::Talkers, talkers_},
        {CaptureSection::Connections, connections_}, {CaptureSection::Notable, notable_},
    };
    for (const auto &s : sections)
        s.second->setMarkdown(parts.value(static_cast<int>(s.first)));

    if (phase_ == Phase::Thinking) {
        // The last section with text is the one being written.
        QList<CollapsibleSection *> order;
        QList<int> keys;
        if (!question_.isEmpty()) {
            order.append(answer_);
            keys.append(-1);
        }
        for (const auto &s : sections) {
            order.append(s.second);
            keys.append(static_cast<int>(s.first));
        }
        int writing = -1;
        for (int i = 0; i < order.size(); ++i) {
            if (!parts.value(keys[i]).isEmpty())
                writing = i;
        }
        for (int i = 0; i < order.size(); ++i) {
            order[i]->setState(i == writing   ? CollapsibleSection::State::Working
                               : i < writing ? CollapsibleSection::State::Done
                                             : CollapsibleSection::State::Waiting);
        }
    }

    if (!followUps_.isEmpty()) {
        QString md;
        for (const auto &qa : followUps_) {
            QString q = qa.first;
            q.replace(QLatin1Char('\\'), QStringLiteral("\\\\")).replace(QLatin1Char('*'), QStringLiteral("\\*"));
            md += QStringLiteral("**You:** ") + q + QStringLiteral("\n\n") + masker_.unmask(qa.second) +
                  QStringLiteral("\n\n---\n\n");
        }
        conversation_->setMarkdown(md);
        conversation_->show();
    }
}

void CapturePanel::analyse(const QString &question)
{
    if (phase_ == Phase::Counting)
        return; // Wireshark's re-scan keeps menus live; ignore a second start
    lookup_->cancel();
    rebuildBackend(Settings::load(ws::settingsFilePath()));

    question_ = guard::singleLine(question, guard::kMaxRequestChars);
    stats_ = CaptureStats();
    messages_.clear();
    reply_.clear();
    followUps_.clear();
    masker_.clear();
    masking_ = false;
    cloud_->hide();
    conversation_->hide();
    conversation_->setMarkdown(QString());
    sent_->setMarkdown(QString());
    sent_->hide();
    for (CollapsibleSection *s : {answer_, summary_, talkers_, connections_, notable_, statistics_}) {
        s->setMarkdown(QString());
        s->setState(CollapsibleSection::State::Idle);
    }

    setPhase(Phase::Counting);
    QApplication::processEvents(); // show "Counting..." before Wireshark's re-scan blocks the UI
    QString error;
    const bool ok = ws::collectDisplayedStats(&stats_, &displayFilter_, &error);
    setPhase(Phase::Idle);
    if (!ok) {
        setStatus(error, true);
        return;
    }
    title_->setText(displayFilter_.isEmpty()
                        ? QStringLiteral("All %1 packets").arg(QLocale().toString(stats_.packets()))
                        : QStringLiteral("%1 packets matching: %2")
                              .arg(QLocale().toString(stats_.packets()), guard::singleLine(displayFilter_, 200)));

    statistics_->setMarkdown(stats_.markdown());
    for (CollapsibleSection *s : {summary_, talkers_, connections_, notable_, statistics_})
        s->show();
    render();

    addresses_.clear();
    bool anyPublic = false;
    for (const QString &a : stats_.addresses(kAddressesToDescribe)) {
        IpFacts f = classifyAddress(a);
        if (f.kind == QLatin1String("Not an IP address"))
            continue;
        anyPublic = anyPublic || f.isPublic;
        addresses_.append(f);
    }

    // Online lookups only if the user already allowed them (asked in the Packet tab).
    if (anyPublic && Settings::load(ws::settingsFilePath()).onlineLookups == Settings::OnlineLookups::Always) {
        setPhase(Phase::LookingUp);
        lookup_->lookup(addresses_, [this](const QList<IpFacts> &facts) {
            if (phase_ != Phase::LookingUp)
                return;
            addresses_ = facts;
            startModel();
        });
        return;
    }
    startModel();
}

void CapturePanel::startModel()
{
    const Settings settings = Settings::load(ws::settingsFilePath());
    if (!CloudConsent::approved(settings)) {
        setPhase(Phase::Idle);
        setStatus(QStringLiteral("SmartShark has a question before it sends anything:"));
        cloud_->ask(
            settings,
            QStringLiteral("<li>packet, byte and connection counts for the displayed packets</li>"
                           "<li>the busiest hosts and conversations, with their addresses</li>"
                           "<li>names seen in the capture: DNS lookups, TLS server names and HTTP hosts</li>"
                           "<li>facts about the busiest IP addresses</li>"
                           "<li>your questions</li>"),
            [this]() { startModel(); }, // checks again, with the settings as they are now
            [this]() {
                for (CollapsibleSection *s : {answer_, summary_, talkers_, connections_, notable_})
                    s->setState(CollapsibleSection::State::Idle, QStringLiteral("not sent"));
                setStatus(cloudCancelledMessage());
            });
        return;
    }
    // Send through a backend built from the same settings the check approved.
    rebuildBackend(settings);

    masking_ = setUpMasker(&masker_, settings);
    QString message = captureMessage(stats_, addresses_, displayFilter_, question_, kMaxStatsChars);
    if (masking_) {
        message = masker_.mask(message);
        if (masker_.count() > 0)
            provider_->setText(provider_->text() + QStringLiteral("  ·  %1 address(es) hidden").arg(masker_.count()));
    }
    sent_->setMarkdown(sentToAiMarkdown(message, settings, masker_));
    sent_->show();
    messages_ = {
        {ChatMessage::Role::System, captureSystemPrompt()},
        {ChatMessage::Role::User, message},
    };
    setPhase(Phase::Thinking);
    render();

    backend_->chatStream(
        messages_,
        [this](const QString &delta) {
            reply_ += delta;
            scheduleRender();
        },
        [this](const ChatResult &res) {
            if (res.ok) {
                reply_ = res.text;
                messages_.append({ChatMessage::Role::Assistant, res.text});
                setPhase(Phase::Idle);
                render();
                for (CollapsibleSection *s : {answer_, summary_, talkers_, connections_, notable_})
                    s->setState(CollapsibleSection::State::Done);
                setStatus(QStringLiteral("Ask a follow-up question below. Click Summarize again after changing "
                                         "the display filter."));
            } else {
                messages_.clear();
                setPhase(Phase::Idle);
                render();
                for (CollapsibleSection *s : {answer_, summary_, talkers_, connections_, notable_})
                    s->setState(CollapsibleSection::State::Failed);
                setStatus(res.error, true);
            }
        },
        [this](const QString &reasoning) { reasoningChars_ += reasoning.size(); });
}

void CapturePanel::onAsk()
{
    const QString question = guard::singleLine(input_->text(), guard::kMaxRequestChars);
    if (question.isEmpty() || phase_ != Phase::Idle)
        return;

    // No analysis yet (or it failed): count the capture and answer as part of it.
    if (messages_.size() < 3) {
        input_->clear();
        analyse(question);
        return;
    }
    const Settings settings = Settings::load(ws::settingsFilePath());
    if (!mayFollowUp(settings))
        return; // the question stays in the box until the user decides
    rebuildBackend(settings);
    input_->clear();

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
                messages_.removeLast();
                followUps_.last().second += QStringLiteral("\n\n*(No answer: %1)*").arg(res.error);
                conversation_->setState(CollapsibleSection::State::Failed);
                setPhase(Phase::Idle);
                setStatus(res.error, true);
            }
            render();
            input_->setFocus();
        },
        [this](const QString &reasoning) { reasoningChars_ += reasoning.size(); });
}

void CapturePanel::onStop()
{
    if (phase_ == Phase::Idle || phase_ == Phase::Counting)
        return;
    const Phase was = phase_;
    lookup_->cancel();
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
        for (CollapsibleSection *s : {answer_, summary_, talkers_, connections_, notable_})
            s->setState(CollapsibleSection::State::Idle, QStringLiteral("stopped"));
    }
    setPhase(Phase::Idle);
    render();
    setStatus(QStringLiteral("Stopped."));
}

} // namespace smartshark
