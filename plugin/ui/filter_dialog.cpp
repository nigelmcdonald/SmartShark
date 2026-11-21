/* filter_dialog.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ui/filter_dialog.h"

#include <QApplication>
#include <QClipboard>
#include <QFontDatabase>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QLocale>
#include <QPushButton>
#include <QTimer>
#include <QVBoxLayout>

#include "core/filter_assistant.h"
#include "core/input_guard.h"
#include "core/openai_compat.h"
#include "core/secret_store.h"
#include "core/settings.h"
#include "ui/bridge.h"
#include "ui/settings_dialog.h"
#include "ui/ws_services.h"

namespace smartshark {

namespace {

const char *kErrorStyle = "color: #c0392b;";

// Button labels treat '&' as a shortcut marker; show it literally.
QString buttonText(QString text)
{
    return text.replace(QLatin1Char('&'), QStringLiteral("&&"));
}

QLabel *sectionLabel(const QString &text, QWidget *parent)
{
    auto *l = new QLabel(QStringLiteral("<b>%1</b>").arg(text.toHtmlEscaped()), parent);
    l->setContentsMargins(0, 6, 0, 0);
    return l;
}

} // namespace

FilterDialog::FilterDialog(QWidget *parent) : QDialog(parent)
{
    setWindowTitle(QStringLiteral("SmartShark: Generate Display Filter"));
    setMinimumWidth(640);

    auto *prompt = new QLabel(QStringLiteral("Describe the packets you want to see, in your own words:"), this);
    request_ = new QLineEdit(this);
    request_->setPlaceholderText(QStringLiteral("e.g. DNS queries for google.com, or TCP retransmissions to 10.0.0.5"));
    request_->setClearButtonEnabled(true);
    request_->setMaxLength(guard::kMaxRequestChars);
    // Enter in the request box generates (handled by returnPressed). No button
    // is the dialog's default: otherwise Enter would also click it, and the
    // second press would stop the request it just started.
    generate_ = new QPushButton(QStringLiteral("&Generate"), this);
    generate_->setAutoDefault(false);
    generate_->setMinimumWidth(90);
    auto *requestRow = new QHBoxLayout;
    requestRow->addWidget(request_, 1);
    requestRow->addWidget(generate_);

    // Clickable examples, so a new user never faces an empty box.
    examples_ = new QWidget(this);
    auto *exampleRow = new QHBoxLayout(examples_);
    exampleRow->setContentsMargins(0, 0, 0, 0);
    exampleRow->addWidget(new QLabel(QStringLiteral("Try:"), examples_));
    const QStringList examples = {
        QStringLiteral("DNS lookups"),
        QStringLiteral("web traffic to google.com"),
        QStringLiteral("TCP problems like retransmissions or resets"),
        QStringLiteral("what can I ask?"),
    };
    for (const QString &ex : examples) {
        auto *btn = new QPushButton(ex, examples_);
        btn->setFlat(true);
        btn->setAutoDefault(false);
        btn->setCursor(Qt::PointingHandCursor);
        btn->setStyleSheet(QStringLiteral("QPushButton { color: palette(link); padding: 0 4px; }"));
        connect(btn, &QPushButton::clicked, this, [this, ex]() {
            request_->setText(ex);
            generate();
        });
        exampleRow->addWidget(btn);
    }
    exampleRow->addStretch();

    auto *filterLabel = new QLabel(QStringLiteral("Display filter:"), this);
    filter_ = new QLineEdit(this);
    filter_->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    filter_->setPlaceholderText(QStringLiteral("The filter appears here, and you can edit it"));
    filter_->setMaxLength(guard::kMaxFilterChars);
    filter_->setEnabled(false); // until there is something to edit

    // Labels that show text from the model or a server are plain text, so
    // markup in a reply is shown as-is, never rendered.
    explanation_ = new QLabel(this);
    explanation_->setTextFormat(Qt::PlainText);
    explanation_->setWordWrap(true);
    explanation_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    explanation_->hide();

    validity_ = new QLabel(this);
    validity_->setTextFormat(Qt::PlainText);
    validity_->setWordWrap(true);
    validity_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    validity_->setStyleSheet(QString::fromLatin1(kErrorStyle));
    validity_->hide();

    status_ = new QLabel(this);
    status_->setTextFormat(Qt::PlainText);
    status_->setWordWrap(true);
    status_->setTextInteractionFlags(Qt::TextSelectableByMouse);

    // Help for requests that are not display filters. Filled by showAdvice().
    advicePanel_ = new QFrame(this);
    advicePanel_->setFrameShape(QFrame::StyledPanel);
    adviceLayout_ = new QVBoxLayout(advicePanel_);
    advicePanel_->hide();

    provider_ = new QLabel(this);
    provider_->setTextFormat(Qt::PlainText); // shows the model name, which comes from the server
    provider_->setStyleSheet(QStringLiteral("color: palette(mid);"));
    auto *settings = new QPushButton(QStringLiteral("S&ettings..."), this);
    settings->setAutoDefault(false);

    apply_ = new QPushButton(QStringLiteral("&Apply Filter"), this);
    apply_->setAutoDefault(false);
    copy_ = new QPushButton(QStringLiteral("&Copy"), this);
    copy_->setAutoDefault(false);
    auto *close = new QPushButton(QStringLiteral("Close"), this);
    close->setAutoDefault(false);

    auto *bottom = new QHBoxLayout;
    bottom->addWidget(provider_, 1);
    bottom->addWidget(settings);
    bottom->addSpacing(12);
    bottom->addWidget(copy_);
    bottom->addWidget(apply_);
    bottom->addWidget(close);

    auto *layout = new QVBoxLayout(this);
    layout->addWidget(prompt);
    layout->addLayout(requestRow);
    layout->addWidget(examples_);
    layout->addWidget(status_);
    layout->addSpacing(6);
    layout->addWidget(filterLabel);
    layout->addWidget(filter_);
    layout->addWidget(explanation_);
    layout->addWidget(validity_);
    layout->addWidget(advicePanel_);
    layout->addStretch();
    layout->addLayout(bottom);

    thinkingTimer_ = new QTimer(this);
    thinkingTimer_->setInterval(400);
    connect(thinkingTimer_, &QTimer::timeout, this, &FilterDialog::onThinkingTick);

    connect(generate_, &QPushButton::clicked, this, &FilterDialog::onGenerateOrStop);
    connect(request_, &QLineEdit::returnPressed, this, &FilterDialog::onGenerateOrStop);
    connect(filter_, &QLineEdit::textChanged, this, &FilterDialog::onFilterEdited);
    connect(filter_, &QLineEdit::returnPressed, this, &FilterDialog::onApply);
    connect(apply_, &QPushButton::clicked, this, &FilterDialog::onApply);
    connect(copy_, &QPushButton::clicked, this, &FilterDialog::onCopy);
    connect(settings, &QPushButton::clicked, this, &FilterDialog::onSettings);
    connect(close, &QPushButton::clicked, this, &QDialog::reject);

    onFilterEdited(QString());
    rebuildBackend();
    request_->setFocus();
}

FilterDialog::~FilterDialog()
{
    if (assistant_)
        assistant_->cancel();
    setBusy(false);
}

void FilterDialog::rebuildBackend()
{
    if (assistant_)
        assistant_->cancel();
    setBusy(false);
    assistant_.reset();
    delete backend_;

    const Settings settings = Settings::load(ws::settingsFilePath());
    ProviderConfig cfg = settings.activeConfig();
    cfg.apiKey = secrets::loadApiKey(cfg.providerId);

    backend_ = createBackend(cfg, this);
    assistant_ = std::make_unique<FilterAssistant>(backend_, &ws::validateDisplayFilter);
    assistant_->setProgressCallback([this](qsizetype chars) { reasoningChars_ += chars; });
    provider_->setText(QStringLiteral("Using %1").arg(backend_->describe()));

    if (cfg.model.isEmpty())
        setStatus(QStringLiteral("No model chosen yet. Click Settings to pick a provider and model."), true);
    else
        setStatus(QString());
}

void FilterDialog::setBusy(bool busy)
{
    if (busy == busy_)
        return;
    busy_ = busy;
    request_->setReadOnly(busy);
    generate_->setText(busy ? QStringLiteral("&Stop") : QStringLiteral("&Generate"));
    generate_->setToolTip(busy ? QStringLiteral("Stop waiting for the model") : QString());
    if (busy) {
        filter_->setEnabled(false);
        apply_->setEnabled(false);
        copy_->setEnabled(false);
        thinkingFrame_ = 0;
        reasoningChars_ = 0;
        thinkingClock_.start();
        onThinkingTick();
        thinkingTimer_->start();
    } else {
        thinkingTimer_->stop();
        filter_->setEnabled(!filter_->text().isEmpty());
        onFilterEdited(filter_->text()); // restores button states
    }
}

void FilterDialog::onThinkingTick()
{
    static const char *const dots[] = {"", ".", "..", "..."};
    const qint64 secs = thinkingClock_.elapsed() / 1000;
    QString text = QStringLiteral("Thinking%1").arg(QLatin1String(dots[thinkingFrame_ % 4]), -3);
    if (reasoningChars_ > 0) // about six characters per English word
        text += QStringLiteral("  reasoning, about %1 words so far").arg(QLocale().toString(reasoningChars_ / 6));
    if (secs >= 2)
        text += QStringLiteral("  (%1 s)").arg(secs);
    status_->setStyleSheet(QString());
    status_->setText(text);
    thinkingFrame_++;
}

void FilterDialog::setStatus(const QString &text, bool error)
{
    status_->setText(text);
    status_->setStyleSheet(error ? QString::fromLatin1(kErrorStyle) : QString());
}

void FilterDialog::setFilterText(const QString &text)
{
    filter_->setText(text);
    filter_->setEnabled(!text.isEmpty());
}

void FilterDialog::onGenerateOrStop()
{
    if (busy_) {
        // Cancel, then replace the backend too: deleting it closes its network
        // connection, so nothing from the old request can arrive afterwards.
        assistant_->cancel();
        rebuildBackend();
        setBusy(false);
        setStatus(QStringLiteral("Stopped."));
        return;
    }
    generate();
}

void FilterDialog::generate()
{
    const QString text = request_->text().trimmed();
    if (text.isEmpty())
        return;

    FilterRequest req;
    req.request = text;
    req.currentFilter = ws::currentDisplayFilter();

    clearAdvice();
    explanation_->hide();
    examples_->hide(); // results take their place; "what can I ask?" brings examples back
    setBusy(true);

    assistant_->generate(req, [this](const FilterOutcome &out) {
        setBusy(false);
        switch (out.status) {
        case FilterOutcome::Status::Ok:
            setFilterText(out.filter);
            if (!out.explanation.isEmpty()) {
                explanation_->setText(out.explanation);
                explanation_->show();
            }
            setStatus(out.attempts > 1
                          ? QStringLiteral("The model's first try did not compile, so it corrected itself "
                                           "(%1 attempts).")
                                .arg(out.attempts)
                          : QString());
            apply_->setFocus();
            break;
        case FilterOutcome::Status::Invalid:
            setFilterText(out.filter);
            setStatus(QStringLiteral("After %1 attempts the model still had no valid filter. "
                                     "You can fix it by hand, or describe what you want differently.")
                          .arg(out.attempts),
                      true);
            break;
        case FilterOutcome::Status::Unsupported:
            setStatus(QString());
            showAdvice(out.advice, false);
            break;
        case FilterOutcome::Status::Help:
            setStatus(QString());
            showAdvice(out.advice, true);
            break;
        case FilterOutcome::Status::Failed:
            setStatus(out.message, true);
            break;
        }
    });
}

void FilterDialog::clearAdvice()
{
    while (QLayoutItem *item = adviceLayout_->takeAt(0)) {
        if (QWidget *w = item->widget())
            w->deleteLater();
        delete item;
    }
    advicePanel_->hide();
}

void FilterDialog::showAdvice(const FilterAdvice &advice, bool help)
{
    clearAdvice();

    const QString title = help ? QStringLiteral("How to use this:")
                               : QStringLiteral("A display filter can't do this on its own.");
    QString reason = advice.reason;
    if (help && reason.isEmpty())
        reason = QStringLiteral("Describe in your own words which packets you want to see, and SmartShark "
                                "writes the display filter for you.");
    auto *headline = new QLabel(QStringLiteral("<b>%1</b> %2").arg(title.toHtmlEscaped(), reason.toHtmlEscaped()),
                                advicePanel_);
    headline->setWordWrap(true);
    adviceLayout_->addWidget(headline);

    if (!help) {
        // A question about the traffic ("which server makes the most
        // connections?") can be answered from the capture itself.
        auto *answer = new QPushButton(QStringLiteral("Answer this from the capture"), advicePanel_);
        answer->setAutoDefault(false);
        answer->setCursor(Qt::PointingHandCursor);
        answer->setToolTip(QStringLiteral("SmartShark counts the displayed packets and answers in its side panel"));
        const QString question = request_->text().trimmed();
        connect(answer, &QPushButton::clicked, this, [question]() { smartshark_ui_ask_capture(question); });
        auto *row = new QHBoxLayout;
        row->addWidget(answer);
        row->addStretch();
        adviceLayout_->addLayout(row);
    }

    if (!advice.whereToLook.isEmpty()) {
        adviceLayout_->addWidget(sectionLabel(QStringLiteral("Where to find it in Wireshark"), advicePanel_));
        for (const QString &tip : advice.whereToLook) {
            auto *l = new QLabel(QStringLiteral("• ") + tip, advicePanel_);
            l->setTextFormat(Qt::PlainText);
            l->setWordWrap(true);
            l->setTextInteractionFlags(Qt::TextSelectableByMouse);
            adviceLayout_->addWidget(l);
        }
    }

    if (!advice.filters.isEmpty()) {
        adviceLayout_->addWidget(sectionLabel(QStringLiteral("Filters that get you closer (click to use)"),
                                              advicePanel_));
        for (const SuggestedFilter &s : advice.filters) {
            auto *row = new QWidget(advicePanel_);
            auto *h = new QHBoxLayout(row);
            h->setContentsMargins(0, 0, 0, 0);
            auto *btn = new QPushButton(buttonText(s.filter), row);
            btn->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
            btn->setAutoDefault(false);
            btn->setCursor(Qt::PointingHandCursor);
            btn->setToolTip(QStringLiteral("Put this filter in the filter box"));
            const QString filter = s.filter;
            const QString description = s.description;
            connect(btn, &QPushButton::clicked, this, [this, filter, description]() {
                setFilterText(filter);
                explanation_->setText(description);
                explanation_->setVisible(!description.isEmpty());
                apply_->setFocus();
            });
            h->addWidget(btn);
            auto *desc = new QLabel(s.description, row);
            desc->setTextFormat(Qt::PlainText);
            desc->setWordWrap(true);
            h->addWidget(desc, 1);
            adviceLayout_->addWidget(row);
        }
    }

    if (!advice.askInstead.isEmpty()) {
        adviceLayout_->addWidget(sectionLabel(help ? QStringLiteral("For example (click to try)")
                                                   : QStringLiteral("Or ask this instead (click to try)"),
                                              advicePanel_));
        for (const QString &ask : advice.askInstead) {
            auto *btn = new QPushButton(buttonText(ask), advicePanel_);
            btn->setFlat(true);
            btn->setAutoDefault(false);
            btn->setCursor(Qt::PointingHandCursor);
            btn->setStyleSheet(QStringLiteral("QPushButton { text-align: left; color: palette(link); }"));
            connect(btn, &QPushButton::clicked, this, [this, ask]() {
                request_->setText(ask);
                generate();
            });
            adviceLayout_->addWidget(btn);
        }
    }

    advicePanel_->show();
}

void FilterDialog::onFilterEdited(const QString &text)
{
    if (text.trimmed().isEmpty()) {
        validity_->hide();
        filter_->setStyleSheet(QString());
        apply_->setEnabled(false);
        copy_->setEnabled(false);
        return;
    }
    QString error;
    const bool ok = ws::validateDisplayFilter(text, &error);
    // Same colours Wireshark's own filter bar uses for valid and invalid filters.
    filter_->setStyleSheet(ok ? QStringLiteral("QLineEdit { background-color: #afffaf; color: black; }")
                              : QStringLiteral("QLineEdit { background-color: #ffafaf; color: black; }"));
    validity_->setText(error);
    validity_->setVisible(!ok);
    apply_->setEnabled(ok && !busy_);
    copy_->setEnabled(!busy_);
}

void FilterDialog::onApply()
{
    const QString text = filter_->text().trimmed();
    if (text.isEmpty() || !ws::validateDisplayFilter(text, nullptr))
        return;
    ws::applyDisplayFilter(text);
    accept();
}

void FilterDialog::onCopy()
{
    QApplication::clipboard()->setText(filter_->text().trimmed());
    setStatus(QStringLiteral("Copied to the clipboard."));
}

void FilterDialog::onSettings()
{
    SettingsDialog dlg(this);
    if (dlg.exec() == QDialog::Accepted)
        rebuildBackend();
}

} // namespace smartshark
