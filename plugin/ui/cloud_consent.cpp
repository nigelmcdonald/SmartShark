/* cloud_consent.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ui/cloud_consent.h"

#include <QHBoxLayout>
#include <QHostAddress>
#include <QLabel>
#include <QNetworkInterface>
#include <QPushButton>
#include <QUrl>
#include <QVBoxLayout>

#include "core/ip_facts.h"
#include "core/privacy.h"
#include "ui/bridge.h"
#include "ui/collapsible_section.h"
#include "ui/ws_services.h"

namespace smartshark {

CloudConsent::CloudConsent(QWidget *parent) : QFrame(parent)
{
    setFrameShape(QFrame::StyledPanel);
    text_ = new QLabel(this);
    text_->setTextFormat(Qt::RichText);
    text_->setWordWrap(true);

    auto *send = new QPushButton(QStringLiteral("Send"), this);
    send->setToolTip(QStringLiteral("Send now, and don't ask again for this provider"));
    auto *settings = new QPushButton(QStringLiteral("Settings..."), this);
    settings->setToolTip(QStringLiteral("Choose a local server, or send less (Tools > SmartShark > Settings)"));
    auto *cancel = new QPushButton(QStringLiteral("Cancel"), this);
    cancel->setToolTip(QStringLiteral("Send nothing"));

    auto *buttons = new QHBoxLayout;
    buttons->addStretch();
    buttons->addWidget(send);
    buttons->addWidget(settings);
    buttons->addWidget(cancel);
    auto *layout = new QVBoxLayout(this);
    layout->addWidget(text_);
    layout->addLayout(buttons);
    hide();

    connect(send, &QPushButton::clicked, this, [this]() {
        hide();
        Settings s = Settings::load(ws::settingsFilePath());
        if (!s.cloudApproved.contains(approvalKey_))
            s.cloudApproved.append(approvalKey_);
        s.save(ws::settingsFilePath());
        const auto proceed = proceed_; // proceed() may call ask(), which replaces proceed_
        if (proceed)
            proceed();
    });
    connect(settings, &QPushButton::clicked, this, [this]() {
        smartshark_ui_settings(); // modal
        hide();
        const auto proceed = proceed_;
        if (proceed)
            proceed(); // asks again if still needed, with the new settings
    });
    connect(cancel, &QPushButton::clicked, this, [this]() {
        hide();
        const auto cancelled = cancelled_;
        if (cancelled)
            cancelled();
    });
}

bool CloudConsent::approved(const Settings &settings)
{
    const ProviderConfig cfg = settings.activeConfig();
    return isLocalServer(cfg.baseUrl) || settings.cloudApproved.contains(cloudApprovalKey(cfg));
}

void CloudConsent::ask(const Settings &settings, const QString &whatIsSent, std::function<void()> proceed,
                       std::function<void()> cancelled)
{
    const ProviderConfig cfg = settings.activeConfig();
    approvalKey_ = cloudApprovalKey(cfg);
    proceed_ = std::move(proceed);
    cancelled_ = std::move(cancelled);

    const ProviderPreset *preset = findPreset(cfg.providerId);
    const QString host = serverHost(cfg.baseUrl).toHtmlEscaped();
    const QString who = preset && preset->id != QLatin1String("custom")
                            ? QStringLiteral("%1 (%2)").arg(preset->displayName.toHtmlEscaped(), host)
                            : host;
    const QString masking =
        settings.masking == AddressMasking::Off
            ? QStringLiteral("IP and MAC addresses are sent as they are. You can hide your own addresses in Settings.")
            : QStringLiteral("MAC addresses, this computer's public IP addresses (those on its network "
                             "adapters) and any addresses you added in Settings are replaced with placeholders "
                             "such as MAC-1 before sending. Host names are still sent.");
    const QString unencrypted =
        QUrl(cfg.baseUrl.trimmed()).scheme() == QLatin1String("http")
            ? QStringLiteral("<br><b>This address uses http, so the data travels unencrypted</b> and anyone on the "
                             "way can read it.")
            : QString();
    text_->setText(QStringLiteral("<b>Send packet data to %1?</b><br>"
                                  "This server is not on your computer or local network, so whoever runs it will "
                                  "receive:"
                                  "<ul style=\"margin-top:2px; margin-bottom:2px;\">%2</ul>"
                                  "%3%4<br>SmartShark asks once for each provider. To keep everything on your "
                                  "computer, choose a local server such as LM Studio or Ollama in Settings.")
                       .arg(who, whatIsSent, masking, unencrypted));
    show();
}

QString cloudCancelledMessage()
{
    return QStringLiteral("Nothing was sent. To keep packet data on your computer, choose a local server (LM Studio, "
                          "Ollama or another) in Tools > SmartShark > Settings, then try again.");
}

QStringList localPublicAddresses()
{
    QStringList out;
    for (const QHostAddress &a : QNetworkInterface::allAddresses()) {
        const QString n = normaliseAddress(a.toString());
        if (!n.isEmpty() && classifyAddress(n).isPublic && !out.contains(n))
            out.append(n);
    }
    return out;
}

// This computer's public adapter addresses plus the ones the user added.
static QStringList addressesToHide(const Settings &settings)
{
    QStringList out = localPublicAddresses();
    for (const QString &a : settings.alsoHide) {
        if (!out.contains(a))
            out.append(a);
    }
    return out;
}

QStringList ownAddressesToSkip(const Settings &settings)
{
    return settings.masking == AddressMasking::Off ? QStringList() : addressesToHide(settings);
}

bool hidingSwitchedOn(bool conversationMasked, const Settings &settings)
{
    return !conversationMasked && settings.masking != AddressMasking::Off;
}

QString hidingSwitchedOnMessage(const QString &startAgain)
{
    return QStringLiteral("Address hiding was switched on after this conversation started, so the packet data it "
                          "already holds still has the real addresses. Nothing was sent. %1 to start again with "
                          "addresses hidden.")
        .arg(startAgain);
}

bool setUpMasker(AddressMasker *masker, const Settings &settings)
{
    masker->clear();
    if (settings.masking == AddressMasking::Off)
        return false;
    masker->setScope(settings.masking, addressesToHide(settings));
    return true;
}

QString sentToAiMarkdown(const QString &message, const Settings &settings, const AddressMasker &masker)
{
    QString md;
    switch (settings.masking) {
    case AddressMasking::Off:
        md = QStringLiteral("Address hiding is off.");
        break;
    case AddressMasking::Mine:
    case AddressMasking::All:
        md = masker.count() == 0
                 ? QStringLiteral("Address hiding is on, but there was nothing to hide here: no MAC addresses and "
                                  "none of your public addresses.")
                 : QStringLiteral("**%1 address(es) hidden.** The AI saw the placeholders below; this panel "
                                  "shows the real addresses.")
                       .arg(masker.count());
        break;
    }
    md += QStringLiteral(" The model received this, after its instructions:\n\n") + markdownCodeBlock(message);
    return md;
}

} // namespace smartshark
