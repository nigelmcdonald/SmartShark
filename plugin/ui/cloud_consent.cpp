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
            : QStringLiteral("MAC addresses and your public IP addresses are replaced with placeholders such as "
                             "MAC-1 before sending. Host names are still sent.");
    text_->setText(QStringLiteral("<b>Send packet data to %1?</b><br>"
                                  "This server is not on your computer, so the company that runs it will receive:"
                                  "<ul style=\"margin-top:2px; margin-bottom:2px;\">%2</ul>"
                                  "%3<br>SmartShark asks once for each provider. To keep everything on your "
                                  "computer, choose a local server such as LM Studio or Ollama in Settings.")
                       .arg(who, whatIsSent, masking));
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

bool setUpMasker(AddressMasker *masker, const Settings &settings)
{
    masker->clear();
    if (settings.masking == AddressMasking::Off)
        return false;
    masker->setScope(settings.masking, localPublicAddresses());
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
