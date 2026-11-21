/* settings_dialog.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ui/settings_dialog.h"

#include <QAction>
#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QSpinBox>
#include <QStyle>
#include <QVBoxLayout>

#include "core/input_guard.h"
#include "core/http_backend.h"
#include "core/secret_store.h"
#include "ui/ws_services.h"

namespace smartshark {

SettingsDialog::SettingsDialog(QWidget *parent) : QDialog(parent)
{
    setWindowTitle(QStringLiteral("SmartShark Settings"));
    setMinimumWidth(520);

    provider_ = new QComboBox(this);
    for (const ProviderPreset &p : providerPresets())
        provider_->addItem(p.displayName, p.id);

    baseUrl_ = new QLineEdit(this);
    baseUrl_->setMaxLength(2048);
    baseUrl_->setPlaceholderText(QStringLiteral("https://example.com/v1"));

    apiKey_ = new QLineEdit(this);
    apiKey_->setMaxLength(guard::kMaxApiKeyChars);
    apiKey_->setEchoMode(QLineEdit::Password);
    QAction *reveal = apiKey_->addAction(style()->standardIcon(QStyle::SP_FileDialogContentsView),
                                         QLineEdit::TrailingPosition);
    reveal->setToolTip(QStringLiteral("Show or hide the key"));
    connect(reveal, &QAction::triggered, this, [this]() {
        apiKey_->setEchoMode(apiKey_->echoMode() == QLineEdit::Password ? QLineEdit::Normal : QLineEdit::Password);
    });

    keyHelp_ = new QLabel(this);
    keyHelp_->setOpenExternalLinks(true);
    keyHelp_->setWordWrap(true);

    model_ = new QComboBox(this);
    model_->setEditable(true);
    model_->setInsertPolicy(QComboBox::NoInsert);
    model_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    model_->lineEdit()->setPlaceholderText(QStringLiteral("Click Fetch models, or type a model name"));
    model_->lineEdit()->setMaxLength(guard::kMaxModelNameChars);
    fetchModels_ = new QPushButton(QStringLiteral("Fetch models"), this);
    fetchModels_->setToolTip(QStringLiteral("Ask the server which models it offers. Also tests the connection."));
    auto *modelRow = new QHBoxLayout;
    modelRow->addWidget(model_, 1);
    modelRow->addWidget(fetchModels_);

    timeout_ = new QSpinBox(this);
    timeout_->setRange(5, 1800);
    timeout_->setSuffix(QStringLiteral(" s"));
    timeout_->setToolTip(QStringLiteral("How long to wait for a reply. Local models on a CPU can be slow."));

    status_ = new QLabel(this);
    status_->setTextFormat(Qt::PlainText); // may show text from a server
    status_->setWordWrap(true);
    status_->setTextInteractionFlags(Qt::TextSelectableByMouse);

    auto *form = new QFormLayout;
    form->addRow(QStringLiteral("Provider:"), provider_);
    form->addRow(QStringLiteral("Server URL:"), baseUrl_);
    form->addRow(QStringLiteral("API key:"), apiKey_);
    form->addRow(QString(), keyHelp_);
    form->addRow(QStringLiteral("Model:"), modelRow);
    form->addRow(QStringLiteral("Timeout:"), timeout_);

    // Privacy: what packet explanations send, and online lookups.
    treeChars_ = new QSpinBox(this);
    treeChars_->setRange(Settings::kMinTreeChars, Settings::kMaxTreeChars);
    treeChars_->setSingleStep(1000);
    treeChars_->setGroupSeparatorShown(true);
    treeChars_->setSuffix(QStringLiteral(" characters"));
    treeChars_->setToolTip(QStringLiteral("How much of a packet's decoded fields is sent when explaining it. "
                                          "Less is more private and faster, but the AI sees less."));
    payloadBytes_ = new QSpinBox(this);
    payloadBytes_->setRange(0, Settings::kMaxPayloadBytes);
    payloadBytes_->setSingleStep(256);
    payloadBytes_->setGroupSeparatorShown(true);
    payloadBytes_->setSuffix(QStringLiteral(" bytes"));
    payloadBytes_->setSpecialValueText(QStringLiteral("None"));
    payloadBytes_->setToolTip(QStringLiteral("How many bytes of decoded, reassembled or decrypted payload are sent "
                                             "per packet. None sends no payload data."));
    masking_ = new QCheckBox(QStringLiteral("Hide MAC addresses and my public IP"), this);
    masking_->setToolTip(QStringLiteral(
        "The AI sees placeholders such as MAC-1 and HOST-1 instead; the panel shows the real addresses. Covers MAC "
        "addresses in the forms Wireshark writes them, and the public addresses on this computer's network adapters "
        "(behind a home router, your public IPv4 address is usually the router's: add it below). Other "
        "addresses help the AI and identify no one. Check the \"Sent to the AI\" section to see what went out."));
    alsoHide_ = new QLineEdit(this);
    alsoHide_->setMaxLength(2000);
    alsoHide_->setPlaceholderText(QStringLiteral("e.g. your router's public IP"));
    alsoHide_->setToolTip(QStringLiteral(
        "More IP addresses to hide, separated by commas. Behind a home router your public IPv4 address belongs to "
        "the router, so SmartShark can't see it on this computer. Your router's status page shows it, or search "
        "\"what is my IP\" in a browser."));
    connect(masking_, &QCheckBox::toggled, alsoHide_, &QWidget::setEnabled);
    lookups_ = new QComboBox(this);
    lookups_->addItem(QStringLiteral("Ask first"), static_cast<int>(Settings::OnlineLookups::Ask));
    lookups_->addItem(QStringLiteral("Always"), static_cast<int>(Settings::OnlineLookups::Always));
    lookups_->addItem(QStringLiteral("Never"), static_cast<int>(Settings::OnlineLookups::Never));
    lookups_->setToolTip(QStringLiteral("Look up who owns public IP addresses (rdap.org) and their DNS names. "
                                        "Only the addresses are sent, never packet data."));
    forgetApprovals_ = new QPushButton(this);
    forgetApprovals_->setToolTip(QStringLiteral("Ask again before packet data next goes to a cloud provider"));
    connect(forgetApprovals_, &QPushButton::clicked, this, [this]() {
        settings_.cloudApproved.clear();
        updateForgetButton();
    });

    auto *privacyNote = new QLabel(QStringLiteral(
        "Servers on your computer or local network keep packet data with you. Before packet data first goes "
        "to a cloud provider, SmartShark asks."), this);
    privacyNote->setWordWrap(true);
    auto *forgetRow = new QHBoxLayout;
    forgetRow->addWidget(forgetApprovals_);
    forgetRow->addStretch();

    auto *privacy = new QGroupBox(QStringLiteral("Privacy"), this);
    auto *privacyForm = new QFormLayout(privacy);
    privacyForm->addRow(privacyNote);
    privacyForm->addRow(QStringLiteral("Packet fields sent:"), treeChars_);
    privacyForm->addRow(QStringLiteral("Payload sent:"), payloadBytes_);
    privacyForm->addRow(masking_);
    privacyForm->addRow(QStringLiteral("Also hide:"), alsoHide_);
    privacyForm->addRow(QStringLiteral("Online IP lookups:"), lookups_);
    privacyForm->addRow(forgetRow);

    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel, this);
    connect(buttons, &QDialogButtonBox::accepted, this, &SettingsDialog::onAccepted);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);

    auto *layout = new QVBoxLayout(this);
    layout->addLayout(form);
    layout->addWidget(privacy);
    layout->addWidget(status_);
    layout->addStretch();
    layout->addWidget(buttons);

    connect(provider_, qOverload<int>(&QComboBox::currentIndexChanged), this, &SettingsDialog::onProviderChanged);
    connect(fetchModels_, &QPushButton::clicked, this, &SettingsDialog::onFetchModels);

    load();
}

QString SettingsDialog::currentProviderId() const
{
    return provider_->currentData().toString();
}

void SettingsDialog::load()
{
    settings_ = Settings::load(ws::settingsFilePath());
    keyCache_.clear();
    timeout_->setValue(settings_.timeoutSec);
    treeChars_->setValue(settings_.maxTreeChars);
    payloadBytes_->setValue(settings_.payloadBytes);
    masking_->setChecked(settings_.masking != AddressMasking::Off);
    alsoHide_->setText(settings_.alsoHide.join(QStringLiteral(", ")));
    alsoHide_->setEnabled(masking_->isChecked());
    lookups_->setCurrentIndex(qMax(0, lookups_->findData(static_cast<int>(settings_.onlineLookups))));
    updateForgetButton();
    shownProvider_.clear();
    const int idx = provider_->findData(settings_.providerId);
    const QSignalBlocker block(provider_);
    provider_->setCurrentIndex(idx >= 0 ? idx : 0);
    showProvider(currentProviderId());
}

void SettingsDialog::storeFormIntoCache(const QString &providerId)
{
    if (providerId.isEmpty())
        return;
    const ProviderPreset *preset = findPreset(providerId);
    ProviderSettings ps = settings_.perProvider.value(providerId); // keeps keyHost
    const QString url = baseUrl_->text().trimmed();
    ps.baseUrl = (preset && url == preset->baseUrl) ? QString() : url; // store only overrides
    ps.model = model_->currentText().trimmed();
    settings_.perProvider.insert(providerId, ps);
    keyCache_.insert(providerId, apiKey_->text().trimmed());
}

void SettingsDialog::showProvider(const QString &providerId)
{
    shownProvider_ = providerId;
    const ProviderPreset *preset = findPreset(providerId);
    const ProviderSettings ps = settings_.perProvider.value(providerId);

    baseUrl_->setText(!ps.baseUrl.isEmpty() ? ps.baseUrl : (preset ? preset->baseUrl : QString()));

    if (!keyCache_.contains(providerId))
        keyCache_.insert(providerId, secrets::loadApiKey(providerId));
    apiKey_->setText(keyCache_.value(providerId));

    if (preset && preset->isLocal) {
        apiKey_->setPlaceholderText(QStringLiteral("Not needed for a local server"));
        keyHelp_->setText(QStringLiteral("A server you run yourself. Packet data stays on this computer, or on your "
                                         "local network if the address above points to another machine there."));
    } else if (preset && preset->api == ApiKind::AnthropicMessages) {
        apiKey_->setPlaceholderText(QStringLiteral("Required: a Claude API key (starts with sk-ant-)"));
        keyHelp_->setText(QStringLiteral(
            "Needs an API key from the Claude Console, billed per use. A Claude Pro or Max subscription "
            "can't be used: Anthropic doesn't allow other apps to sign in with one. Some plans include monthly "
            "API credits you can claim for the Console (claude.ai, Settings &gt; Billing). "
            "<a href=\"%1\">Get an API key</a>. Stored in Windows Credential Manager. "
            "Packet data you send is processed by Anthropic.")
                              .arg(preset->keyHelpUrl));
    } else if (preset && preset->needsApiKey) {
        apiKey_->setPlaceholderText(QStringLiteral("Required"));
        keyHelp_->setText(QStringLiteral("Stored in Windows Credential Manager, not in a file. "
                                         "<a href=\"%1\">Get an API key</a>. "
                                         "Packet data you send is processed by %2.")
                              .arg(preset->keyHelpUrl, preset->displayName));
    } else {
        apiKey_->setPlaceholderText(QStringLiteral("Optional"));
        keyHelp_->setText(QStringLiteral("Stored in Windows Credential Manager, not in a file."));
    }

    model_->clear();
    if (!ps.model.isEmpty())
        model_->addItem(ps.model);
    model_->setEditText(ps.model);
    setStatus(QString());
}

void SettingsDialog::onProviderChanged(int)
{
    storeFormIntoCache(shownProvider_);
    showProvider(currentProviderId());
}

void SettingsDialog::setStatus(const QString &text, bool error)
{
    status_->setText(text);
    status_->setStyleSheet(error ? QStringLiteral("color: #c0392b;") : QString());
}

void SettingsDialog::updateForgetButton()
{
    const int n = static_cast<int>(settings_.cloudApproved.size());
    forgetApprovals_->setText(n == 0 ? QStringLiteral("No cloud providers approved")
                                     : QStringLiteral("Forget cloud approvals (%1)").arg(n));
    forgetApprovals_->setEnabled(n > 0);
}

void SettingsDialog::onFetchModels()
{
    ProviderConfig cfg;
    cfg.providerId = currentProviderId();
    cfg.baseUrl = baseUrl_->text().trimmed();
    cfg.apiKey = apiKey_->text().trimmed();
    cfg.timeoutSec = qMin(timeout_->value(), 30);
    const QString problem = validateForm();
    if (!problem.isEmpty()) {
        setStatus(problem, true);
        return;
    }
    cfg.apiKey = guard::cleanApiKey(cfg.apiKey, nullptr);
    if (!confirmKeyHost(cfg.providerId, cfg.baseUrl, cfg.apiKey))
        return;

    delete probe_;
    if (const ProviderPreset *preset = findPreset(cfg.providerId))
        cfg.api = preset->api;
    probe_ = createBackend(cfg, this);
    fetchModels_->setEnabled(false);
    setStatus(QStringLiteral("Contacting %1 ...").arg(cfg.baseUrl));

    probe_->listModels([this](const ModelListResult &res) {
        fetchModels_->setEnabled(true);
        if (!res.ok) {
            setStatus(res.error, true);
            return;
        }
        if (res.models.isEmpty()) {
            setStatus(QStringLiteral("Connected, but the server lists no models. "
                                     "For LM Studio or Ollama, download or load a model first."),
                      true);
            return;
        }
        const QString keep = model_->currentText().trimmed();
        model_->clear();
        model_->addItems(res.models);
        model_->setEditText(res.models.contains(keep) ? keep : res.models.first());
        setStatus(QStringLiteral("Connected. Models available: %1.").arg(res.models.size()));
    });
}

bool SettingsDialog::save()
{
    storeFormIntoCache(currentProviderId());
    settings_.providerId = currentProviderId();
    settings_.timeoutSec = timeout_->value();
    settings_.maxTreeChars = treeChars_->value();
    settings_.payloadBytes = payloadBytes_->value();
    settings_.masking = masking_->isChecked() ? AddressMasking::Mine : AddressMasking::Off;
    QString bad;
    settings_.alsoHide = Settings::parseAddressList(alsoHide_->text(), &bad);
    if (!bad.isEmpty()) {
        setStatus(QStringLiteral("\"%1\" under Also hide is not an IP address. Enter addresses such as 203.0.113.7, "
                                 "separated by commas.")
                      .arg(bad.left(60)),
                  true);
        return false;
    }
    settings_.onlineLookups = static_cast<Settings::OnlineLookups>(lookups_->currentData().toInt());

    for (auto it = keyCache_.cbegin(); it != keyCache_.cend(); ++it) {
        if (!confirmKeyHost(it.key(), settings_.baseUrlFor(it.key()), it.value()))
            return false;
    }
    for (auto it = keyCache_.cbegin(); it != keyCache_.cend(); ++it) {
        if (it.value() != secrets::loadApiKey(it.key()) && !secrets::saveApiKey(it.key(), it.value())) {
            setStatus(QStringLiteral("Could not save the API key to Windows Credential Manager."), true);
            return false;
        }
    }
    if (!settings_.save(ws::settingsFilePath())) {
        setStatus(QStringLiteral("Could not write %1.").arg(ws::settingsFilePath()), true);
        return false;
    }
    return true;
}

bool SettingsDialog::confirmKeyHost(const QString &providerId, const QString &baseUrl, const QString &key)
{
    const QString host = serverHost(baseUrl);
    ProviderSettings ps = settings_.perProvider.value(providerId);
    if (key.isEmpty() || ps.keyHost == host)
        return true;
    // A key typed in this session belongs to the server shown with it. A key
    // loaded from Credential Manager was saved for another server: ask.
    if (key == secrets::loadApiKey(providerId) && !settings_.keyMayBeSentTo(providerId, baseUrl)) {
        QString was = ps.keyHost;
        if (was.isEmpty())
            if (const ProviderPreset *preset = findPreset(providerId))
                was = serverHost(preset->baseUrl);
        const auto answer = QMessageBox::question(
            this, QStringLiteral("Send your saved API key?"),
            QStringLiteral("Your saved API key was entered for %1. Send it to %2?\n\n"
                           "Only say Yes if you trust %2 with the key. Otherwise choose No and enter the key "
                           "for the new server.")
                .arg(was.isEmpty() ? QStringLiteral("another server") : was, host),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (answer != QMessageBox::Yes) {
            setStatus(QStringLiteral("The saved key was not sent. Enter the API key for %1, or change the server "
                                     "address back.")
                          .arg(host),
                      true);
            return false;
        }
    }
    ps.keyHost = host;
    settings_.perProvider.insert(providerId, ps);
    return true;
}

QString SettingsDialog::validateForm() const
{
    QString error;
    const QString key = guard::cleanApiKey(apiKey_->text(), &error);
    if (!error.isEmpty())
        return error;
    const QString urlProblem = guard::checkBaseUrl(baseUrl_->text(), !key.isEmpty());
    if (!urlProblem.isEmpty())
        return urlProblem;
    guard::cleanModelName(model_->currentText(), &error);
    return error;
}

void SettingsDialog::onAccepted()
{
    const QString problem = validateForm();
    if (!problem.isEmpty()) {
        setStatus(problem, true);
        return;
    }
    if (model_->currentText().trimmed().isEmpty()) {
        setStatus(QStringLiteral("Choose a model (click Fetch models)."), true);
        return;
    }
    if (save())
        accept();
}

} // namespace smartshark
