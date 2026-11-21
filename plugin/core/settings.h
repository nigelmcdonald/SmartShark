/* settings.h
 *
 * SmartShark settings. Stored as an INI file in Wireshark's per-user
 * configuration folder. API keys are not stored here: see secret_store.h.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QHash>
#include <QString>
#include <QStringList>

#include "core/privacy.h"
#include "core/provider.h"

namespace smartshark {

struct ProviderSettings {
    QString baseUrl; // empty means the preset's default
    QString model;
};

struct Settings {
    // Online lookups of public IP addresses (reverse DNS, registry owner).
    enum class OnlineLookups { Ask, Always, Never };

    QString providerId = QStringLiteral("lmstudio");
    int timeoutSec = 120;
    OnlineLookups onlineLookups = OnlineLookups::Ask;
    QHash<QString, ProviderSettings> perProvider; // keyed by provider id

    // Privacy: how much of a packet is sent to the model.
    static constexpr int kMinTreeChars = 2000, kMaxTreeChars = 100000, kDefaultTreeChars = 24000;
    static constexpr int kMaxPayloadBytes = 16384, kDefaultPayloadBytes = 2048;
    int maxTreeChars = kDefaultTreeChars; // dissection text sent per packet
    int payloadBytes = kDefaultPayloadBytes; // decoded payload bytes sent per packet; 0 sends none
    AddressMasking masking = AddressMasking::Off; // Off or Mine: hide MAC addresses and this computer's public IPs
    // Cloud servers the user agreed to send packet data to (cloudApprovalKey()).
    QStringList cloudApproved;

    // Connection settings for the active provider. apiKey is left empty.
    ProviderConfig activeConfig() const;

    static Settings load(const QString &iniPath);
    bool save(const QString &iniPath) const;
};

} // namespace smartshark
