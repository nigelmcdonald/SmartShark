/* settings.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "core/settings.h"

#include <QRegularExpression>
#include <QSettings>

namespace smartshark {

ProviderConfig Settings::activeConfig() const
{
    ProviderConfig cfg;
    cfg.providerId = providerId;
    cfg.timeoutSec = timeoutSec;
    const ProviderPreset *preset = findPreset(providerId);
    if (preset)
        cfg.api = preset->api;
    const ProviderSettings ps = perProvider.value(providerId);
    cfg.baseUrl = !ps.baseUrl.trimmed().isEmpty() ? ps.baseUrl.trimmed() : (preset ? preset->baseUrl : QString());
    cfg.model = ps.model.trimmed();
    return cfg;
}

QStringList Settings::parseAddressList(const QString &text, QString *bad)
{
    QStringList out;
    static const QRegularExpression separators(QStringLiteral("[,;\\s]+"));
    for (const QString &part : text.split(separators, Qt::SkipEmptyParts)) {
        const QString n = normaliseAddress(part);
        if (n.isEmpty()) {
            if (bad && bad->isEmpty())
                *bad = part;
            continue;
        }
        if (!out.contains(n) && out.size() < 50)
            out.append(n);
    }
    return out;
}

QString Settings::baseUrlFor(const QString &id) const
{
    const ProviderPreset *preset = findPreset(id);
    const QString url = perProvider.value(id).baseUrl.trimmed();
    return !url.isEmpty() ? url : (preset ? preset->baseUrl : QString());
}

bool Settings::keyMayBeSentTo(const QString &id, const QString &baseUrl) const
{
    QString bound = perProvider.value(id).keyHost;
    if (bound.isEmpty()) {
        const ProviderPreset *preset = findPreset(id);
        bound = preset ? serverHost(preset->baseUrl) : QString();
    }
    const QString host = serverHost(baseUrl);
    return !bound.isEmpty() && host == bound;
}

Settings Settings::load(const QString &iniPath)
{
    Settings s;
    QSettings ini(iniPath, QSettings::IniFormat);
    const QString provider = ini.value(QStringLiteral("general/provider")).toString();
    if (findPreset(provider))
        s.providerId = provider;
    const int timeout = ini.value(QStringLiteral("general/timeout_sec"), s.timeoutSec).toInt();
    if (timeout >= 5 && timeout <= 1800)
        s.timeoutSec = timeout;
    const QString lookups = ini.value(QStringLiteral("general/online_ip_lookups")).toString();
    if (lookups == QLatin1String("always"))
        s.onlineLookups = OnlineLookups::Always;
    else if (lookups == QLatin1String("never"))
        s.onlineLookups = OnlineLookups::Never;

    const int tree = ini.value(QStringLiteral("privacy/max_tree_chars"), s.maxTreeChars).toInt();
    if (tree >= kMinTreeChars && tree <= kMaxTreeChars)
        s.maxTreeChars = tree;
    const int payload = ini.value(QStringLiteral("privacy/payload_bytes"), s.payloadBytes).toInt();
    if (payload >= 0 && payload <= kMaxPayloadBytes)
        s.payloadBytes = payload;
    const QString mask = ini.value(QStringLiteral("privacy/mask_addresses")).toString().toLower();
    if (mask == QLatin1String("mine") || mask == QLatin1String("true") || mask == QLatin1String("all"))
        s.masking = AddressMasking::Mine; // "true" and "all": earlier 3e builds
    s.alsoHide = parseAddressList(ini.value(QStringLiteral("privacy/also_hide")).toStringList().join(QLatin1Char(',')));
    for (const QString &k : ini.value(QStringLiteral("privacy/cloud_approved")).toStringList()) {
        if (!k.trimmed().isEmpty() && !s.cloudApproved.contains(k.trimmed()))
            s.cloudApproved.append(k.trimmed());
    }

    for (const ProviderPreset &p : providerPresets()) {
        ini.beginGroup(QStringLiteral("provider.") + p.id);
        ProviderSettings ps;
        ps.baseUrl = ini.value(QStringLiteral("base_url")).toString();
        ps.model = ini.value(QStringLiteral("model")).toString();
        ps.keyHost = ini.value(QStringLiteral("key_host")).toString().trimmed().toLower();
        ini.endGroup();
        if (!ps.baseUrl.isEmpty() || !ps.model.isEmpty() || !ps.keyHost.isEmpty())
            s.perProvider.insert(p.id, ps);
    }

    return s;
}

bool Settings::save(const QString &iniPath) const
{
    QSettings ini(iniPath, QSettings::IniFormat);
    ini.setValue(QStringLiteral("general/provider"), providerId);
    ini.setValue(QStringLiteral("general/timeout_sec"), timeoutSec);
    ini.setValue(QStringLiteral("general/online_ip_lookups"),
                 onlineLookups == OnlineLookups::Always  ? QStringLiteral("always")
                 : onlineLookups == OnlineLookups::Never ? QStringLiteral("never")
                                                         : QStringLiteral("ask"));
    ini.setValue(QStringLiteral("privacy/max_tree_chars"), maxTreeChars);
    ini.setValue(QStringLiteral("privacy/payload_bytes"), payloadBytes);
    ini.setValue(QStringLiteral("privacy/mask_addresses"),
                 masking == AddressMasking::Off ? QStringLiteral("off") : QStringLiteral("mine"));
    ini.remove(QStringLiteral("privacy/my_addresses")); // field of an earlier 3e build
    ini.setValue(QStringLiteral("privacy/also_hide"), alsoHide);
    ini.setValue(QStringLiteral("privacy/cloud_approved"), cloudApproved);
    for (auto it = perProvider.cbegin(); it != perProvider.cend(); ++it) {
        ini.beginGroup(QStringLiteral("provider.") + it.key());
        ini.setValue(QStringLiteral("base_url"), it.value().baseUrl);
        ini.setValue(QStringLiteral("model"), it.value().model);
        ini.setValue(QStringLiteral("key_host"), it.value().keyHost);
        ini.endGroup();
    }
    ini.sync();
    return ini.status() == QSettings::NoError;
}

} // namespace smartshark
