/* privacy.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "core/privacy.h"

#include <QHostAddress>
#include <QRegularExpression>
#include <QUrl>

#include "core/input_guard.h"

namespace smartshark {

QString serverHost(const QString &baseUrl)
{
    return QUrl(baseUrl.trimmed()).host().toLower();
}

bool isLocalServer(const QString &baseUrl)
{
    const QString host = serverHost(baseUrl);
    if (host.isEmpty())
        return false;
    if (guard::isLoopbackHost(host))
        return true;
    QHostAddress addr;
    if (addr.setAddress(host))
        return addr.isPrivateUse() || addr.isLinkLocal() || addr.isLoopback();
    // A name without a dot, or under a suffix reserved for local use, cannot
    // be a public internet server.
    if (!host.contains(QLatin1Char('.')))
        return true;
    for (const char *suffix : {".local", ".lan", ".internal", ".home.arpa"}) {
        if (host.endsWith(QLatin1String(suffix)))
            return true;
    }
    return false;
}

QString cloudApprovalKey(const ProviderConfig &cfg)
{
    return cfg.providerId + QLatin1Char('|') + serverHost(cfg.baseUrl);
}

QString normaliseAddress(const QString &text)
{
    QString t = text.trimmed();
    const qsizetype pct = t.indexOf(QLatin1Char('%')); // IPv6 scope id, e.g. fe80::1%12
    if (pct >= 0)
        t.truncate(pct);
    QHostAddress a;
    if (!a.setAddress(t))
        return QString();
    return a.toString().toLower();
}

void AddressMasker::setScope(AddressMasking scope, const QStringList &ownAddresses)
{
    all_ = scope != AddressMasking::Mine;
    own_.clear();
    for (const QString &a : ownAddresses) {
        const QString n = normaliseAddress(a);
        if (!n.isEmpty())
            own_.insert(n);
    }
}

bool AddressMasker::shouldMaskIp(const QString &key, bool eui64) const
{
    return all_ || eui64 || own_.contains(key);
}

void AddressMasker::clear()
{
    token_.clear();
    original_.clear();
    hosts_ = 0;
    macs_ = 0;
}

QString AddressMasker::tokenFor(const QString &key, const QString &original, bool mac)
{
    auto it = token_.constFind(key);
    if (it != token_.constEnd())
        return it.value();
    const QString token =
        mac ? QStringLiteral("MAC-%1").arg(++macs_) : QStringLiteral("HOST-%1").arg(++hosts_);
    token_.insert(key, token);
    original_.insert(token, original);
    return token;
}

namespace {

// Replace every match of re in text with what fn returns for it. fn returns a
// null QString to keep the match unchanged.
template <typename Fn>
QString replaceMatches(const QString &text, const QRegularExpression &re, Fn fn)
{
    QString out;
    qsizetype pos = 0;
    QRegularExpressionMatchIterator it = re.globalMatch(text);
    while (it.hasNext()) {
        const QRegularExpressionMatch m = it.next();
        const QString replacement = fn(m);
        if (replacement.isNull())
            continue;
        out += text.mid(pos, m.capturedStart() - pos);
        out += replacement;
        pos = m.capturedEnd();
    }
    out += text.mid(pos);
    return out;
}

// Addresses that do not identify anyone stay as they are.
bool keepAddress(const QHostAddress &a)
{
    return a.isNull() || a.isLoopback() || a.isMulticast() || a.isBroadcast() || a == QHostAddress(QHostAddress::AnyIPv4) ||
           a == QHostAddress(QHostAddress::AnyIPv6);
}

} // namespace

QString AddressMasker::mask(const QString &text)
{
    // Full MAC addresses: aa:bb:cc:dd:ee:ff or aa-bb-cc-dd-ee-ff.
    static const QRegularExpression macRe(
        QStringLiteral("(?<![\\w:.-])([0-9A-Fa-f]{2})([:-])[0-9A-Fa-f]{2}(?:\\2[0-9A-Fa-f]{2}){4}(?![\\w:]|-[0-9A-Fa-f])"));
    // Cisco-style dotted form, as devices sometimes write it in payloads: aabb.ccdd.eeff.
    static const QRegularExpression dottedMacRe(QStringLiteral(
        "(?<![\\w.])([0-9A-Fa-f]{4})\\.([0-9A-Fa-f]{4})\\.([0-9A-Fa-f]{4})(?![\\w]|\\.[0-9A-Fa-f])"));
    // Wireshark's short forms with the maker's name: "Intel_dd:ee:ff", and for
    // smaller address blocks "Maker_d:ee:ff" or "Maker_e:ff".
    static const QRegularExpression vendorMacRe(QStringLiteral(
        "(?<![\\w.-])([A-Za-z][\\w.-]*?)_([0-9A-Fa-f]{1,2}(?::[0-9A-Fa-f]{2}){1,4})(?![\\w:])"));
    // IPv6 candidates, checked with QHostAddress. The IPv4 tail comes first so
    // "::ffff:192.0.2.1" is taken whole.
    static const QRegularExpression ipv6Re(QStringLiteral(
        "(?<![\\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:\\d{1,3}(?:\\.\\d{1,3}){3}|[0-9A-Fa-f]{1,4})?(?![\\w:]|\\.[0-9A-Fa-f])"));
    static const QRegularExpression ipv4Re(
        QStringLiteral("(?<![\\w.])(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})(?![\\w]|\\.\\d)"));

    // key: lower case, colon separated.
    auto macToken = [this](const QString &key, const QString &original) {
        const int first = key.left(2).toInt(nullptr, 16);
        if ((first & 1) || key == QLatin1String("00:00:00:00:00:00"))
            return QString(); // broadcast, multicast or empty: not a device
        return tokenFor(key, original, true);
    };

    QString out = replaceMatches(text, macRe, [&](const QRegularExpressionMatch &m) {
        QString key = m.captured(0).toLower();
        key.replace(QLatin1Char('-'), QLatin1Char(':'));
        return macToken(key, m.captured(0));
    });

    out = replaceMatches(out, dottedMacRe, [&](const QRegularExpressionMatch &m) {
        const QString hex = (m.captured(1) + m.captured(2) + m.captured(3)).toLower();
        QStringList pairs;
        for (int i = 0; i < 12; i += 2)
            pairs.append(hex.mid(i, 2));
        return macToken(pairs.join(QLatin1Char(':')), m.captured(0));
    });

    out = replaceMatches(out, vendorMacRe, [this](const QRegularExpressionMatch &m) {
        const QString suffix = m.captured(2).toLower().remove(QLatin1Char(':'));
        // Same device as a full address already seen? Use its placeholder.
        for (auto it = token_.cbegin(); it != token_.cend(); ++it) {
            if (it.value().startsWith(QLatin1String("MAC-")) && it.key().size() == 17 &&
                QString(it.key()).remove(QLatin1Char(':')).endsWith(suffix))
                return m.captured(1) + QLatin1Char('_') + it.value();
        }
        return m.captured(1) + QLatin1Char('_') +
               tokenFor(QStringLiteral("partial:") + suffix, m.captured(2), true);
    });

    // Known devices written without separators ("0800274e66a1") or as bytes
    // in a hex dump ("08 00 27 4e 66 a1", on one line).
    for (auto it = token_.cbegin(); it != token_.cend(); ++it) {
        if (!it.value().startsWith(QLatin1String("MAC-")) || it.key().size() != 17)
            continue;
        const QStringList bytes = it.key().split(QLatin1Char(':'));
        const QRegularExpression bare(QStringLiteral("(?<![0-9A-Fa-f])(?:%1|%2)(?![0-9A-Fa-f])")
                                          .arg(bytes.join(QString()), bytes.join(QStringLiteral(" "))),
                                      QRegularExpression::CaseInsensitiveOption);
        out.replace(bare, it.value());
    }

    out = replaceMatches(out, ipv6Re, [this](const QRegularExpressionMatch &m) {
        QHostAddress a;
        if (!a.setAddress(m.captured(0)) || a.protocol() != QAbstractSocket::IPv6Protocol || keepAddress(a))
            return QString();
        // An interface identifier ending in ff:fe in the middle was built from a MAC address.
        const Q_IPV6ADDR b = a.toIPv6Address();
        const bool eui64 = b[11] == 0xff && b[12] == 0xfe;
        const QString key = a.toString().toLower();
        if (!shouldMaskIp(key, eui64))
            return QString();
        return tokenFor(key, m.captured(0), false);
    });

    out = replaceMatches(out, ipv4Re, [this](const QRegularExpressionMatch &m) {
        QStringList parts;
        for (int i = 1; i <= 4; ++i) {
            const int v = m.captured(i).toInt();
            if (v > 255)
                return QString();
            parts.append(QString::number(v));
        }
        const QString key = parts.join(QLatin1Char('.'));
        if (keepAddress(QHostAddress(key)) || !shouldMaskIp(key, false))
            return QString();
        return tokenFor(key, m.captured(0), false);
    });

    // This computer's own IPv4 addresses also appear reversed in reverse-DNS
    // names (d.c.b.a.in-addr.arpa) and with dashes in ISP host names
    // (host-a-b-c-d.example.net).
    for (const QString &own : own_) {
        const QStringList p = own.split(QLatin1Char('.'));
        if (p.size() != 4)
            continue;
        const QString reversed = QStringList{p[3], p[2], p[1], p[0]}.join(QStringLiteral("\\."));
        const QRegularExpression forms(
            QStringLiteral("(?<![\\d.])%1(?=\\.in-addr\\.arpa)|(?<!\\d)(?<!\\d-)%2(?!\\d)(?!-\\d)")
                .arg(reversed, p.join(QLatin1Char('-'))),
            QRegularExpression::CaseInsensitiveOption);
        if (out.contains(forms))
            out.replace(forms, tokenFor(own, own, false));
    }
    return out;
}

QString AddressMasker::unmask(const QString &text) const
{
    if (original_.isEmpty())
        return text;
    static const QRegularExpression tokenRe(QStringLiteral("(?<![A-Za-z0-9])(?:HOST|MAC)-\\d+(?!\\d)"));
    return replaceMatches(text, tokenRe, [this](const QRegularExpressionMatch &m) {
        const auto it = original_.constFind(m.captured(0));
        return it == original_.constEnd() ? QString() : it.value();
    });
}

} // namespace smartshark
