/* input_guard.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "core/input_guard.h"

#include <QHostAddress>
#include <QUrl>

namespace smartshark::guard {

QString singleLine(const QString &text, int maxChars)
{
    QString out;
    out.reserve(qMin(text.size(), static_cast<qsizetype>(maxChars) + 1));
    bool lastSpace = true; // drops leading whitespace
    for (const QChar c : text) {
        const bool space = c.isSpace() || c.category() == QChar::Other_Control ||
                           c.category() == QChar::Other_Format;
        if (space) {
            if (!lastSpace)
                out.append(QLatin1Char(' '));
            lastSpace = true;
        } else {
            out.append(c);
            lastSpace = false;
        }
        if (out.size() > maxChars)
            break;
    }
    out = out.trimmed();
    if (out.size() > maxChars)
        out.truncate(maxChars);
    return out;
}

QString escapeMarkdown(const QString &text)
{
    static const QString specials = QStringLiteral("\\`*_{}[]()<>#+-.!|~");
    QString out;
    out.reserve(text.size() + 8);
    for (const QChar c : text) {
        if (specials.contains(c))
            out += QLatin1Char('\\');
        out += c;
    }
    return out;
}

bool isLoopbackHost(const QString &host)
{
    const QString h = host.trimmed().toLower();
    if (h == QLatin1String("localhost") || h.endsWith(QLatin1String(".localhost")))
        return true;
    QHostAddress addr;
    if (!addr.setAddress(h.startsWith(QLatin1Char('[')) ? h.mid(1, h.size() - 2) : h))
        return false;
    return addr.isLoopback();
}

QString checkBaseUrl(const QString &url, bool willSendApiKey)
{
    const QString text = url.trimmed();
    if (text.isEmpty())
        return QStringLiteral("Enter the server URL.");
    if (text.size() > 2048)
        return QStringLiteral("The server URL is too long.");

    const QUrl u(text, QUrl::StrictMode);
    if (!u.isValid() || u.host().isEmpty())
        return QStringLiteral("The server URL is not valid. It should look like https://example.com/v1");
    const QString scheme = u.scheme().toLower();
    if (scheme != QLatin1String("http") && scheme != QLatin1String("https"))
        return QStringLiteral("The server URL must start with http:// or https://");
    if (!u.userInfo().isEmpty())
        return QStringLiteral("Do not put a user name or password in the URL. Use the API key field.");
    if (u.hasQuery() || u.hasFragment())
        return QStringLiteral("The server URL should not contain ? or #.");
    if (willSendApiKey && scheme == QLatin1String("http") && !isLoopbackHost(u.host()))
        return QStringLiteral("This would send your API key unencrypted. Use an https:// URL, "
                              "or plain http only for a server on this computer.");
    return QString();
}

QString cleanApiKey(const QString &key, QString *error)
{
    const QString k = key.trimmed();
    if (k.size() > kMaxApiKeyChars) {
        if (error)
            *error = QStringLiteral("The API key is too long. Check that you pasted only the key.");
        return QString();
    }
    for (const QChar c : k) {
        // Printable ASCII only: anything else cannot be sent in a header and
        // usually means extra text was pasted along with the key.
        if (c.unicode() < 0x21 || c.unicode() > 0x7e) {
            if (error)
                *error = QStringLiteral("The API key contains spaces or unusual characters. "
                                        "Check that you pasted only the key.");
            return QString();
        }
    }
    return k;
}

QString cleanModelName(const QString &model, QString *error)
{
    const QString m = model.trimmed();
    if (m.size() > kMaxModelNameChars) {
        if (error)
            *error = QStringLiteral("The model name is too long.");
        return QString();
    }
    for (const QChar c : m) {
        if (c.unicode() < 0x20 || c.category() == QChar::Other_Control) {
            if (error)
                *error = QStringLiteral("The model name contains invalid characters.");
            return QString();
        }
    }
    return m;
}

} // namespace smartshark::guard
