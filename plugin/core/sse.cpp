/* sse.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "core/sse.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

namespace smartshark {

QList<QByteArray> SseParser::feed(const QByteArray &chunk)
{
    QList<QByteArray> events;
    buffer_.append(chunk);

    qsizetype start = 0;
    for (;;) {
        const qsizetype nl = buffer_.indexOf('\n', start);
        if (nl < 0)
            break;
        QByteArray line = buffer_.mid(start, nl - start);
        start = nl + 1;
        if (line.endsWith('\r'))
            line.chop(1);

        if (line.isEmpty()) {
            // A blank line ends the event.
            if (!eventData_.isNull()) {
                events.append(eventData_);
                eventData_ = QByteArray();
            }
            continue;
        }
        if (line.startsWith(':'))
            continue; // comment / keep-alive
        if (line.startsWith("data:")) {
            QByteArray value = line.mid(5);
            if (value.startsWith(' '))
                value.remove(0, 1);
            sawEvents_ = true;
            if (eventData_.isNull())
                eventData_ = value;
            else
                eventData_.append('\n').append(value);
        }
        // Other fields (event:, id:, retry:) are not needed.
    }
    buffer_.remove(0, start);
    return events;
}

namespace openai {

QString parseStreamDelta(const QByteArray &data, QString *error, QString *reasoning)
{
    QJsonParseError perr;
    const QJsonDocument doc = QJsonDocument::fromJson(data, &perr);
    if (perr.error != QJsonParseError::NoError || !doc.isObject())
        return QString();
    const QJsonObject root = doc.object();

    const QJsonValue err = root.value(QStringLiteral("error"));
    if (!err.isUndefined() && !err.isNull()) {
        if (error)
            *error = err.isObject() ? err.toObject().value(QStringLiteral("message")).toString() : err.toString();
        return QString();
    }

    const QJsonArray choices = root.value(QStringLiteral("choices")).toArray();
    if (choices.isEmpty())
        return QString();
    const QJsonObject delta = choices.at(0).toObject().value(QStringLiteral("delta")).toObject();
    if (reasoning) {
        const QJsonValue r = delta.contains(QStringLiteral("reasoning_content"))
                                 ? delta.value(QStringLiteral("reasoning_content"))
                                 : delta.value(QStringLiteral("reasoning"));
        if (r.isString())
            *reasoning = r.toString();
    }
    const QJsonValue content = delta.value(QStringLiteral("content"));
    if (content.isString())
        return content.toString();
    QString text;
    if (content.isArray()) {
        for (const QJsonValue &part : content.toArray())
            text += part.toObject().value(QStringLiteral("text")).toString();
    }
    return text;
}

} // namespace openai

} // namespace smartshark
