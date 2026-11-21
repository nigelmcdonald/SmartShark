/* sse.h
 *
 * Server-Sent Events parsing for streamed chat replies.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QByteArray>
#include <QList>
#include <QString>

namespace smartshark {

// Splits a byte stream into SSE events and returns each event's data. Bytes
// may arrive in any chunking; partial lines are kept until completed.
class SseParser {
public:
    // Returns the data of every event completed by this chunk.
    QList<QByteArray> feed(const QByteArray &chunk);

    // True once at least one "data:" line has been seen.
    bool sawEvents() const { return sawEvents_; }

private:
    QByteArray buffer_;
    QByteArray eventData_;
    bool sawEvents_ = false;
};

namespace openai {

// Text added by one streamed chunk ({"choices":[{"delta":{"content":"..."}}]}).
// Sets *error if the chunk is an error object. Reasoning text that some servers
// stream separately (delta.reasoning_content or delta.reasoning) goes to
// *reasoning.
QString parseStreamDelta(const QByteArray &data, QString *error = nullptr, QString *reasoning = nullptr);

} // namespace openai

} // namespace smartshark
