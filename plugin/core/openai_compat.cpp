/* openai_compat.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "core/openai_compat.h"

#include "core/input_guard.h"
#include "core/sse.h"

#include <algorithm>
#include <memory>

#include <QJsonArray>
#include <QJsonDocument>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QUrl>

namespace smartshark {

namespace openai {

static QString roleName(ChatMessage::Role role)
{
    switch (role) {
    case ChatMessage::Role::System: return QStringLiteral("system");
    case ChatMessage::Role::User: return QStringLiteral("user");
    case ChatMessage::Role::Assistant: return QStringLiteral("assistant");
    }
    return QStringLiteral("user");
}

QJsonObject buildChatBody(const QString &model, const QList<ChatMessage> &messages, bool stream)
{
    QJsonArray msgs;
    for (const ChatMessage &m : messages) {
        msgs.append(QJsonObject{
            {QStringLiteral("role"), roleName(m.role)},
            {QStringLiteral("content"), m.content},
        });
    }
    return QJsonObject{
        {QStringLiteral("model"), model},
        {QStringLiteral("messages"), msgs},
        {QStringLiteral("stream"), stream},
    };
}

QString parseErrorMessage(const QByteArray &body)
{
    QJsonParseError perr;
    const QJsonDocument doc = QJsonDocument::fromJson(body, &perr);
    if (perr.error != QJsonParseError::NoError)
        return QString();

    // OpenAI style: {"error": {"message": "..."}}; some servers: {"error": "..."}.
    // Gemini wraps it in a list: [{"error": {...}}].
    QJsonObject root = doc.isArray() ? doc.array().at(0).toObject() : doc.object();
    const QJsonValue err = root.value(QStringLiteral("error"));
    if (err.isObject())
        return err.toObject().value(QStringLiteral("message")).toString();
    if (err.isString())
        return err.toString();
    return root.value(QStringLiteral("message")).toString();
}

ChatResult parseChatResponse(const QByteArray &body)
{
    ChatResult r;
    QJsonParseError perr;
    const QJsonDocument doc = QJsonDocument::fromJson(body, &perr);
    if (perr.error != QJsonParseError::NoError || !doc.isObject()) {
        r.error = QStringLiteral("The server's reply was not valid JSON.");
        return r;
    }
    const QJsonObject root = doc.object();
    const QString apiError = parseErrorMessage(body);
    if (root.contains(QStringLiteral("error")) && !apiError.isEmpty()) {
        r.error = apiError;
        return r;
    }

    const QJsonArray choices = root.value(QStringLiteral("choices")).toArray();
    if (choices.isEmpty()) {
        r.error = QStringLiteral("The server's reply had no choices.");
        return r;
    }
    const QJsonObject choice = choices.at(0).toObject();
    const QJsonValue content = choice.value(QStringLiteral("message")).toObject().value(QStringLiteral("content"));

    // content is normally a string, but some servers send a list of parts.
    QString text;
    if (content.isString()) {
        text = content.toString();
    } else if (content.isArray()) {
        for (const QJsonValue &part : content.toArray())
            text += part.toObject().value(QStringLiteral("text")).toString();
    }

    if (text.trimmed().isEmpty()) {
        const QString reason = choice.value(QStringLiteral("finish_reason")).toString();
        r.error = reason == QLatin1String("length")
                      ? QStringLiteral("The model ran out of output tokens before answering. "
                                       "Reasoning models sometimes do this; try a different model.")
                      : QStringLiteral("The model returned an empty reply.");
        return r;
    }
    r.ok = true;
    r.text = text;
    return r;
}

ModelListResult parseModelsResponse(const QByteArray &body)
{
    ModelListResult r;
    QJsonParseError perr;
    const QJsonDocument doc = QJsonDocument::fromJson(body, &perr);
    if (perr.error != QJsonParseError::NoError || !doc.isObject()) {
        r.error = QStringLiteral("The server's model list was not valid JSON.");
        return r;
    }
    const QJsonArray data = doc.object().value(QStringLiteral("data")).toArray();
    for (const QJsonValue &v : data) {
        QString id = v.toObject().value(QStringLiteral("id")).toString();
        // Gemini prefixes ids with "models/", but expects them without it.
        if (id.startsWith(QLatin1String("models/")))
            id.remove(0, 7);
        if (!id.isEmpty())
            r.models.append(id);
    }
    std::sort(r.models.begin(), r.models.end(),
              [](const QString &a, const QString &b) { return a.compare(b, Qt::CaseInsensitive) < 0; });
    r.models.removeDuplicates();
    r.ok = true;
    return r;
}

} // namespace openai

void OpenAiCompatBackend::addHeaders(QNetworkRequest *request, const QString &key) const
{
    if (!key.isEmpty())
        request->setRawHeader("Authorization", "Bearer " + key.toLatin1());
}

void OpenAiCompatBackend::chat(const QList<ChatMessage> &messages, ChatCallback done)
{
    if (config_.model.isEmpty()) {
        done(ChatResult{false, QString(), QStringLiteral("No model is selected. Choose one in SmartShark settings.")});
        return;
    }
    const QByteArray body = QJsonDocument(openai::buildChatBody(config_.model, messages)).toJson(QJsonDocument::Compact);
    QString error;
    QNetworkReply *reply = send(QStringLiteral("chat/completions"), &body, &error);
    if (!reply) {
        done(ChatResult{false, QString(), error});
        return;
    }

    connect(reply, &QNetworkReply::finished, this, [this, reply, done]() {
        if (pending_ == reply)
            pending_ = nullptr;
        reply->deleteLater();
        const QByteArray data = reply->readAll();
        if (reply->error() != QNetworkReply::NoError) {
            done(ChatResult{false, QString(), describeNetworkError(reply, data)});
            return;
        }
        done(openai::parseChatResponse(data));
    });
}

void OpenAiCompatBackend::listModels(ModelsCallback done)
{
    QString error;
    QNetworkReply *reply = send(QStringLiteral("models"), nullptr, &error);
    if (!reply) {
        done(ModelListResult{false, {}, error});
        return;
    }

    connect(reply, &QNetworkReply::finished, this, [this, reply, done]() {
        if (pending_ == reply)
            pending_ = nullptr;
        reply->deleteLater();
        const QByteArray data = reply->readAll();
        if (reply->error() != QNetworkReply::NoError) {
            done(ModelListResult{false, {}, describeNetworkError(reply, data)});
            return;
        }
        done(openai::parseModelsResponse(data));
    });
}

void OpenAiCompatBackend::chatStream(const QList<ChatMessage> &messages, DeltaCallback onDelta, ChatCallback done,
                                     DeltaCallback onReasoning)
{
    if (config_.model.isEmpty()) {
        done(ChatResult{false, QString(), QStringLiteral("No model is selected. Choose one in SmartShark settings.")});
        return;
    }
    const QByteArray body =
        QJsonDocument(openai::buildChatBody(config_.model, messages, true)).toJson(QJsonDocument::Compact);
    QString error;
    // A stream carries far more bytes than its text (SSE framing, reasoning).
    QNetworkReply *reply = send(QStringLiteral("chat/completions"), &body, &error, guard::kMaxStreamBytes, true);
    if (!reply) {
        done(ChatResult{false, QString(), error});
        return;
    }

    struct State {
        SseParser parser;
        QString text;       // reply so far
        QByteArray raw;     // everything received, for error bodies and non-streaming servers
        QString streamError;
        bool tooLong = false;
    };
    auto state = std::make_shared<State>();

    // Returns false if the request was cancelled from inside a callback.
    auto consume = [this, reply, state, onDelta, onReasoning](const QByteArray &chunk) -> bool {
        if (state->raw.size() + chunk.size() <= guard::kMaxResponseBytes)
            state->raw.append(chunk);
        for (const QByteArray &event : state->parser.feed(chunk)) {
            if (event.trimmed() == "[DONE]")
                continue;
            QString err;
            QString reasoning;
            const QString delta = openai::parseStreamDelta(event, &err, &reasoning);
            if (!err.isEmpty())
                state->streamError = guard::singleLine(err, 500);
            if (!reasoning.isEmpty() && onReasoning) {
                onReasoning(reasoning);
                if (pending_ != reply)
                    return false;
            }
            if (!delta.isEmpty()) {
                state->text += delta;
                onDelta(delta);
                if (pending_ != reply)
                    return false;
                if (state->text.size() > guard::kMaxReplyChars) {
                    // Some servers set no output limit; a looping model would
                    // otherwise run on and slow the panel down.
                    state->tooLong = true;
                    reply->abort(); // finishes the reply
                    return false;
                }
            }
        }
        return true;
    };

    connect(reply, &QNetworkReply::readyRead, this, [reply, consume]() { consume(reply->readAll()); });

    connect(reply, &QNetworkReply::finished, this, [this, reply, state, consume, onDelta, done]() {
        if (pending_ != reply)
            return; // cancelled
        // consume() returns false when cancelled from a callback, or when the
        // reply became too long (then it is reported below).
        if (!state->tooLong && !consume(reply->readAll()) && !state->tooLong)
            return;
        pending_ = nullptr;
        reply->deleteLater();

        if (state->tooLong) {
            done(ChatResult{false, state->text, replyTooLongError()});
            return;
        }
        if (reply->error() != QNetworkReply::NoError) {
            done(ChatResult{false, state->text, describeNetworkError(reply, state->raw)});
            return;
        }
        if (!state->streamError.isEmpty()) {
            done(ChatResult{false, state->text, state->streamError});
            return;
        }
        if (!state->parser.sawEvents()) {
            // The server ignored "stream": true and sent one JSON reply.
            const ChatResult r = openai::parseChatResponse(state->raw);
            if (r.ok)
                onDelta(r.text);
            done(r);
            return;
        }
        if (state->text.trimmed().isEmpty()) {
            done(ChatResult{false, QString(), QStringLiteral("The model returned an empty reply.")});
            return;
        }
        done(ChatResult{true, state->text, QString()});
    });
}

} // namespace smartshark
