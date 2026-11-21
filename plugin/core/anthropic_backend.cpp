/* anthropic_backend.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "core/anthropic_backend.h"

#include <memory>

#include <QJsonArray>
#include <QJsonDocument>
#include <QNetworkReply>
#include <QNetworkRequest>

#include "core/input_guard.h"
#include "core/openai_compat.h"
#include "core/sse.h"

namespace smartshark {

namespace anthropic {

// Used by parseMessagesResponse and AnthropicBackend::chatStream.
QString cutOffNote()
{
    return QStringLiteral("\n\n*(The reply reached SmartShark's length limit and was cut off.)*");
}

QString emptyReplyErrorText(const QString &stopReason)
{
    return stopReason == QLatin1String("max_tokens")
               ? QStringLiteral("The model used its whole output allowance on thinking before answering. Try again, "
                                "or ask a shorter question.")
               : QStringLiteral("The model returned an empty reply.");
}

bool supportsFallbacks(const QString &model)
{
    static const QStringList models = {
        QStringLiteral("claude-fable-5-2"), QStringLiteral("claude-fable-5-1"), QStringLiteral("claude-opus-5-5"),
        QStringLiteral("claude-opus-5"),    QStringLiteral("claude-sonnet-5-5"),
    };
    return models.contains(model.trimmed());
}

QJsonObject buildMessagesBody(const QString &model, const QList<ChatMessage> &messages, bool stream, int maxTokens)
{
    QStringList system;
    QJsonArray msgs;
    for (const ChatMessage &m : messages) {
        if (m.role == ChatMessage::Role::System) {
            system.append(m.content);
            continue;
        }
        msgs.append(QJsonObject{
            {QStringLiteral("role"),
             m.role == ChatMessage::Role::Assistant ? QStringLiteral("assistant") : QStringLiteral("user")},
            {QStringLiteral("content"), m.content},
        });
    }
    QJsonObject body{
        {QStringLiteral("model"), model},
        {QStringLiteral("max_tokens"), maxTokens},
        {QStringLiteral("messages"), msgs},
    };
    if (!system.isEmpty())
        body.insert(QStringLiteral("system"), system.join(QStringLiteral("\n\n")));
    if (stream)
        body.insert(QStringLiteral("stream"), true);
    if (supportsFallbacks(model))
        body.insert(QStringLiteral("fallbacks"), QStringLiteral("default"));
    return body;
}

QString refusalMessage(const QString &category)
{
    QString msg = QStringLiteral("Claude declined to answer this");
    if (!category.isEmpty())
        msg += QStringLiteral(" (its safety checks flagged it as \"%1\")").arg(guard::singleLine(category, 40));
    msg += QStringLiteral(". This can happen with security-related traffic even when the question is harmless. Try "
                          "rewording the question, explaining a different packet, or choosing another model or a "
                          "local server in Tools > SmartShark > Settings.");
    return msg;
}

ChatResult parseMessagesResponse(const QByteArray &body)
{
    ChatResult r;
    QJsonParseError perr;
    const QJsonDocument doc = QJsonDocument::fromJson(body, &perr);
    if (perr.error != QJsonParseError::NoError || !doc.isObject()) {
        r.error = QStringLiteral("The server's reply was not valid JSON.");
        return r;
    }
    const QJsonObject root = doc.object();
    if (root.value(QStringLiteral("type")).toString() == QLatin1String("error")) {
        r.error = openai::parseErrorMessage(body);
        if (r.error.isEmpty())
            r.error = QStringLiteral("The server returned an error.");
        return r;
    }
    const QString stopReason = root.value(QStringLiteral("stop_reason")).toString();
    if (stopReason == QLatin1String("refusal")) {
        r.error = refusalMessage(
            root.value(QStringLiteral("stop_details")).toObject().value(QStringLiteral("category")).toString());
        return r;
    }
    QString text;
    for (const QJsonValue &v : root.value(QStringLiteral("content")).toArray()) {
        const QJsonObject block = v.toObject();
        if (block.value(QStringLiteral("type")).toString() == QLatin1String("text"))
            text += block.value(QStringLiteral("text")).toString();
    }
    if (text.trimmed().isEmpty()) {
        r.error = emptyReplyErrorText(stopReason);
        return r;
    }
    if (stopReason == QLatin1String("max_tokens"))
        text += cutOffNote();
    r.ok = true;
    r.text = text;
    return r;
}

StreamEvent parseStreamEvent(const QByteArray &data)
{
    StreamEvent ev;
    const QJsonDocument doc = QJsonDocument::fromJson(data);
    if (!doc.isObject())
        return ev;
    const QJsonObject root = doc.object();
    const QString type = root.value(QStringLiteral("type")).toString();
    if (type == QLatin1String("content_block_delta")) {
        const QJsonObject delta = root.value(QStringLiteral("delta")).toObject();
        const QString kind = delta.value(QStringLiteral("type")).toString();
        if (kind == QLatin1String("text_delta"))
            ev.text = delta.value(QStringLiteral("text")).toString();
        else if (kind == QLatin1String("thinking_delta"))
            ev.thinking = delta.value(QStringLiteral("thinking")).toString();
    } else if (type == QLatin1String("message_delta")) {
        const QJsonObject delta = root.value(QStringLiteral("delta")).toObject();
        ev.stopReason = delta.value(QStringLiteral("stop_reason")).toString();
        ev.refusalCategory =
            delta.value(QStringLiteral("stop_details")).toObject().value(QStringLiteral("category")).toString();
    } else if (type == QLatin1String("error")) {
        ev.error = root.value(QStringLiteral("error")).toObject().value(QStringLiteral("message")).toString();
        if (ev.error.isEmpty())
            ev.error = QStringLiteral("The server reported an error while replying.");
    }
    return ev;
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
    for (const QJsonValue &v : doc.object().value(QStringLiteral("data")).toArray()) {
        const QString id = v.toObject().value(QStringLiteral("id")).toString();
        if (!id.isEmpty() && !r.models.contains(id))
            r.models.append(id);
    }
    r.ok = true;
    return r;
}

QJsonObject webSearchTool()
{
    return QJsonObject{
        {QStringLiteral("type"), QStringLiteral("web_search_20250305")},
        {QStringLiteral("name"), QStringLiteral("web_search")},
        {QStringLiteral("max_uses"), kMaxSearches},
    };
}

QString searchErrorText(const QString &code)
{
    if (code == QLatin1String("max_uses_exceeded"))
        return QStringLiteral("search limit for this question reached");
    if (code == QLatin1String("too_many_requests"))
        return QStringLiteral("too many searches right now (rate limited)");
    if (code == QLatin1String("query_too_long"))
        return QStringLiteral("search too long");
    if (code == QLatin1String("unavailable"))
        return QStringLiteral("search service unavailable");
    return code.isEmpty() ? QStringLiteral("search failed") : QStringLiteral("search failed (%1)").arg(code);
}

namespace {

WebSource sourceFrom(const QJsonObject &o)
{
    WebSource s;
    s.url = o.value(QStringLiteral("url")).toString();
    s.title = o.value(QStringLiteral("title")).toString();
    s.pageAge = o.value(QStringLiteral("page_age")).toString();
    s.citedText = o.value(QStringLiteral("cited_text")).toString();
    return s;
}

} // namespace

ContentAccumulator::Update ContentAccumulator::apply(const QByteArray &eventData)
{
    Update up;
    const QJsonDocument doc = QJsonDocument::fromJson(eventData);
    if (!doc.isObject())
        return up;
    const QJsonObject root = doc.object();
    const QString type = root.value(QStringLiteral("type")).toString();
    const int index = root.value(QStringLiteral("index")).toInt(-1);

    if (type == QLatin1String("content_block_start") && index >= 0) {
        const QJsonObject block = root.value(QStringLiteral("content_block")).toObject();
        blocks_[index] = block;
        if (block.value(QStringLiteral("type")).toString() == QLatin1String("web_search_tool_result")) {
            const QJsonValue content = block.value(QStringLiteral("content"));
            if (content.isArray()) {
                for (const QJsonValue &v : content.toArray())
                    up.results.append(sourceFrom(v.toObject()));
            } else {
                up.searchError = content.toObject().value(QStringLiteral("error_code")).toString();
                if (up.searchError.isEmpty())
                    up.searchError = QStringLiteral("unknown");
            }
        }
    } else if (type == QLatin1String("content_block_delta") && blocks_.contains(index)) {
        QJsonObject &block = blocks_[index];
        const QJsonObject delta = root.value(QStringLiteral("delta")).toObject();
        const QString kind = delta.value(QStringLiteral("type")).toString();
        if (kind == QLatin1String("text_delta")) {
            up.text = delta.value(QStringLiteral("text")).toString();
            block.insert(QStringLiteral("text"), block.value(QStringLiteral("text")).toString() + up.text);
            text_ += up.text;
        } else if (kind == QLatin1String("thinking_delta")) {
            up.thinking = delta.value(QStringLiteral("thinking")).toString();
            block.insert(QStringLiteral("thinking"), block.value(QStringLiteral("thinking")).toString() + up.thinking);
        } else if (kind == QLatin1String("signature_delta")) {
            block.insert(QStringLiteral("signature"), block.value(QStringLiteral("signature")).toString() +
                                                          delta.value(QStringLiteral("signature")).toString());
        } else if (kind == QLatin1String("input_json_delta")) {
            partialJson_[index] += delta.value(QStringLiteral("partial_json")).toString();
        } else if (kind == QLatin1String("citations_delta")) {
            const QJsonObject citation = delta.value(QStringLiteral("citation")).toObject();
            QJsonArray citations = block.value(QStringLiteral("citations")).toArray();
            citations.append(citation);
            block.insert(QStringLiteral("citations"), citations);
            if (citation.value(QStringLiteral("type")).toString() == QLatin1String("web_search_result_location")) {
                up.hasCitation = true;
                up.citation = sourceFrom(citation);
            }
        }
    } else if (type == QLatin1String("content_block_stop") && blocks_.contains(index)) {
        QJsonObject &block = blocks_[index];
        if (partialJson_.contains(index)) {
            const QJsonObject input = QJsonDocument::fromJson(partialJson_.take(index).toUtf8()).object();
            block.insert(QStringLiteral("input"), input);
            if (block.value(QStringLiteral("type")).toString() == QLatin1String("server_tool_use") &&
                block.value(QStringLiteral("name")).toString() == QLatin1String("web_search"))
                up.searchQuery = input.value(QStringLiteral("query")).toString();
        }
    } else if (type == QLatin1String("message_delta")) {
        const QJsonObject delta = root.value(QStringLiteral("delta")).toObject();
        stopReason_ = delta.value(QStringLiteral("stop_reason")).toString();
        refusalCategory_ =
            delta.value(QStringLiteral("stop_details")).toObject().value(QStringLiteral("category")).toString();
    } else if (type == QLatin1String("error")) {
        error_ = root.value(QStringLiteral("error")).toObject().value(QStringLiteral("message")).toString();
        if (error_.isEmpty())
            error_ = QStringLiteral("The server reported an error while replying.");
    }
    return up;
}

QJsonArray ContentAccumulator::blocks() const
{
    QJsonArray out;
    for (const QJsonObject &b : blocks_)
        out.append(b);
    return out;
}

} // namespace anthropic

void AnthropicBackend::addHeaders(QNetworkRequest *request, const QString &key) const
{
    if (!key.isEmpty())
        request->setRawHeader("x-api-key", key.toLatin1());
    request->setRawHeader("anthropic-version", anthropic::kApiVersion);
    if (!beta_.isEmpty())
        request->setRawHeader("anthropic-beta", beta_);
}

void AnthropicBackend::chat(const QList<ChatMessage> &messages, ChatCallback done)
{
    if (config_.model.isEmpty()) {
        done(ChatResult{false, QString(), QStringLiteral("No model is selected. Choose one in SmartShark settings.")});
        return;
    }
    const QByteArray body =
        QJsonDocument(anthropic::buildMessagesBody(config_.model, messages)).toJson(QJsonDocument::Compact);
    beta_ = anthropic::supportsFallbacks(config_.model) ? QByteArray(anthropic::kFallbackBeta) : QByteArray();
    QString error;
    QNetworkReply *reply = send(QStringLiteral("messages"), &body, &error);
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
        done(anthropic::parseMessagesResponse(data));
    });
}

void AnthropicBackend::listModels(ModelsCallback done)
{
    beta_.clear();
    QString error;
    QNetworkReply *reply = send(QStringLiteral("models?limit=1000"), nullptr, &error);
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
        done(anthropic::parseModelsResponse(data));
    });
}

void AnthropicBackend::chatStream(const QList<ChatMessage> &messages, DeltaCallback onDelta, ChatCallback done,
                                  DeltaCallback onReasoning)
{
    if (config_.model.isEmpty()) {
        done(ChatResult{false, QString(), QStringLiteral("No model is selected. Choose one in SmartShark settings.")});
        return;
    }
    const QByteArray body =
        QJsonDocument(anthropic::buildMessagesBody(config_.model, messages, true)).toJson(QJsonDocument::Compact);
    beta_ = anthropic::supportsFallbacks(config_.model) ? QByteArray(anthropic::kFallbackBeta) : QByteArray();
    QString error;
    QNetworkReply *reply = send(QStringLiteral("messages"), &body, &error, guard::kMaxStreamBytes, true);
    if (!reply) {
        done(ChatResult{false, QString(), error});
        return;
    }

    struct State {
        SseParser parser;
        QString text;
        QByteArray raw; // for error bodies
        QString stopReason;
        QString refusalCategory;
        QString streamError;
    };
    auto state = std::make_shared<State>();

    // Returns false if the request was cancelled from inside a callback.
    auto consume = [this, reply, state, onDelta, onReasoning](const QByteArray &chunk) -> bool {
        if (state->raw.size() + chunk.size() <= guard::kMaxResponseBytes)
            state->raw.append(chunk);
        for (const QByteArray &event : state->parser.feed(chunk)) {
            const anthropic::StreamEvent ev = anthropic::parseStreamEvent(event);
            if (!ev.error.isEmpty())
                state->streamError = ev.error;
            if (!ev.stopReason.isEmpty()) {
                state->stopReason = ev.stopReason;
                state->refusalCategory = ev.refusalCategory;
            }
            if (!ev.thinking.isEmpty() && onReasoning) {
                onReasoning(ev.thinking);
                if (pending_ != reply)
                    return false;
            }
            if (!ev.text.isEmpty()) {
                state->text += ev.text;
                onDelta(ev.text);
                if (pending_ != reply)
                    return false;
            }
        }
        return true;
    };

    connect(reply, &QNetworkReply::readyRead, this, [reply, consume]() { consume(reply->readAll()); });

    connect(reply, &QNetworkReply::finished, this, [this, reply, state, consume, onDelta, done]() {
        if (pending_ != reply)
            return; // cancelled
        if (!consume(reply->readAll()))
            return;
        pending_ = nullptr;
        reply->deleteLater();

        if (reply->error() != QNetworkReply::NoError) {
            done(ChatResult{false, state->text, describeNetworkError(reply, state->raw)});
            return;
        }
        if (!state->streamError.isEmpty()) {
            done(ChatResult{false, state->text, state->streamError});
            return;
        }
        if (!state->parser.sawEvents()) {
            const ChatResult r = anthropic::parseMessagesResponse(state->raw);
            if (r.ok)
                onDelta(r.text);
            done(r);
            return;
        }
        if (state->stopReason == QLatin1String("refusal")) {
            // Any partial text is incomplete; the panels show it as failed.
            done(ChatResult{false, state->text, anthropic::refusalMessage(state->refusalCategory)});
            return;
        }
        if (state->text.trimmed().isEmpty()) {
            done(ChatResult{false, QString(), anthropic::emptyReplyErrorText(state->stopReason)});
            return;
        }
        if (state->stopReason == QLatin1String("max_tokens")) {
            onDelta(anthropic::cutOffNote());
            state->text += anthropic::cutOffNote();
        }
        done(ChatResult{true, state->text, QString()});
    });
}

void AnthropicBackend::research(const QList<ChatMessage> &messages, const ResearchCallbacks &callbacks,
                                ChatCallback done)
{
    if (config_.model.isEmpty()) {
        done(ChatResult{false, QString(), QStringLiteral("No model is selected. Choose one in SmartShark settings.")});
        return;
    }
    QStringList system;
    QJsonArray msgs;
    for (const ChatMessage &m : messages) {
        if (m.role == ChatMessage::Role::System) {
            system.append(m.content);
            continue;
        }
        msgs.append(QJsonObject{
            {QStringLiteral("role"),
             m.role == ChatMessage::Role::Assistant ? QStringLiteral("assistant") : QStringLiteral("user")},
            {QStringLiteral("content"), m.content},
        });
    }
    researchRequest(msgs, system.join(QStringLiteral("\n\n")), callbacks, done, 0, QString());
}

void AnthropicBackend::researchRequest(const QJsonArray &messages, const QString &system,
                                       const ResearchCallbacks &cb, ChatCallback done, int resumes,
                                       const QString &textSoFar)
{
    QJsonObject body{
        {QStringLiteral("model"), config_.model},
        {QStringLiteral("max_tokens"), anthropic::kMaxTokens},
        {QStringLiteral("messages"), messages},
        {QStringLiteral("stream"), true},
        {QStringLiteral("tools"), QJsonArray{anthropic::webSearchTool()}},
    };
    if (!system.isEmpty())
        body.insert(QStringLiteral("system"), system);
    if (anthropic::supportsFallbacks(config_.model))
        body.insert(QStringLiteral("fallbacks"), QStringLiteral("default"));
    beta_ = anthropic::supportsFallbacks(config_.model) ? QByteArray(anthropic::kFallbackBeta) : QByteArray();

    const QByteArray payload = QJsonDocument(body).toJson(QJsonDocument::Compact);
    QString error;
    QNetworkReply *reply = send(QStringLiteral("messages"), &payload, &error, guard::kMaxStreamBytes, true);
    if (!reply) {
        done(ChatResult{false, textSoFar, error});
        return;
    }

    struct State {
        SseParser parser;
        anthropic::ContentAccumulator acc;
        QByteArray raw;
    };
    auto state = std::make_shared<State>();

    auto consume = [this, reply, state, cb](const QByteArray &chunk) -> bool {
        if (state->raw.size() + chunk.size() <= guard::kMaxResponseBytes)
            state->raw.append(chunk);
        for (const QByteArray &event : state->parser.feed(chunk)) {
            const anthropic::ContentAccumulator::Update up = state->acc.apply(event);
            if (!up.thinking.isEmpty() && cb.onReasoning)
                cb.onReasoning(up.thinking);
            if (!up.searchQuery.isEmpty() && cb.onSearch)
                cb.onSearch(up.searchQuery);
            if ((!up.results.isEmpty() || !up.searchError.isEmpty()) && cb.onResults)
                cb.onResults(up.results, up.searchError);
            if (up.hasCitation && cb.onCitation)
                cb.onCitation(up.citation);
            if (!up.text.isEmpty() && cb.onText)
                cb.onText(up.text);
            if (pending_ != reply)
                return false; // cancelled from a callback
        }
        return true;
    };

    connect(reply, &QNetworkReply::readyRead, this, [reply, consume]() { consume(reply->readAll()); });

    connect(reply, &QNetworkReply::finished, this,
            [this, reply, state, consume, cb, done, messages, system, resumes, textSoFar]() {
                if (pending_ != reply)
                    return;
                if (!consume(reply->readAll()))
                    return;
                pending_ = nullptr;
                reply->deleteLater();

                const QString text = textSoFar + state->acc.text();
                if (reply->error() != QNetworkReply::NoError) {
                    done(ChatResult{false, text, describeNetworkError(reply, state->raw)});
                    return;
                }
                if (!state->acc.error().isEmpty()) {
                    done(ChatResult{false, text, state->acc.error()});
                    return;
                }
                if (!state->parser.sawEvents()) {
                    const ChatResult r = anthropic::parseMessagesResponse(state->raw);
                    done(r.ok ? ChatResult{false, text, QStringLiteral("The server did not stream its reply.")} : r);
                    return;
                }
                const QString stop = state->acc.stopReason();
                if (stop == QLatin1String("pause_turn") && resumes < 2) {
                    // Send the paused turn back unchanged; the server carries on. A turn
                    // paused before is merged into one assistant message.
                    QJsonArray next = messages;
                    QJsonArray content;
                    if (!next.isEmpty() &&
                        next.last().toObject().value(QStringLiteral("role")).toString() == QLatin1String("assistant")) {
                        content = next.last().toObject().value(QStringLiteral("content")).toArray();
                        next.removeLast();
                    }
                    for (const QJsonValue &b : state->acc.blocks())
                        content.append(b);
                    next.append(QJsonObject{{QStringLiteral("role"), QStringLiteral("assistant")},
                                            {QStringLiteral("content"), content}});
                    researchRequest(next, system, cb, done, resumes + 1, text);
                    return;
                }
                if (stop == QLatin1String("refusal")) {
                    done(ChatResult{false, text, anthropic::refusalMessage(state->acc.refusalCategory())});
                    return;
                }
                if (text.trimmed().isEmpty()) {
                    done(ChatResult{false, QString(), anthropic::emptyReplyErrorText(stop)});
                    return;
                }
                QString finalText = text;
                if (stop == QLatin1String("max_tokens") || stop == QLatin1String("pause_turn")) {
                    if (cb.onText)
                        cb.onText(anthropic::cutOffNote());
                    finalText += anthropic::cutOffNote();
                }
                done(ChatResult{true, finalText, QString()});
            });
}

} // namespace smartshark
