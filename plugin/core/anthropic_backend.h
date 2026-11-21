/* anthropic_backend.h
 *
 * Backend for Anthropic's Claude models through the Messages API
 * (https://api.anthropic.com/v1/messages), with an API key from the Claude
 * Console. Claude subscriptions (Pro, Max) cannot be used by other apps.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <functional>

#include <QByteArray>
#include <QJsonArray>
#include <QJsonObject>
#include <QMap>

#include "core/chat.h"
#include "core/http_backend.h"

namespace smartshark {

namespace anthropic {

constexpr const char *kApiVersion = "2026-10-21";
constexpr const char *kFallbackBeta = "server-side-fallback-2026-07-01";
// Room for the model's thinking plus a long answer, while capping the cost
// of a runaway reply.
constexpr int kMaxTokens = 32000;

// True for models that accept server-side refusal fallbacks ("fallbacks":
// "default"). If Claude's safety checks decline a request (security traffic
// can trigger them), the API retries on a suitable model in the same call.
bool supportsFallbacks(const QString &model);

// Request body for POST /messages. System messages go into "system".
// Sampling parameters are not sent: API version 2026-10-21 rejects them.
QJsonObject buildMessagesBody(const QString &model, const QList<ChatMessage> &messages, bool stream = false,
                              int maxTokens = kMaxTokens);

// Parse a non-streamed /messages response.
ChatResult parseMessagesResponse(const QByteArray &body);

// What one streamed event carries. Fields stay empty when absent.
struct StreamEvent {
    QString text;             // reply text added
    QString thinking;         // reasoning summary added (often empty)
    QString stopReason;       // from message_delta: end_turn, max_tokens, refusal, ...
    QString refusalCategory;  // stop_details.category on a refusal, if given
    QString error;            // an error event's message
};
StreamEvent parseStreamEvent(const QByteArray &data);

// Parse GET /models. Ids keep the API's order (newest first).
ModelListResult parseModelsResponse(const QByteArray &body);

// Message for the user when Claude declines, with a way forward.
QString refusalMessage(const QString &category);

// Note appended when a reply hits kMaxTokens, and the error for a reply with
// no text.
QString cutOffNote();
QString emptyReplyErrorText(const QString &stopReason);

// ---- Web research (Anthropic's server-side web search tool) ----

constexpr int kMaxSearches = 5; // per research turn: at most 5 cents at $10 per 1,000 searches

// A web page found by a search or cited in the reply.
struct WebSource {
    QString url;
    QString title;
    QString pageAge;   // "when the site was last updated", if given
    QString citedText; // for citations: up to 150 characters quoted
};

// The web search tool definition. The basic version works on every model.
QJsonObject webSearchTool();

// Rebuilds the assistant's content blocks from a stream, exactly as the API
// sent them (needed to resume a paused turn), and reports what each event
// added.
class ContentAccumulator {
public:
    struct Update {
        QString text;
        QString thinking;
        QString searchQuery;        // a search Claude just started
        QList<WebSource> results;   // results of a search that just finished
        QString searchError;        // error code of a search that failed
        bool hasCitation = false;
        WebSource citation;
    };

    Update apply(const QByteArray &eventData);

    QJsonArray blocks() const;
    QString stopReason() const { return stopReason_; }
    QString refusalCategory() const { return refusalCategory_; }
    QString error() const { return error_; }
    QString text() const { return text_; }

private:
    QMap<int, QJsonObject> blocks_;
    QMap<int, QString> partialJson_;
    QString stopReason_, refusalCategory_, error_, text_;
};

// Message for a failed search, by error code.
QString searchErrorText(const QString &code);

} // namespace anthropic

class AnthropicBackend : public HttpBackend {
    Q_OBJECT
public:
    using HttpBackend::HttpBackend;

    void chat(const QList<ChatMessage> &messages, ChatCallback done) override;
    void chatStream(const QList<ChatMessage> &messages, DeltaCallback onDelta, ChatCallback done,
                    DeltaCallback onReasoning = nullptr) override;
    void listModels(ModelsCallback done) override;

    // A streamed reply with the web search tool available. Paused turns are
    // resumed automatically (up to twice).
    struct ResearchCallbacks {
        DeltaCallback onText;
        DeltaCallback onReasoning;
        std::function<void(const QString &query)> onSearch;
        std::function<void(const QList<anthropic::WebSource> &results, const QString &error)> onResults;
        std::function<void(const anthropic::WebSource &citation)> onCitation;
    };
    void research(const QList<ChatMessage> &messages, const ResearchCallbacks &callbacks, ChatCallback done);

protected:
    void addHeaders(QNetworkRequest *request, const QString &key) const override;

private:
    void researchRequest(const QJsonArray &messages, const QString &system, const ResearchCallbacks &cb,
                         ChatCallback done, int resumes, const QString &textSoFar);

    QByteArray beta_; // anthropic-beta header for the next request, if any
};

} // namespace smartshark
