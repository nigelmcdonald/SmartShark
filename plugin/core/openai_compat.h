/* openai_compat.h
 *
 * Backend for servers that speak the OpenAI Chat Completions API: OpenAI,
 * Gemini (its OpenAI endpoint), Kimi, DeepSeek, LM Studio, Ollama,
 * llama.cpp's llama-server, vLLM and others.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QByteArray>
#include <QJsonObject>

#include "core/chat.h"
#include "core/http_backend.h"
#include "core/provider.h"

namespace smartshark {

namespace openai {

// Request body for POST /chat/completions. Sampling parameters are left out on
// purpose: several current models reject any non-default temperature.
QJsonObject buildChatBody(const QString &model, const QList<ChatMessage> &messages, bool stream = false);

// Parse a /chat/completions response body.
ChatResult parseChatResponse(const QByteArray &body);

// Parse a GET /models response body. Model ids come back sorted.
ModelListResult parseModelsResponse(const QByteArray &body);

// Best-effort error text from an error response body, or an empty string.
QString parseErrorMessage(const QByteArray &body);

} // namespace openai

class OpenAiCompatBackend : public HttpBackend {
    Q_OBJECT
public:
    using HttpBackend::HttpBackend;

    void chat(const QList<ChatMessage> &messages, ChatCallback done) override;
    void chatStream(const QList<ChatMessage> &messages, DeltaCallback onDelta, ChatCallback done,
                    DeltaCallback onReasoning = nullptr) override;
    void listModels(ModelsCallback done) override;

protected:
    void addHeaders(QNetworkRequest *request, const QString &key) const override;
};

} // namespace smartshark
