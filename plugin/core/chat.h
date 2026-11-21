/* chat.h
 *
 * Provider-neutral chat types and the backend interface. The filter and
 * summary features talk to this interface, so tests can swap in a fake.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <functional>

#include <QList>
#include <QString>
#include <QStringList>

namespace smartshark {

struct ChatMessage {
    enum class Role { System, User, Assistant };
    Role role;
    QString content;
};

struct ChatResult {
    bool ok = false;
    QString text;   // the model's reply when ok
    QString error;  // human-readable reason when not ok
};

struct ModelListResult {
    bool ok = false;
    QStringList models;
    QString error;
};

class ChatBackend {
public:
    using ChatCallback = std::function<void(const ChatResult &)>;
    using ModelsCallback = std::function<void(const ModelListResult &)>;

    virtual ~ChatBackend() = default;

    // Send a conversation and get the reply. The callback runs exactly once, on
    // the thread that called chat(), unless the backend is destroyed or
    // cancel() is called first; then it never runs.
    virtual void chat(const QList<ChatMessage> &messages, ChatCallback done) = 0;

    using DeltaCallback = std::function<void(const QString &delta)>;

    // Like chat(), but the reply arrives in pieces through onDelta as the model
    // writes it. done gets the whole reply at the end (or an error, with any
    // partial text in ChatResult::text). Backends that cannot stream deliver
    // the whole reply as a single delta. onReasoning, if set, receives the
    // model's reasoning as it streams, for servers that send it separately; it
    // is only for showing progress and is not part of the reply.
    virtual void chatStream(const QList<ChatMessage> &messages, DeltaCallback onDelta, ChatCallback done,
                            DeltaCallback onReasoning = nullptr)
    {
        Q_UNUSED(onReasoning);
        chat(messages, [onDelta, done](const ChatResult &r) {
            if (r.ok)
                onDelta(r.text);
            done(r);
        });
    }

    // List the models the server offers. Same callback rules as chat().
    virtual void listModels(ModelsCallback done) = 0;

    // Drop any request in flight without calling its callback.
    virtual void cancel() = 0;

    // Short label for the UI, for example "LM Studio (local) / qwen3-8b".
    virtual QString describe() const = 0;
};

} // namespace smartshark
