/* http_backend.h
 *
 * What every network chat backend shares: one request at a time, URL and key
 * checks, no redirects to other hosts, size limits, a hard time limit on
 * streamed replies, and readable error messages.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QByteArray>
#include <QObject>
#include <QPointer>

#include "core/chat.h"
#include "core/provider.h"

class QNetworkAccessManager;
class QNetworkReply;
class QNetworkRequest;

namespace smartshark {

class HttpBackend : public QObject, public ChatBackend {
    Q_OBJECT
public:
    HttpBackend(const ProviderConfig &config, QObject *parent = nullptr);
    ~HttpBackend() override;

    void cancel() override;
    QString describe() const override;

    // Longest a streamed reply may run, however steadily it arrives. Stops a
    // model that is stuck repeating itself.
    static constexpr int kMaxStreamSeconds = 600;

protected:
    // Sends the request (GET if postBody is null). Returns nullptr and sets
    // *error if the settings are unsafe or invalid. A previous request still
    // in flight is cancelled. With streamDeadline, the reply is aborted after
    // kMaxStreamSeconds.
    QNetworkReply *send(const QString &path, const QByteArray *postBody, QString *error, qint64 maxBytes = 4 << 20,
                        bool streamDeadline = false);

    // Add the provider's authentication and version headers. key is checked
    // and may be empty.
    virtual void addHeaders(QNetworkRequest *request, const QString &key) const = 0;

    QString describeNetworkError(QNetworkReply *reply, const QByteArray &body) const;

    ProviderConfig config_;
    QNetworkAccessManager *nam_;
    QPointer<QNetworkReply> pending_;
};

// The backend for the provider's API kind. The caller owns it through parent.
HttpBackend *createBackend(const ProviderConfig &config, QObject *parent);

// Error text when a reply passes guard::kMaxReplyChars and is stopped.
QString replyTooLongError();

} // namespace smartshark
