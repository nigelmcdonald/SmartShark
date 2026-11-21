/* http_backend.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "core/http_backend.h"

#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QTimer>
#include <QUrl>

#include "core/anthropic_backend.h"
#include "core/input_guard.h"
#include "core/openai_compat.h"

namespace smartshark {

HttpBackend::HttpBackend(const ProviderConfig &config, QObject *parent)
    : QObject(parent), config_(config), nam_(new QNetworkAccessManager(this))
{
}

HttpBackend::~HttpBackend()
{
    cancel();
}

void HttpBackend::cancel()
{
    if (pending_) {
        QNetworkReply *reply = pending_;
        pending_ = nullptr;
        // Disconnect first, so abort() does not run the callback.
        reply->disconnect(this);
        reply->abort();
        reply->deleteLater();
    }
}

QString HttpBackend::describe() const
{
    const ProviderPreset *preset = findPreset(config_.providerId);
    const QString name = preset ? preset->displayName : config_.baseUrl;
    return config_.model.isEmpty() ? name : name + QStringLiteral(" / ") + config_.model;
}

QNetworkReply *HttpBackend::send(const QString &path, const QByteArray *postBody, QString *error, qint64 maxBytes,
                                 bool streamDeadline)
{
    cancel(); // one request at a time

    const QString urlProblem = guard::checkBaseUrl(config_.baseUrl, !config_.apiKey.isEmpty());
    if (!urlProblem.isEmpty()) {
        *error = urlProblem;
        return nullptr;
    }
    QString keyProblem;
    const QString key = guard::cleanApiKey(config_.apiKey, &keyProblem);
    if (!keyProblem.isEmpty()) {
        *error = keyProblem;
        return nullptr;
    }

    QNetworkRequest req(QUrl(joinUrl(config_.baseUrl, path)));
    req.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    req.setRawHeader("Accept", "application/json, text/event-stream");
    req.setHeader(QNetworkRequest::UserAgentHeader, QStringLiteral("SmartShark"));
    addHeaders(&req, key);
    req.setTransferTimeout(config_.timeoutSec * 1000);
    // Never follow a redirect to another host: it would carry the API key there.
    req.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::SameOriginRedirectPolicy);

    QNetworkReply *reply = postBody ? nam_->post(req, *postBody) : nam_->get(req);
    pending_ = reply;

    // Refuse oversized replies instead of buffering them.
    reply->setProperty("smartshark_max_bytes", maxBytes);
    connect(reply, &QNetworkReply::downloadProgress, this, [reply, maxBytes](qint64 received, qint64) {
        if (received > maxBytes && !reply->property("smartshark_too_large").toBool()) {
            reply->setProperty("smartshark_too_large", true);
            reply->abort();
        }
    });

    if (streamDeadline) {
        auto *deadline = new QTimer(reply); // dies with the reply
        deadline->setSingleShot(true);
        connect(deadline, &QTimer::timeout, reply, [reply]() {
            reply->setProperty("smartshark_deadline", true);
            reply->abort();
        });
        deadline->start(kMaxStreamSeconds * 1000);
    }
    return reply;
}

QString HttpBackend::describeNetworkError(QNetworkReply *reply, const QByteArray &body) const
{
    const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    // Also reads Anthropic's error shape. Shortened: a hostile server could send megabytes.
    const QString apiMessage = guard::singleLine(openai::parseErrorMessage(body), 500);

    if (reply->property("smartshark_too_large").toBool())
        return QStringLiteral("The server's reply was larger than %1 MB, so SmartShark stopped reading it.")
            .arg(reply->property("smartshark_max_bytes").toLongLong() >> 20);
    if (reply->property("smartshark_deadline").toBool())
        return QStringLiteral("The reply was still going after %1 minutes, so SmartShark stopped it. The model may "
                              "have got stuck repeating itself. Try again, ask a shorter question, or choose "
                              "another model in Settings.")
            .arg(kMaxStreamSeconds / 60);

    switch (reply->error()) {
    case QNetworkReply::ConnectionRefusedError:
    case QNetworkReply::HostNotFoundError:
        if (const ProviderPreset *p = findPreset(config_.providerId); p && p->isLocal)
            return QStringLiteral("Could not reach %1 at %2. Is it running, with its server started?")
                .arg(p->displayName, config_.baseUrl);
        return QStringLiteral("Could not reach %1.").arg(config_.baseUrl);
    case QNetworkReply::OperationCanceledError:
    case QNetworkReply::TimeoutError:
        return QStringLiteral("The server sent nothing for %1 seconds, so SmartShark gave up. You can raise the "
                              "timeout in Settings.")
            .arg(config_.timeoutSec);
    default:
        break;
    }

    if (status == 401 || status == 403)
        return QStringLiteral("The server rejected the API key (HTTP %1). %2").arg(status).arg(apiMessage).trimmed();
    if (status == 429)
        return QStringLiteral("Rate limited or out of quota (HTTP 429). %1").arg(apiMessage).trimmed();
    if (status == 529)
        return QStringLiteral("The provider is overloaded right now (HTTP 529). Try again in a minute.");
    if (status != 0)
        return QStringLiteral("HTTP %1: %2")
            .arg(status)
            .arg(apiMessage.isEmpty() ? reply->errorString() : apiMessage);
    return reply->errorString();
}

QString replyTooLongError()
{
    return QStringLiteral("The reply grew past %1 characters, so SmartShark stopped it. The model may have got stuck "
                          "repeating itself. Try again, or choose another model.")
        .arg(guard::kMaxReplyChars);
}

HttpBackend *createBackend(const ProviderConfig &config, QObject *parent)
{
    switch (config.api) {
    case ApiKind::AnthropicMessages: return new AnthropicBackend(config, parent);
    case ApiKind::OpenAiCompatible: break;
    }
    return new OpenAiCompatBackend(config, parent);
}

} // namespace smartshark
