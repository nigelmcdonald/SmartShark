/* ip_lookup.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ui/ip_lookup.h"

#include <memory>

#include <QHostInfo>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QPointer>
#include <QUrl>

#include "core/input_guard.h"
#include "core/privacy.h"

namespace smartshark {

namespace {
constexpr int kTimeoutMs = 8000;
constexpr qint64 kMaxRdapBytes = 512 * 1024;
} // namespace

struct IpLookup::Job {
    QList<IpFacts> facts;
    std::function<void(const QList<IpFacts> &)> done;
    int pending = 0;
    bool cancelled = false;
    QList<QPointer<QNetworkReply>> replies;
};

IpLookup::IpLookup(QObject *parent) : QObject(parent), nam_(new QNetworkAccessManager(this)) {}

IpLookup::~IpLookup()
{
    cancel();
}

void IpLookup::cancel()
{
    for (int id : hostLookups_)
        QHostInfo::abortHostLookup(id);
    hostLookups_.clear();
    if (current_) {
        current_->cancelled = true;
        for (const QPointer<QNetworkReply> &r : current_->replies) {
            if (r) {
                r->disconnect(this);
                r->abort();
                r->deleteLater();
            }
        }
        current_.reset();
    }
}

void IpLookup::finishOne(const std::shared_ptr<Job> &job)
{
    if (job->cancelled)
        return;
    if (--job->pending > 0)
        return;
    for (const IpFacts &f : job->facts) {
        if (f.isPublic)
            cache_.insert(f.address, f);
    }
    if (current_ == job)
        current_.reset();
    hostLookups_.clear();
    job->done(job->facts);
}

void IpLookup::lookup(const QList<IpFacts> &facts, std::function<void(const QList<IpFacts> &)> done,
                      const QStringList &skip)
{
    cancel();
    auto job = std::make_shared<Job>();
    job->facts = facts;
    job->done = std::move(done);
    current_ = job;

    for (int i = 0; i < job->facts.size(); ++i) {
        IpFacts &f = job->facts[i];
        if (!f.isPublic || skip.contains(normaliseAddress(f.address)))
            continue;
        if (cache_.contains(f.address)) {
            const QString wsName = f.wiresharkName;
            f = cache_.value(f.address);
            f.wiresharkName = wsName;
            continue;
        }

        // Owner, from the registry. rdap.org redirects to the right registry,
        // so cross-host redirects are allowed here (no credentials are sent).
        QNetworkRequest req(QUrl(QStringLiteral("https://rdap.org/ip/") + f.address));
        req.setRawHeader("Accept", "application/rdap+json, application/json");
        req.setHeader(QNetworkRequest::UserAgentHeader, QStringLiteral("SmartShark"));
        req.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);
        req.setTransferTimeout(kTimeoutMs);
        QNetworkReply *reply = nam_->get(req);
        job->replies.append(reply);
        job->pending++;
        connect(reply, &QNetworkReply::downloadProgress, this, [reply](qint64 received, qint64) {
            if (received > kMaxRdapBytes)
                reply->abort();
        });
        connect(reply, &QNetworkReply::finished, this, [this, job, reply, i]() {
            reply->deleteLater();
            if (job->cancelled)
                return;
            IpFacts &target = job->facts[i];
            if (reply->error() == QNetworkReply::NoError) {
                if (!applyRdap(reply->readAll(), &target))
                    target.lookupError = QStringLiteral("registry reply not understood");
            } else {
                target.lookupError = QStringLiteral("registry lookup failed");
            }
            target.lookedUp = true;
            finishOne(job);
        });

        // Reverse DNS, through the system resolver.
        job->pending++;
        const int id = QHostInfo::lookupHost(f.address, this, [this, job, i](const QHostInfo &info) {
            if (job->cancelled)
                return;
            const QString name = info.hostName();
            if (info.error() == QHostInfo::NoError && name != job->facts[i].address)
                job->facts[i].reverseDns = guard::singleLine(name, 253);
            finishOne(job);
        });
        hostLookups_.append(id);
    }

    if (job->pending == 0) {
        // Nothing to look up (or all cached): answer on the next event loop turn,
        // so callers see the same asynchronous behaviour either way.
        job->pending = 1;
        QMetaObject::invokeMethod(this, [this, job]() { finishOne(job); }, Qt::QueuedConnection);
    }
}

} // namespace smartshark
