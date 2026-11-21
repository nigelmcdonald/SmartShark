/* ip_lookup.h
 *
 * Online facts about public IP addresses: reverse DNS through the system
 * resolver, and the registered owner through RDAP (rdap.org, which forwards to
 * the regional registry). Only the IP addresses are sent. Runs only when the
 * user has allowed online lookups.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <functional>

#include <QHash>
#include <QList>
#include <QObject>

#include "core/ip_facts.h"

class QNetworkAccessManager;

namespace smartshark {

class IpLookup : public QObject {
    Q_OBJECT
public:
    explicit IpLookup(QObject *parent = nullptr);
    ~IpLookup() override;

    // Look up every public address in facts and call done with the updated
    // list. Private addresses pass through unchanged. done runs once, unless
    // cancel() is called or the object is destroyed first.
    void lookup(const QList<IpFacts> &facts, std::function<void(const QList<IpFacts> &)> done);
    void cancel();

private:
    struct Job;
    void finishOne(const std::shared_ptr<Job> &job);

    QNetworkAccessManager *nam_;
    std::shared_ptr<Job> current_;
    QList<int> hostLookups_;
    QHash<QString, IpFacts> cache_; // per session, so a capture's addresses are looked up once
};

} // namespace smartshark
