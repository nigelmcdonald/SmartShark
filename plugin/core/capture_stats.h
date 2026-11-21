/* capture_stats.h
 *
 * Statistics over the displayed packets, counted by SmartShark so the model
 * interprets real numbers instead of guessing: protocols, top talkers,
 * conversations, who opens the most connections, TCP problems and the names
 * hosts asked for (DNS, TLS server names, HTTP hosts).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QHash>
#include <QList>
#include <QString>

namespace smartshark {

// The fields SmartShark reads from one packet.
struct PacketRecord {
    double time = 0;     // seconds, any origin
    quint32 length = 0;  // bytes on the wire
    QString src, dst;    // IP addresses (outermost layer), may be empty
    QString transport;   // "TCP", "UDP" or empty
    quint16 srcPort = 0, dstPort = 0;
    QString protocol;    // highest layer, e.g. "dns", "tls"
    bool tcpSyn = false, tcpAck = false, tcpReset = false;
    bool retransmission = false;
    QString dnsName;     // queried name, for DNS queries
    QString tlsServer;   // TLS server name (SNI)
    QString httpHost;
};

struct CountedItem {
    QString name;
    quint64 packets = 0;
    quint64 bytes = 0;
};

class CaptureStats {
public:
    void add(const PacketRecord &p);

    quint64 packets() const { return packets_; }
    quint64 bytes() const { return bytes_; }
    double durationSeconds() const { return packets_ ? lastTime_ - firstTime_ : 0; }

    // Top entries, most packets first (ties broken by name).
    QList<CountedItem> topProtocols(int n) const;
    QList<CountedItem> topEndpoints(int n) const;      // by packets sent + received
    QList<CountedItem> topConversations(int n) const;  // "A <-> B (TCP 443)"
    QList<CountedItem> topConnectionSources(int n) const;      // hosts opening TCP connections (SYN)
    QList<CountedItem> topConnectionDestinations(int n) const; // servers receiving them, "addr:port"
    QList<CountedItem> topResets(int n) const;          // hosts sending TCP resets
    QList<CountedItem> topRetransmitters(int n) const;
    QList<CountedItem> topDnsNames(int n) const;
    QList<CountedItem> topTlsServers(int n) const;
    QList<CountedItem> topHttpHosts(int n) const;

    // Every distinct IP address seen, most packets first.
    QStringList addresses(int n) const;

    // Compact plain text for the model, at most maxChars.
    QString summaryForPrompt(int maxChars) const;

    // Markdown tables for the panel.
    QString markdown() const;

private:
    static void bump(QHash<QString, CountedItem> &table, const QString &key, quint32 length);
    static QList<CountedItem> top(const QHash<QString, CountedItem> &table, int n);

    quint64 packets_ = 0;
    quint64 bytes_ = 0;
    double firstTime_ = 0, lastTime_ = 0;
    quint64 synCount_ = 0, resetCount_ = 0, retransCount_ = 0;
    QHash<QString, CountedItem> protocols_, endpoints_, conversations_, connSources_, connDests_, resets_,
        retrans_, dnsNames_, tlsServers_, httpHosts_;
};

} // namespace smartshark
