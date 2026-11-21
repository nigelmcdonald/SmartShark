/* capture_stats.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "core/capture_stats.h"

#include <algorithm>

#include <QLocale>

#include "core/input_guard.h"

namespace smartshark {

namespace {

constexpr int kTableKeys = 20000; // per table, so a huge capture cannot exhaust memory

QString human(quint64 bytes)
{
    return QLocale().formattedDataSize(static_cast<qint64>(bytes), 1, QLocale::DataSizeTraditionalFormat);
}

// Names come from the network; keep them on one line and short.
QString clean(const QString &s)
{
    return guard::singleLine(s, 120);
}

// Names come from the network: show them literally in a Markdown table.
QString cell(const QString &s)
{
    return guard::escapeMarkdown(clean(s));
}

} // namespace

void CaptureStats::bump(QHash<QString, CountedItem> &table, const QString &key, quint32 length)
{
    if (key.isEmpty())
        return;
    auto it = table.find(key);
    if (it == table.end()) {
        if (table.size() >= kTableKeys)
            return;
        it = table.insert(key, CountedItem{key, 0, 0});
    }
    it->packets++;
    it->bytes += length;
}

QList<CountedItem> CaptureStats::top(const QHash<QString, CountedItem> &table, int n)
{
    QList<CountedItem> items = table.values();
    std::sort(items.begin(), items.end(), [](const CountedItem &a, const CountedItem &b) {
        if (a.packets != b.packets)
            return a.packets > b.packets;
        return a.name < b.name;
    });
    if (items.size() > n)
        items.resize(n);
    return items;
}

void CaptureStats::add(const PacketRecord &p)
{
    if (packets_ == 0) {
        firstTime_ = lastTime_ = p.time;
    } else {
        firstTime_ = qMin(firstTime_, p.time);
        lastTime_ = qMax(lastTime_, p.time);
    }
    packets_++;
    bytes_ += p.length;

    bump(protocols_, p.protocol.isEmpty() ? QStringLiteral("(unknown)") : clean(p.protocol), p.length);

    const QString src = clean(p.src), dst = clean(p.dst);
    bump(endpoints_, src, p.length);
    if (dst != src)
        bump(endpoints_, dst, p.length);

    if (!src.isEmpty() && !dst.isEmpty()) {
        // Order the pair so both directions count as one conversation.
        const bool swap = dst < src;
        const QString a = swap ? dst : src, b = swap ? src : dst;
        QString key = a + QStringLiteral(" <-> ") + b;
        if (!p.transport.isEmpty()) {
            const quint16 serverPort = qMin(p.srcPort, p.dstPort); // usually the service port
            key += QStringLiteral(" (%1 %2)").arg(p.transport).arg(serverPort);
        }
        bump(conversations_, key, p.length);
    }

    if (p.transport == QLatin1String("TCP")) {
        if (p.tcpSyn && !p.tcpAck) {
            synCount_++;
            bump(connSources_, src, p.length);
            if (!dst.isEmpty())
                bump(connDests_, QStringLiteral("%1 port %2").arg(dst).arg(p.dstPort), p.length);
        }
        if (p.tcpReset) {
            resetCount_++;
            bump(resets_, src, p.length);
        }
        if (p.retransmission) {
            retransCount_++;
            bump(retrans_, src, p.length);
        }
    }

    bump(dnsNames_, clean(p.dnsName).toLower(), p.length);
    bump(tlsServers_, clean(p.tlsServer).toLower(), p.length);
    bump(httpHosts_, clean(p.httpHost).toLower(), p.length);
}

QList<CountedItem> CaptureStats::topProtocols(int n) const { return top(protocols_, n); }
QList<CountedItem> CaptureStats::topEndpoints(int n) const { return top(endpoints_, n); }
QList<CountedItem> CaptureStats::topConversations(int n) const { return top(conversations_, n); }
QList<CountedItem> CaptureStats::topConnectionSources(int n) const { return top(connSources_, n); }
QList<CountedItem> CaptureStats::topConnectionDestinations(int n) const { return top(connDests_, n); }
QList<CountedItem> CaptureStats::topResets(int n) const { return top(resets_, n); }
QList<CountedItem> CaptureStats::topRetransmitters(int n) const { return top(retrans_, n); }
QList<CountedItem> CaptureStats::topDnsNames(int n) const { return top(dnsNames_, n); }
QList<CountedItem> CaptureStats::topTlsServers(int n) const { return top(tlsServers_, n); }
QList<CountedItem> CaptureStats::topHttpHosts(int n) const { return top(httpHosts_, n); }

QStringList CaptureStats::addresses(int n) const
{
    QStringList out;
    for (const CountedItem &i : top(endpoints_, n))
        out.append(i.name);
    return out;
}

QString CaptureStats::summaryForPrompt(int maxChars) const
{
    QString out;
    out += QStringLiteral("Packets: %1, bytes: %2, duration: %3 s\n")
               .arg(packets_)
               .arg(bytes_)
               .arg(durationSeconds(), 0, 'f', 1);
    out += QStringLiteral("TCP connection attempts (SYN): %1, TCP resets: %2, retransmissions: %3\n")
               .arg(synCount_)
               .arg(resetCount_)
               .arg(retransCount_);

    auto section = [&](const QString &title, const QList<CountedItem> &items, bool withBytes) {
        if (items.isEmpty())
            return;
        out += title + QStringLiteral(":\n");
        for (const CountedItem &i : items) {
            out += QStringLiteral("- %1: %2 packets").arg(i.name).arg(i.packets);
            if (withBytes)
                out += QStringLiteral(", %1 bytes").arg(i.bytes);
            out += QLatin1Char('\n');
        }
    };
    section(QStringLiteral("Protocols (highest layer)"), topProtocols(15), true);
    section(QStringLiteral("Endpoints (packets sent or received)"), topEndpoints(15), true);
    section(QStringLiteral("Conversations"), topConversations(15), true);
    section(QStringLiteral("Hosts opening the most TCP connections (SYN count)"), topConnectionSources(10), false);
    section(QStringLiteral("Servers receiving the most TCP connections"), topConnectionDestinations(10), false);
    section(QStringLiteral("Hosts sending TCP resets"), topResets(10), false);
    section(QStringLiteral("Hosts with retransmissions"), topRetransmitters(10), false);
    section(QStringLiteral("DNS names queried"), topDnsNames(15), false);
    section(QStringLiteral("TLS server names (SNI)"), topTlsServers(15), false);
    section(QStringLiteral("HTTP hosts"), topHttpHosts(10), false);

    if (out.size() > maxChars) {
        out.truncate(maxChars);
        out += QStringLiteral("\n(shortened)");
    }
    return out;
}

QString CaptureStats::markdown() const
{
    QString md = QStringLiteral("**%1 packets, %2, over %3 seconds.** %4 TCP connection attempts, %5 resets, "
                                "%6 retransmissions.\n\n")
                     .arg(QLocale().toString(packets_))
                     .arg(human(bytes_))
                     .arg(durationSeconds(), 0, 'f', 1)
                     .arg(QLocale().toString(synCount_))
                     .arg(QLocale().toString(resetCount_))
                     .arg(QLocale().toString(retransCount_));

    auto table = [&](const QString &title, const QString &col, const QList<CountedItem> &items, bool withBytes) {
        if (items.isEmpty())
            return;
        md += QStringLiteral("**%1**\n\n").arg(title);
        md += withBytes ? QStringLiteral("| %1 | Packets | Bytes |\n|---|---:|---:|\n").arg(col)
                        : QStringLiteral("| %1 | Count |\n|---|---:|\n").arg(col);
        for (const CountedItem &i : items) {
            md += QStringLiteral("| %1 | %2 |").arg(cell(i.name), QLocale().toString(i.packets));
            if (withBytes)
                md += QStringLiteral(" %1 |").arg(human(i.bytes));
            md += QLatin1Char('\n');
        }
        md += QLatin1Char('\n');
    };
    table(QStringLiteral("Protocols"), QStringLiteral("Protocol"), topProtocols(10), true);
    table(QStringLiteral("Top talkers"), QStringLiteral("Address"), topEndpoints(10), true);
    table(QStringLiteral("Top conversations"), QStringLiteral("Between"), topConversations(10), true);
    table(QStringLiteral("Hosts opening the most connections"), QStringLiteral("Address"), topConnectionSources(10),
          false);
    table(QStringLiteral("Servers receiving the most connections"), QStringLiteral("Server"),
          topConnectionDestinations(10), false);
    table(QStringLiteral("TCP resets sent by"), QStringLiteral("Address"), topResets(5), false);
    table(QStringLiteral("Retransmissions from"), QStringLiteral("Address"), topRetransmitters(5), false);
    table(QStringLiteral("DNS names looked up"), QStringLiteral("Name"), topDnsNames(10), false);
    table(QStringLiteral("TLS server names"), QStringLiteral("Name"), topTlsServers(10), false);
    table(QStringLiteral("HTTP hosts"), QStringLiteral("Host"), topHttpHosts(10), false);
    return md;
}

} // namespace smartshark
