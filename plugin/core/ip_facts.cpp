/* ip_facts.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "core/ip_facts.h"

#include <QHash>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include "core/input_guard.h"

namespace smartshark {

namespace {

struct Range {
    const char *cidr;
    const char *kind;
    bool isPublic;
};

// Checked in order; the first match wins. Sources: IANA special-purpose registries.
const Range kRanges[] = {
    {"127.0.0.0/8", "Loopback (this computer)", false},
    {"10.0.0.0/8", "Private (RFC 1918), a local network", false},
    {"172.16.0.0/12", "Private (RFC 1918), a local network", false},
    {"192.168.0.0/16", "Private (RFC 1918), a local network", false},
    {"100.64.0.0/10", "Carrier-grade NAT (shared address space used by ISPs)", false},
    {"169.254.0.0/16", "Link-local (self-assigned, no DHCP)", false},
    {"0.0.0.0/8", "Unspecified / this network", false},
    {"192.0.2.0/24", "Documentation example range", false},
    {"198.51.100.0/24", "Documentation example range", false},
    {"203.0.113.0/24", "Documentation example range", false},
    {"198.18.0.0/15", "Benchmark testing range", false},
    {"224.0.0.0/4", "Multicast (sent to a group of devices)", false},
    {"240.0.0.0/4", "Reserved", false},
    {"::1/128", "Loopback (this computer)", false},
    {"fe80::/10", "Link-local (only valid on this network segment)", false},
    {"fc00::/7", "Unique local (private IPv6), a local network", false},
    {"ff00::/8", "Multicast (sent to a group of devices)", false},
    {"2001:db8::/32", "Documentation example range", false},
    {"64:ff9b::/96", "IPv4/IPv6 translation (NAT64)", true},
    {"2000::/3", "Public (global unicast)", true},
};

const QHash<QString, QString> &wellKnownAddresses()
{
    static const QHash<QString, QString> map = {
        {QStringLiteral("8.8.8.8"), QStringLiteral("Google Public DNS")},
        {QStringLiteral("8.8.4.4"), QStringLiteral("Google Public DNS")},
        {QStringLiteral("2001:4860:4860::8888"), QStringLiteral("Google Public DNS")},
        {QStringLiteral("2001:4860:4860::8844"), QStringLiteral("Google Public DNS")},
        {QStringLiteral("1.1.1.1"), QStringLiteral("Cloudflare DNS")},
        {QStringLiteral("1.0.0.1"), QStringLiteral("Cloudflare DNS")},
        {QStringLiteral("2606:4700:4700::1111"), QStringLiteral("Cloudflare DNS")},
        {QStringLiteral("2606:4700:4700::1001"), QStringLiteral("Cloudflare DNS")},
        {QStringLiteral("9.9.9.9"), QStringLiteral("Quad9 DNS")},
        {QStringLiteral("149.112.112.112"), QStringLiteral("Quad9 DNS")},
        {QStringLiteral("208.67.222.222"), QStringLiteral("OpenDNS (Cisco)")},
        {QStringLiteral("208.67.220.220"), QStringLiteral("OpenDNS (Cisco)")},
        {QStringLiteral("255.255.255.255"), QStringLiteral("Broadcast to every device on the local network")},
        {QStringLiteral("224.0.0.1"), QStringLiteral("All hosts on this network (multicast)")},
        {QStringLiteral("224.0.0.251"), QStringLiteral("mDNS (local name discovery, e.g. Bonjour)")},
        {QStringLiteral("ff02::fb"), QStringLiteral("mDNS (local name discovery, e.g. Bonjour)")},
        {QStringLiteral("224.0.0.252"), QStringLiteral("LLMNR (Windows local name resolution)")},
        {QStringLiteral("ff02::1:3"), QStringLiteral("LLMNR (Windows local name resolution)")},
        {QStringLiteral("239.255.255.250"), QStringLiteral("SSDP / UPnP (device discovery)")},
        {QStringLiteral("ff02::c"), QStringLiteral("SSDP / UPnP (device discovery)")},
        {QStringLiteral("ff02::1"), QStringLiteral("All nodes on this network segment (multicast)")},
        {QStringLiteral("ff02::2"), QStringLiteral("All routers on this network segment (multicast)")},
        {QStringLiteral("224.0.0.22"), QStringLiteral("IGMP (multicast group management)")},
    };
    return map;
}

// Names and registry records come from the network: show them literally in a
// Markdown table, on one line.
QString cell(const QString &text)
{
    const QString t = guard::singleLine(text, 200);
    return t.isEmpty() ? QStringLiteral("-") : guard::escapeMarkdown(t);
}

QString vcardName(const QJsonObject &entity)
{
    // vcardArray: ["vcard", [["fn", {}, "text", "Google LLC"], ...]]
    const QJsonArray vcard = entity.value(QStringLiteral("vcardArray")).toArray();
    const QJsonArray props = vcard.at(1).toArray();
    for (const QJsonValue &p : props) {
        const QJsonArray prop = p.toArray();
        if (prop.at(0).toString() == QLatin1String("fn"))
            return prop.at(3).toString();
    }
    return QString();
}

} // namespace

IpFacts classifyAddress(const QString &address)
{
    IpFacts f;
    f.address = address.trimmed();
    QHostAddress addr;
    if (!addr.setAddress(f.address)) {
        f.kind = QStringLiteral("Not an IP address");
        return f;
    }
    // An IPv4 address written as IPv6 (::ffff:a.b.c.d) is classified as IPv4.
    bool mapped = false;
    const quint32 v4 = addr.toIPv4Address(&mapped);
    if (mapped && addr.protocol() == QAbstractSocket::IPv6Protocol)
        addr = QHostAddress(v4);

    f.address = addr.toString();
    f.wellKnown = wellKnownAddresses().value(f.address);

    for (const Range &r : kRanges) {
        const auto subnet = QHostAddress::parseSubnet(QString::fromLatin1(r.cidr));
        if (addr.isInSubnet(subnet)) {
            f.kind = QString::fromLatin1(r.kind);
            f.isPublic = r.isPublic;
            return f;
        }
    }
    if (addr.protocol() == QAbstractSocket::IPv4Protocol) {
        f.kind = QStringLiteral("Public (internet)");
        f.isPublic = true;
    } else {
        f.kind = QStringLiteral("Other IPv6");
    }
    return f;
}

bool applyRdap(const QByteArray &body, IpFacts *facts)
{
    QJsonParseError perr;
    const QJsonDocument doc = QJsonDocument::fromJson(body, &perr);
    if (perr.error != QJsonParseError::NoError || !doc.isObject())
        return false;
    const QJsonObject root = doc.object();
    if (root.value(QStringLiteral("objectClassName")).toString() != QLatin1String("ip network"))
        return false;

    facts->network = root.value(QStringLiteral("name")).toString();
    facts->country = root.value(QStringLiteral("country")).toString();
    const QString start = root.value(QStringLiteral("startAddress")).toString();
    const QString end = root.value(QStringLiteral("endAddress")).toString();
    if (!start.isEmpty() && !end.isEmpty())
        facts->range = start + QStringLiteral(" - ") + end;

    // The owner is the entity with the "registrant" role, else any named entity.
    QString fallback;
    for (const QJsonValue &v : root.value(QStringLiteral("entities")).toArray()) {
        const QJsonObject e = v.toObject();
        const QString name = vcardName(e);
        if (name.isEmpty())
            continue;
        const QJsonArray roles = e.value(QStringLiteral("roles")).toArray();
        if (roles.contains(QStringLiteral("registrant"))) {
            facts->owner = name;
            break;
        }
        if (fallback.isEmpty())
            fallback = name;
    }
    if (facts->owner.isEmpty())
        facts->owner = fallback;
    facts->lookedUp = true;
    return true;
}

QString factsTable(const QList<IpFacts> &facts)
{
    bool anyOnline = false;
    for (const IpFacts &f : facts)
        anyOnline = anyOnline || f.lookedUp || !f.reverseDns.isEmpty();

    QString md = anyOnline ? QStringLiteral("| Address | Type | Known as | Owner (registry) | Reverse DNS |\n"
                                            "|---|---|---|---|---|\n")
                           : QStringLiteral("| Address | Type | Known as |\n|---|---|---|\n");
    for (const IpFacts &f : facts) {
        QString known = f.wellKnown;
        if (!f.wiresharkName.isEmpty())
            known = known.isEmpty() ? f.wiresharkName : known + QStringLiteral(" / ") + f.wiresharkName;
        md += QStringLiteral("| %1 | %2 | %3 |").arg(cell(f.address), cell(f.kind), cell(known));
        if (anyOnline) {
            QString owner = f.owner;
            if (!f.country.isEmpty())
                owner += QStringLiteral(" (%1)").arg(f.country);
            if (owner.isEmpty() && !f.lookupError.isEmpty())
                owner = f.lookupError;
            md += QStringLiteral(" %1 | %2 |").arg(cell(owner), cell(f.reverseDns));
        }
        md += QLatin1Char('\n');
    }
    return md;
}

QString factsForPrompt(const QList<IpFacts> &facts)
{
    QString out;
    for (const IpFacts &f : facts) {
        out += QStringLiteral("- %1: %2").arg(f.address, f.kind);
        if (!f.wellKnown.isEmpty())
            out += QStringLiteral("; well known as %1").arg(f.wellKnown);
        if (!f.wiresharkName.isEmpty())
            out += QStringLiteral("; Wireshark resolved it to %1").arg(guard::singleLine(f.wiresharkName, 200));
        if (!f.reverseDns.isEmpty())
            out += QStringLiteral("; reverse DNS: %1").arg(guard::singleLine(f.reverseDns, 200));
        if (!f.owner.isEmpty())
            out += QStringLiteral("; registry owner: %1").arg(guard::singleLine(f.owner, 200));
        if (!f.network.isEmpty())
            out += QStringLiteral("; network name: %1").arg(guard::singleLine(f.network, 100));
        if (!f.country.isEmpty())
            out += QStringLiteral("; country: %1").arg(guard::singleLine(f.country, 20));
        if (!f.range.isEmpty())
            out += QStringLiteral("; address block: %1").arg(guard::singleLine(f.range, 100));
        out += QLatin1Char('\n');
    }
    return out;
}

} // namespace smartshark
