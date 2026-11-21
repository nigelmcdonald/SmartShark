/* ip_facts.h
 *
 * Facts about IP addresses, gathered by SmartShark rather than guessed by a
 * model: the address class, well-known services, names Wireshark resolved,
 * and (only with the user's permission) reverse DNS and registry ownership.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QByteArray>
#include <QList>
#include <QString>

namespace smartshark {

struct IpFacts {
    QString address;
    QString kind;          // "Private (RFC 1918)", "Public", "Multicast", ...
    QString wellKnown;     // e.g. "Google Public DNS", empty if none
    bool isPublic = false; // worth looking up online
    QString wiresharkName; // name Wireshark resolved (from DNS seen in the capture), if any

    // Online lookups, only filled when the user allowed them.
    bool lookedUp = false;
    QString reverseDns;
    QString owner;   // organisation that holds the address block
    QString network; // network name in the registry
    QString country;
    QString range;   // e.g. "8.8.8.0 - 8.8.8.255"
    QString lookupError;
};

// Classify an IPv4 or IPv6 address. Unknown text yields kind "Not an IP address".
IpFacts classifyAddress(const QString &address);

// Fill the online fields from an RDAP "ip network" response. Returns false if
// the body is not usable RDAP.
bool applyRdap(const QByteArray &body, IpFacts *facts);

// The facts as Markdown table rows for the panel (header included).
QString factsTable(const QList<IpFacts> &facts);

// The facts as plain lines for the model.
QString factsForPrompt(const QList<IpFacts> &facts);

} // namespace smartshark
