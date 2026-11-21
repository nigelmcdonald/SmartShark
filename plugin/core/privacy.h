/* privacy.h
 *
 * Privacy helpers for packet data sent to a model: deciding whether a server
 * is on the user's own computer or network, and replacing IP and MAC
 * addresses with consistent placeholders before sending.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QHash>
#include <QSet>
#include <QString>
#include <QStringList>

#include "core/provider.h"

namespace smartshark {

// True if a server at this base URL is on this computer or the local network:
// localhost, loopback, private or link-local IP addresses, and names that
// cannot be public (no dot, or ending in .local, .lan, .internal, .home.arpa).
// Packet data sent there does not go to an outside company.
bool isLocalServer(const QString &baseUrl);

// The host part of a base URL, lower case. Empty if the URL has none.
QString serverHost(const QString &baseUrl);

// Key under which the user's "send packet data" approval for this provider
// and server is remembered. A changed server URL needs a new approval.
QString cloudApprovalKey(const ProviderConfig &cfg);

// An IP address in the form AddressMasker compares (lower case, no IPv6
// scope id), or an empty string if the text is not an IP address.
QString normaliseAddress(const QString &text);

// Which addresses are replaced before packet data is sent.
enum class AddressMasking {
    Off,
    Mine, // the user's own public IP addresses, IPv6 addresses with a MAC built in, and MAC addresses
    All,  // every IP and MAC address
};

// Replaces IPv4, IPv6 and MAC addresses in text with placeholders (HOST-1,
// HOST-2, MAC-1, ...). The same address always gets the same placeholder, so
// one masker is used for a whole conversation, and unmask() maps the model's
// reply back to the real addresses for display.
//
// Addresses that identify no one are kept: unspecified (0.0.0.0, ::),
// loopback, multicast and the broadcast address 255.255.255.255.
// Host names are not masked, except that the listed own IPv4 addresses are
// also replaced in reverse-DNS names and in dashed form (host-a-b-c-d...).
// MAC addresses are recognised as aa:bb:cc:dd:ee:ff, aa-bb-..., aabb.ccdd.eeff
// and Wireshark's Maker_dd:ee:ff short forms; a device already seen is also
// replaced when written as aabbccddeeff or as hex-dump bytes on one line.
class AddressMasker {
public:
    // Default: every address. With Mine, only MAC addresses, IPv6 addresses
    // built from a MAC (EUI-64), and the listed addresses are replaced.
    void setScope(AddressMasking scope, const QStringList &ownAddresses = {});

    QString mask(const QString &text);
    QString unmask(const QString &text) const;

    int count() const { return static_cast<int>(original_.size()); }
    void clear();

private:
    QString tokenFor(const QString &key, const QString &original, bool mac);
    bool shouldMaskIp(const QString &key, bool eui64) const;

    bool all_ = true;
    QSet<QString> own_; // normalised addresses to mask when !all_

    QHash<QString, QString> token_;    // normalised address -> placeholder
    QHash<QString, QString> original_; // placeholder -> address as first seen
    int hosts_ = 0;
    int macs_ = 0;
};

} // namespace smartshark
