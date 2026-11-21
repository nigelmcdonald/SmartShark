/* packet_explainer.h
 *
 * Prompts and reply handling for explaining a single packet.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QByteArray>
#include <QList>
#include <QMap>
#include <QString>
#include <QStringList>

#include "core/chat.h"
#include "core/ip_facts.h"

namespace smartshark {

// One block of bytes Wireshark shows for a packet: the frame itself, or data
// it reassembled, decompressed or decrypted ("Decrypted TLS", ...).
struct PayloadSource {
    QString name;       // e.g. "Frame", "Decrypted TLS", "Reassembled TCP"
    QByteArray bytes;   // capped
    int totalLength = 0;
};

// What SmartShark extracted from Wireshark about one packet.
struct PacketSnapshot {
    bool ok = false;
    QString error;        // why there is no packet, when !ok
    quint32 frameNumber = 0;
    QString protocols;    // e.g. "eth:ethertype:ip:tcp:tls"
    QString tree;         // the dissection tree, indented text
    bool truncated = false;

    QString sourceAddress, destinationAddress; // outermost IP layer, if any
    QString sourcePort, destinationPort;       // TCP or UDP, if any
    QList<IpFacts> addresses;                  // facts for each distinct address

    QList<PayloadSource> sources;
    bool encryptedWithoutKeys = false; // TLS or QUIC present, but nothing decrypted
};

// The sections the model is asked to write, in order.
enum class ExplainSection { Overview, Layers, Endpoints, Payload, Notable };

QString explainSectionTitle(ExplainSection s);

// System prompt for packet explanations.
QString explainSystemPrompt();

// First user message: the packet, its address facts and payload preview, all
// marked as untrusted data. The tree is capped at maxTreeChars, the decoded
// payload at payloadBytes (0 sends none).
QString explainPacketMessage(const PacketSnapshot &packet, int maxTreeChars, int payloadBytes);

// Follow-up question in the same conversation.
QString explainFollowUpMessage(const QString &question);

// Split a (possibly incomplete) Markdown reply into its sections by "## Title"
// headings. Text before the first known heading goes to Overview. Headings are
// matched loosely (case, '#' count, trailing colon).
QMap<ExplainSection, QString> splitExplanation(const QString &markdown);

// Bytes as readable text if they are mostly printable, else as a hex dump
// with an ASCII column. At most maxBytes are shown.
QString payloadPreview(const QByteArray &bytes, int maxBytes);

// Help shown when a packet is encrypted and Wireshark has no keys for it.
QString encryptedPayloadHelp();

} // namespace smartshark
