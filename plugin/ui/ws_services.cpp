/* ws_services.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include <cfile.h>
#include <epan/dfilter/dfilter.h>
#include <epan/addr_resolv.h>
#include <epan/epan_dissect.h>
#include <epan/funnel.h>
#include <epan/tap.h>
#include <epan/packet.h>
#include <epan/tvbuff.h>
#include <wsutil/inet_addr.h>
#include <epan/plugin_if.h>
#include <epan/proto.h>
#include <wsutil/filesystem.h>

#include "ui/ws_services.h"

#include <cstring>

#include <QHostAddress>
#include <QtEndian>

namespace smartshark::ws {

bool validateDisplayFilter(const QString &filter, QString *error)
{
    const QByteArray text = filter.toUtf8();
    dfilter_t *df = nullptr;
    df_error_t *err = nullptr;
    const bool ok = dfilter_compile(text.constData(), &df, &err);
    if (ok) {
        dfilter_free(df);
        return true;
    }
    if (error)
        *error = (err && err->msg) ? QString::fromUtf8(err->msg) : QStringLiteral("Invalid display filter.");
    df_error_free(&err);
    return false;
}

static void *readDisplayFilter(capture_file *cf, void *)
{
    return (cf && cf->dfilter) ? g_strdup(cf->dfilter) : nullptr;
}

QString currentDisplayFilter()
{
    char *text = static_cast<char *>(plugin_if_get_capture_file(readDisplayFilter, nullptr));
    const QString filter = text ? QString::fromUtf8(text) : QString();
    g_free(text);
    return filter;
}

void applyDisplayFilter(const QString &filter)
{
    const QByteArray text = filter.toUtf8();
    plugin_if_apply_filter(text.constData(), true);
}

namespace {

constexpr int kMaxSourceBytes = 16384; // per data source, for the panel's raw view

struct TreeWalk {
    QString text;
    int depth = 0;
    int maxChars = 0;
    bool truncated = false;
    QString protocols;
    // First (outermost) occurrence of each field we need.
    QString ipSrc, ipDst, srcPort, dstPort;
};

// "Source Address: 192.168.1.10" -> "192.168.1.10"
QString labelValue(const QString &label)
{
    const qsizetype colon = label.indexOf(QLatin1String(": "));
    QString v = colon >= 0 ? label.mid(colon + 2) : label;
    const qsizetype space = v.indexOf(QLatin1Char(' '));
    return space >= 0 ? v.left(space) : v;
}

void walkNode(proto_node *node, void *data)
{
    auto *walk = static_cast<TreeWalk *>(data);
    if (proto_item_is_hidden(node))
        return;
    field_info *fi = PNODE_FINFO(node);
    if (!fi)
        return;

    char buf[ITEM_LABEL_LENGTH];
    const char *label = nullptr;
    if (fi->rep && fi->rep->representation[0]) {
        label = fi->rep->representation;
    } else {
        buf[0] = '\0';
        proto_item_fill_label(fi, buf, nullptr);
        label = buf;
    }
    const QString line = QString::fromUtf8(label);

    if (fi->hfinfo && fi->hfinfo->abbrev) {
        const char *abbrev = fi->hfinfo->abbrev;
        auto first = [&](QString &slot) {
            if (slot.isEmpty())
                slot = labelValue(line);
        };
        if (g_strcmp0(abbrev, "frame.protocols") == 0) {
            const qsizetype colon = line.indexOf(QLatin1String(": "));
            walk->protocols = colon >= 0 ? line.mid(colon + 2) : line;
        } else if (g_strcmp0(abbrev, "ip.src") == 0 || g_strcmp0(abbrev, "ipv6.src") == 0) {
            first(walk->ipSrc);
        } else if (g_strcmp0(abbrev, "ip.dst") == 0 || g_strcmp0(abbrev, "ipv6.dst") == 0) {
            first(walk->ipDst);
        } else if (g_strcmp0(abbrev, "tcp.srcport") == 0 || g_strcmp0(abbrev, "udp.srcport") == 0) {
            first(walk->srcPort);
        } else if (g_strcmp0(abbrev, "tcp.dstport") == 0 || g_strcmp0(abbrev, "udp.dstport") == 0) {
            first(walk->dstPort);
        }
    }

    // Past the size cap, keep walking for the fields above but stop writing text.
    if (!walk->truncated && walk->text.size() + line.size() > walk->maxChars)
        walk->truncated = true;
    if (!walk->truncated)
        walk->text += QString(walk->depth * 2, QLatin1Char(' ')) + line + QLatin1Char('\n');

    walk->depth++;
    proto_tree_children_foreach(node, walkNode, walk);
    walk->depth--;
}

// The name Wireshark knows for an address (from DNS seen in the capture, or
// its own name resolution), or empty if it only knows the number.
QString wiresharkHostName(const QString &address)
{
    QHostAddress addr;
    if (!addr.setAddress(address))
        return QString();
    const char *name = nullptr;
    if (addr.protocol() == QAbstractSocket::IPv4Protocol) {
        name = get_hostname(qToBigEndian(addr.toIPv4Address()));
    } else {
        ws_in6_addr a6;
        const Q_IPV6ADDR q6 = addr.toIPv6Address();
        memcpy(a6.bytes, q6.c, sizeof(a6.bytes));
        name = get_hostname6(&a6);
    }
    const QString result = name ? QString::fromUtf8(name) : QString();
    QHostAddress same;
    return (result.isEmpty() || (same.setAddress(result) && same == addr)) ? QString() : result;
}

struct SnapshotRequest {
    int maxChars;
    PacketSnapshot *out;
};

void *takeSnapshot(capture_file *cf, void *data)
{
    auto *req = static_cast<SnapshotRequest *>(data);
    PacketSnapshot &snap = *req->out;
    if (!cf || cf->state == FILE_CLOSED) {
        snap.error = QStringLiteral("No capture is open.");
        return nullptr;
    }
    if (!cf->current_frame || !cf->edt || !cf->edt->tree) {
        snap.error = QStringLiteral("No packet is selected. Click a packet in the packet list first.");
        return nullptr;
    }
    TreeWalk walk;
    walk.maxChars = req->maxChars;
    proto_tree_children_foreach(cf->edt->tree, walkNode, &walk);

    snap.ok = true;
    snap.frameNumber = cf->current_frame->num;
    snap.tree = walk.text;
    snap.truncated = walk.truncated;
    snap.protocols = walk.protocols;
    snap.sourceAddress = walk.ipSrc;
    snap.destinationAddress = walk.ipDst;
    snap.sourcePort = walk.srcPort;
    snap.destinationPort = walk.dstPort;

    for (const QString &a : {walk.ipSrc, walk.ipDst}) {
        if (a.isEmpty())
            continue;
        IpFacts f = classifyAddress(a);
        if (f.kind == QLatin1String("Not an IP address"))
            continue;
        bool seen = false;
        for (const IpFacts &existing : snap.addresses)
            seen = seen || existing.address == f.address;
        if (seen)
            continue;
        f.wiresharkName = wiresharkHostName(f.address);
        snap.addresses.append(f);
    }

    // Data sources: the frame, plus anything Wireshark reassembled, decompressed or decrypted.
    bool decrypted = false;
    for (GSList *l = cf->edt->pi.data_src; l; l = l->next) {
        auto *src = static_cast<struct data_source *>(l->data);
        tvbuff_t *tvb = get_data_source_tvb(src);
        if (!tvb)
            continue;
        char *desc = get_data_source_description(src);
        QString name = QString::fromUtf8(desc);
        wmem_free(nullptr, desc);
        const qsizetype paren = name.lastIndexOf(QLatin1String(" ("));
        if (paren > 0)
            name.truncate(paren);

        PayloadSource ps;
        ps.name = name;
        ps.totalLength = static_cast<int>(tvb_captured_length(tvb));
        const int take = qMin(ps.totalLength, kMaxSourceBytes);
        ps.bytes.resize(take);
        if (take > 0)
            tvb_memcpy(tvb, ps.bytes.data(), 0, take);
        snap.sources.append(ps);
        decrypted = decrypted || name.startsWith(QLatin1String("Decrypted"), Qt::CaseInsensitive);
    }
    const QStringList layers = snap.protocols.split(QLatin1Char(':'));
    snap.encryptedWithoutKeys =
        (layers.contains(QStringLiteral("tls")) || layers.contains(QStringLiteral("quic"))) && !decrypted;
    return nullptr;
}

} // namespace

PacketSnapshot selectedPacket(int maxChars)
{
    PacketSnapshot snap;
    snap.error = QStringLiteral("No capture is open.");
    SnapshotRequest req{maxChars, &snap};
    plugin_if_get_capture_file(takeSnapshot, &req);
    if (snap.ok)
        snap.error.clear();
    return snap;
}

namespace {

// Fields read from every displayed packet. Referencing them in the tap's filter
// makes Wireshark build them even though the tree is otherwise minimal.
const char *const kStatFields[] = {
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "tcp.flags", "tcp.analysis.retransmission", "frame.protocols", "dns.qry.name", "dns.flags.response",
    "tls.handshake.extensions_server_name", "http.host",
};
enum StatField {
    F_IP_SRC, F_IP_DST, F_IP6_SRC, F_IP6_DST, F_TCP_SRC, F_TCP_DST, F_UDP_SRC, F_UDP_DST,
    F_TCP_FLAGS, F_TCP_RETRANS, F_PROTOCOLS, F_DNS_NAME, F_DNS_RESPONSE, F_TLS_SNI, F_HTTP_HOST, F_COUNT
};

struct StatsTap {
    CaptureStats *stats;
    int hf[F_COUNT];
};

field_info *firstField(epan_dissect_t *edt, int hf)
{
    if (hf < 0 || !edt->tree)
        return nullptr;
    GPtrArray *arr = proto_get_finfo_ptr_array(edt->tree, hf);
    return (arr && arr->len > 0) ? static_cast<field_info *>(g_ptr_array_index(arr, 0)) : nullptr;
}

QString fieldText(epan_dissect_t *edt, int hf)
{
    field_info *fi = firstField(edt, hf);
    if (!fi || !fi->value)
        return QString();
    char *s = fvalue_to_string_repr(nullptr, fi->value, FTREPR_DISPLAY, BASE_NONE);
    const QString text = s ? QString::fromUtf8(s) : QString();
    wmem_free(nullptr, s);
    return text;
}

quint32 fieldUInt(epan_dissect_t *edt, int hf)
{
    field_info *fi = firstField(edt, hf);
    return (fi && fi->value) ? fvalue_get_uinteger(fi->value) : 0;
}

tap_packet_status statsPacket(void *tapdata, packet_info *pinfo, epan_dissect_t *edt, const void *, tap_flags_t)
{
    auto *tap = static_cast<StatsTap *>(tapdata);
    PacketRecord r;
    r.time = static_cast<double>(pinfo->abs_ts.secs) + pinfo->abs_ts.nsecs / 1e9;
    r.length = pinfo->fd ? pinfo->fd->pkt_len : 0;
    r.src = fieldText(edt, tap->hf[F_IP_SRC]);
    if (r.src.isEmpty())
        r.src = fieldText(edt, tap->hf[F_IP6_SRC]);
    r.dst = fieldText(edt, tap->hf[F_IP_DST]);
    if (r.dst.isEmpty())
        r.dst = fieldText(edt, tap->hf[F_IP6_DST]);

    if (firstField(edt, tap->hf[F_TCP_SRC])) {
        r.transport = QStringLiteral("TCP");
        r.srcPort = static_cast<quint16>(fieldUInt(edt, tap->hf[F_TCP_SRC]));
        r.dstPort = static_cast<quint16>(fieldUInt(edt, tap->hf[F_TCP_DST]));
        const quint32 flags = fieldUInt(edt, tap->hf[F_TCP_FLAGS]);
        r.tcpSyn = flags & 0x002;
        r.tcpReset = flags & 0x004;
        r.tcpAck = flags & 0x010;
        r.retransmission = firstField(edt, tap->hf[F_TCP_RETRANS]) != nullptr;
    } else if (firstField(edt, tap->hf[F_UDP_SRC])) {
        r.transport = QStringLiteral("UDP");
        r.srcPort = static_cast<quint16>(fieldUInt(edt, tap->hf[F_UDP_SRC]));
        r.dstPort = static_cast<quint16>(fieldUInt(edt, tap->hf[F_UDP_DST]));
    }

    const QString protocols = fieldText(edt, tap->hf[F_PROTOCOLS]);
    r.protocol = protocols.section(QLatin1Char(':'), -1);

    const QString response = fieldText(edt, tap->hf[F_DNS_RESPONSE]);
    const bool isResponse = response == QLatin1String("1") || response.compare(QLatin1String("True"), Qt::CaseInsensitive) == 0;
    if (!isResponse)
        r.dnsName = fieldText(edt, tap->hf[F_DNS_NAME]);
    r.tlsServer = fieldText(edt, tap->hf[F_TLS_SNI]);
    r.httpHost = fieldText(edt, tap->hf[F_HTTP_HOST]);

    tap->stats->add(r);
    return TAP_PACKET_DONT_REDRAW;
}

struct DisplayFilterRequest {
    QString filter;
    quint32 displayed = 0;
    bool open = false;
};

void *readCaptureState(capture_file *cf, void *data)
{
    auto *req = static_cast<DisplayFilterRequest *>(data);
    req->open = cf && cf->state != FILE_CLOSED;
    if (req->open) {
        req->filter = cf->dfilter ? QString::fromUtf8(cf->dfilter) : QString();
        req->displayed = cf->displayed_count;
    }
    return nullptr;
}

} // namespace

bool collectDisplayedStats(CaptureStats *stats, QString *displayFilter, QString *error)
{
    DisplayFilterRequest state;
    plugin_if_get_capture_file(readCaptureState, &state);
    if (!state.open) {
        *error = QStringLiteral("No capture is open.");
        return false;
    }
    if (state.displayed == 0) {
        *error = QStringLiteral("No packets are displayed. Clear or change the display filter.");
        return false;
    }
    *displayFilter = state.filter;

    const funnel_ops_t *ops = funnel_get_funnel_ops();
    if (!ops || !ops->retap_packets) {
        *error = QStringLiteral("Wireshark's packet re-scan is not available here.");
        return false;
    }

    StatsTap tap;
    tap.stats = stats;
    QStringList refs;
    for (int i = 0; i < F_COUNT; ++i) {
        tap.hf[i] = proto_registrar_get_id_byname(kStatFields[i]);
        if (tap.hf[i] >= 0)
            refs.append(QString::fromLatin1(kStatFields[i]));
    }
    // "frame.number > 0" is always true, so the OR never filters anything out;
    // it is there to make Wireshark build the referenced fields.
    const QString prime = QStringLiteral("(frame.number > 0 || ") + refs.join(QStringLiteral(" || ")) +
                          QStringLiteral(")");
    const QString filter = state.filter.trimmed().isEmpty()
                               ? prime
                               : QStringLiteral("(") + state.filter + QStringLiteral(") && ") + prime;

    const QByteArray filterUtf8 = filter.toUtf8();
    GString *err = register_tap_listener("frame", &tap, filterUtf8.constData(), TL_REQUIRES_PROTO_TREE, nullptr,
                                         statsPacket, nullptr, nullptr);
    if (err) {
        *error = QStringLiteral("Could not start counting packets: %1").arg(QString::fromUtf8(err->str));
        g_string_free(err, TRUE);
        return false;
    }
    ops->retap_packets(ops->ops_id); // runs every packet through the tap, with Wireshark's progress bar
    remove_tap_listener(&tap);

    // The re-scan gives no result code. It does nothing while Wireshark is still
    // reading the file, and the user can stop it from the progress bar.
    if (stats->packets() == 0) {
        *error = QStringLiteral("Wireshark could not re-scan the packets just now, usually because it is still "
                                "loading the file. Try again when loading has finished.");
        return false;
    }
    if (stats->packets() < state.displayed) {
        *error = QStringLiteral("Counting stopped before the end (%1 of %2 packets), so nothing was sent. Click "
                                "again to count them all.")
                     .arg(stats->packets())
                     .arg(state.displayed);
        return false;
    }
    return true;
}

QString settingsFilePath()
{
    // Not per-profile: provider settings apply to every Wireshark profile.
    char *path = get_persconffile_path("smartshark.ini", false);
    const QString result = QString::fromUtf8(path);
    g_free(path);
    return result;
}

QString wiresharkVersion()
{
    return QStringLiteral(SMARTSHARK_WS_VERSION);
}

} // namespace smartshark::ws
