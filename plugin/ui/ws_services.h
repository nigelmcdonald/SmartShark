/* ws_services.h
 *
 * The few Wireshark facilities the UI needs, behind a small C++ interface.
 * This is the only UI file that includes Wireshark headers.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QString>

#include "core/capture_stats.h"
#include "core/packet_explainer.h"

namespace smartshark::ws {

// Compile a display filter with Wireshark's own compiler.
// Returns true if valid; otherwise sets *error.
bool validateDisplayFilter(const QString &filter, QString *error);

// The display filter currently applied, or empty.
QString currentDisplayFilter();

// Apply a display filter in the main window.
void applyDisplayFilter(const QString &filter);

// The packet selected in the packet list: its dissection tree as indented
// text, capped at maxChars.
PacketSnapshot selectedPacket(int maxChars);

// Count statistics over the displayed packets (those matching the current
// display filter). Re-scans the capture, with Wireshark's progress bar.
// Returns false and sets *error if there is nothing to count.
bool collectDisplayedStats(CaptureStats *stats, QString *displayFilter, QString *error);

// Path of SmartShark's settings file in Wireshark's per-user config folder.
QString settingsFilePath();

// Wireshark version the plugin was built against, e.g. "4.6.0".
QString wiresharkVersion();

} // namespace smartshark::ws
