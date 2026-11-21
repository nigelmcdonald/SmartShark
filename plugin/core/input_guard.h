/* input_guard.h
 *
 * Basic checks on what the user types and what servers send back, so bad
 * input cannot break the plugin or leak an API key.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QString>

namespace smartshark::guard {

constexpr int kMaxRequestChars = 1000;        // a filter request
constexpr int kMaxModelNameChars = 200;
constexpr int kMaxApiKeyChars = 512;
constexpr int kMaxFilterChars = 4000;         // a filter we will apply
constexpr qint64 kMaxResponseBytes = 4 << 20; // a server reply (4 MiB)
constexpr int kMaxReplyChars = 200000;       // reply text from a server that sets no output limit
constexpr qint64 kMaxStreamBytes = 64 << 20;  // a streamed reply, framing and reasoning included

// One line of text: control characters and line breaks become spaces, runs of
// whitespace collapse, ends are trimmed, length is capped.
QString singleLine(const QString &text, int maxChars);

// Text with Markdown's special characters escaped, so network data placed in
// a Markdown table or list shows literally (no links, images or emphasis).
QString escapeMarkdown(const QString &text);

// True for localhost, 127.0.0.0/8 and ::1.
bool isLoopbackHost(const QString &host);

// Check a server URL. Returns an empty string if it is acceptable, otherwise a
// message for the user. An API key is never sent over plain http, except to a
// server on this computer.
QString checkBaseUrl(const QString &url, bool willSendApiKey);

// Trims the key; returns an empty string and sets *error if it has characters
// that cannot appear in an HTTP header.
QString cleanApiKey(const QString &key, QString *error);

// Trims the model name; sets *error if it is unusable.
QString cleanModelName(const QString &model, QString *error);

} // namespace smartshark::guard
