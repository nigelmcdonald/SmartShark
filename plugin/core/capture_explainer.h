/* capture_explainer.h
 *
 * Prompts for questions about the whole capture (the displayed packets),
 * answered from statistics SmartShark counted itself.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QList>
#include <QMap>
#include <QString>
#include <QStringList>

#include "core/ip_facts.h"

namespace smartshark {

class CaptureStats;

enum class CaptureSection { Summary, Talkers, Connections, Notable };

QString captureSectionTitle(CaptureSection s);

QString captureSystemPrompt();

// First user message: the statistics and address facts, marked as untrusted
// data. If question is empty the model summarises; otherwise it answers the
// question first, then summarises.
QString captureMessage(const CaptureStats &stats, const QList<IpFacts> &addresses, const QString &displayFilter,
                       const QString &question, int maxStatsChars);

// Split a (possibly incomplete) reply into its sections, like splitExplanation.
// An "## Answer" section, if present, is returned under the key -1.
QMap<int, QString> splitCaptureReply(const QString &markdown);

} // namespace smartshark
