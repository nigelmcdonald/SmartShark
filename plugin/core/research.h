/* research.h
 *
 * Prompts and reply handling for web research: Claude picks the most unusual
 * things in a packet or a capture, looks them up with web search, and
 * reports what the sources say.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QList>
#include <QMap>
#include <QString>

#include "core/anthropic_backend.h"

namespace smartshark {

enum class ResearchSection { StoodOut, Findings, Meaning, NextSteps };

QString researchSectionTitle(ResearchSection s);

QString researchSystemPrompt();

// First user message, built from the same data the Packet and Capture tabs
// send (packetOrStatsMessage), with the research request in front. guidance
// is what the user typed to steer the research, if anything.
QString researchMessage(const QString &packetOrStatsMessage, bool wholeCapture, const QString &guidance);

// Split a (possibly incomplete) reply into its sections by "## Title".
// Text before the first heading goes to StoodOut.
QMap<ResearchSection, QString> splitResearch(const QString &markdown);

// Sources as a numbered Markdown list of links: cited pages first, then
// other results Claude looked at. Titles are escaped; only http(s) URLs are
// listed.
QString sourcesMarkdown(const QList<anthropic::WebSource> &cited, const QList<anthropic::WebSource> &others);

// True for an http or https URL.
bool isWebUrl(const QString &url);

} // namespace smartshark
