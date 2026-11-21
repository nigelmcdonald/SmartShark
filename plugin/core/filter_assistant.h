/* filter_assistant.h
 *
 * Turns a plain-language request into a Wireshark display filter.
 *
 * The model's answer is checked with a validator (in the plugin, Wireshark's
 * own display filter compiler). If it does not compile, the compiler's error
 * goes back to the model so it can correct itself, up to maxRepairs times.
 *
 * When a request cannot be a display filter (counting, ranking, graphs...),
 * the model does not just refuse: it says where in Wireshark to look, offers
 * filters that get closer, and suggests questions it can answer.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <functional>
#include <memory>

#include <QList>
#include <QString>
#include <QStringList>

#include "core/chat.h"

namespace smartshark {

// Returns true if the filter compiles. On failure, sets *error to the reason.
using FilterValidator = std::function<bool(const QString &filter, QString *error)>;

struct FilterRequest {
    QString request;        // what the user typed
    QString currentFilter;  // the display filter in use now, or empty
};

struct SuggestedFilter {
    QString filter;
    QString description; // what it shows, may be empty
};

// Help for a request that is not a display filter.
struct FilterAdvice {
    QString reason;                  // why it is not a display filter
    QStringList whereToLook;         // Wireshark features that answer it
    QList<SuggestedFilter> filters;  // filters that get closer (only valid ones)
    QStringList askInstead;          // rephrased requests that work
};

// A model reply, parsed.
struct FilterReply {
    QString filter;       // empty if none
    QString explanation;  // plain-English meaning of the filter, may be empty
    bool unsupported = false;
    bool help = false;    // the user asked how to use the tool; see advice
    FilterAdvice advice;  // filled when unsupported or help
};

struct FilterOutcome {
    enum class Status {
        Ok,          // filter compiles
        Invalid,     // the model kept producing filters that do not compile
        Unsupported, // not a display filter; see advice
        Help,        // the user asked how to use the tool; see advice
        Failed,      // network, server or configuration error
    };
    Status status = Status::Failed;
    QString filter;       // best filter found (Ok and Invalid)
    QString explanation;  // Ok only
    FilterAdvice advice;  // Unsupported and Help
    QString message;      // reason (Invalid, Failed)
    int attempts = 0;     // model calls made
};

// System prompt for filter generation.
QString filterSystemPrompt();

// First user message for a request. The request is cleaned to a single line
// of at most guard::kMaxRequestChars characters.
QString filterUserPrompt(const FilterRequest &req);

// Follow-up message when the last filter did not compile.
QString filterRepairPrompt(const QString &filter, const QString &compilerError);

// Parse a model reply. Tolerates reasoning blocks, code fences, labels and
// quotes around the filter. Suggested filters are not validated here.
FilterReply parseFilterReply(const QString &reply);

// True if a "filter" is really an English sentence, for example a model that
// answered a question instead of writing a filter.
bool looksLikeProse(const QString &text);

class FilterAssistant {
public:
    using Done = std::function<void(const FilterOutcome &)>;

    FilterAssistant(ChatBackend *backend, FilterValidator validator, int maxRepairs = 2);

    // Start a request. done runs once, unless cancel() is called first.
    void generate(const FilterRequest &req, Done done);
    void cancel();

    // Called with the size of each piece of reasoning a model streams, so the
    // UI can show that it is still working.
    void setProgressCallback(std::function<void(qsizetype reasoningChars)> progress)
    {
        progress_ = std::move(progress);
    }

private:
    std::function<void(qsizetype)> progress_;
    struct Run;
    void step(std::shared_ptr<Run> run);

    ChatBackend *backend_;
    FilterValidator validator_;
    int maxRepairs_;
    std::shared_ptr<Run> current_;
};

} // namespace smartshark
