/* filter_assistant.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "core/filter_assistant.h"

#include "core/input_guard.h"

#include <QHash>
#include <QRegularExpression>

namespace smartshark {

QString filterSystemPrompt()
{
    return QStringLiteral(
        "You are an expert in Wireshark display filters (Wireshark 4.6), helping a user who may be new to "
        "Wireshark.\n"
        "Convert the user's request into ONE Wireshark display filter.\n"
        "\n"
        "Reply format:\n"
        "Line 1: the filter only. No quotes, no code fences.\n"
        "Line 2: MEANS: <one short plain-English sentence saying what the filter shows>\n"
        "\n"
        "Filter rules:\n"
        "- Use display filter syntax, not capture filter (BPF) syntax. Write `ip.addr == 10.0.0.1`, "
        "not `host 10.0.0.1`; `tcp.port == 443`, not `port 443`.\n"
        "- Use only real Wireshark protocol and field names, for example ip.src, ipv6.addr, tcp.flags.syn, "
        "udp.port, dns.qry.name, http.request.method, tls.handshake.extensions_server_name, frame.len.\n"
        "- Combine conditions with &&, ||, ! and parentheses. Quote string values with double quotes.\n"
        "- For text matching use `contains` or `matches` (a case-insensitive regex is written "
        "`matches \"(?i)text\"`).\n"
        "- If the user refers to the current filter (\"also\", \"and exclude\", \"narrow it\"), build on it.\n"
        "\n"
        "A display filter can only keep or hide individual packets. It cannot count, rank, sort, compare, "
        "total, average or graph traffic. If the request needs that, do not just refuse. Reply in this format "
        "instead, with no filter line:\n"
        "UNSUPPORTED: <one short plain-English sentence why>\n"
        "TRY: <the Wireshark feature that answers it, with the exact menu path and what to click or sort, "
        "for example: Statistics > Conversations, then the IPv4 tab, sorted by Packets>\n"
        "FILTER: <a display filter that gets the user closer> | <what it shows>\n"
        "ASK: <a rephrased request you could turn into a display filter>\n"
        "Give one or two TRY lines, one to three FILTER lines and one or two ASK lines.\n"
        "\n"
        "If the user is asking about this tool itself (what to type, how it works, what it can do) or says "
        "something that is not a description of traffic, reply in this format instead:\n"
        "HELP: <one or two friendly sentences: they describe in their own words which packets they want to "
        "see, and you turn that into a display filter they can apply>\n"
        "ASK: <an example request a beginner might find useful>\n"
        "Give three or four varied ASK lines, for example about DNS lookups, web traffic to a site, one "
        "device's traffic, or connection problems.\n");
}

QString filterUserPrompt(const FilterRequest &req)
{
    QString msg;
    if (!req.currentFilter.trimmed().isEmpty())
        msg += QStringLiteral("Current display filter: %1\n")
                   .arg(guard::singleLine(req.currentFilter, guard::kMaxFilterChars));
    msg += QStringLiteral("Request: %1").arg(guard::singleLine(req.request, guard::kMaxRequestChars));
    return msg;
}

QString filterRepairPrompt(const QString &filter, const QString &compilerError)
{
    return QStringLiteral(
               "Wireshark rejected that filter.\n"
               "Filter: %1\n"
               "Error: %2\n"
               "Reply with a corrected filter on line 1 and the MEANS line on line 2.")
        .arg(filter, compilerError);
}

static QString stripPair(QString s, QChar open, QChar close)
{
    if (s.size() >= 2 && s.startsWith(open) && s.endsWith(close))
        s = s.mid(1, s.size() - 2).trimmed();
    return s;
}

// Remove decoration a model may put around a filter.
static QString cleanFilter(QString line)
{
    static const QRegularExpression label(QStringLiteral("^(display\\s+filter|filter)\\s*:\\s*"),
                                          QRegularExpression::CaseInsensitiveOption);
    line = line.trimmed();
    line.remove(label);
    line = stripPair(line, QLatin1Char('`'), QLatin1Char('`'));
    line = stripPair(line, QLatin1Char('\''), QLatin1Char('\''));
    // Only strip double quotes if they wrap the whole filter, not a value inside it.
    if (line.startsWith(QLatin1Char('"')) && line.endsWith(QLatin1Char('"')) && line.count(QLatin1Char('"')) == 2)
        line = stripPair(line, QLatin1Char('"'), QLatin1Char('"'));
    return line.trimmed();
}

// Split "filter | description" at the last single '|' with spaces around it.
// A filter may contain "||", which must not be split.
static SuggestedFilter splitSuggestion(const QString &text)
{
    for (qsizetype i = text.size() - 2; i >= 1; --i) {
        if (text[i] == QLatin1Char('|') && text[i - 1] == QLatin1Char(' ') && text[i + 1] == QLatin1Char(' ') &&
            (i < 2 || text[i - 2] != QLatin1Char('|')) &&
            (i + 2 >= text.size() || text[i + 2] != QLatin1Char('|')))
            return {cleanFilter(text.left(i)), text.mid(i + 1).trimmed()};
    }
    return {cleanFilter(text), QString()};
}

// "TRY:", "**TRY**:", "- TRY -" and so on. Returns the text after the tag.
static bool takeTag(const QString &line, const QString &tag, QString *rest)
{
    // One compiled expression per tag, not per line.
    static QHash<QString, QRegularExpression> cache;
    auto it = cache.find(tag);
    if (it == cache.end())
        it = cache.insert(tag, QRegularExpression(QStringLiteral("^[\\s*_#>-]*") + tag +
                                                      QStringLiteral("[\\s*_]*(?::|-)[\\s*_]*(.*)$"),
                                                  QRegularExpression::CaseInsensitiveOption));
    const QRegularExpressionMatch m = it->match(line);
    if (!m.hasMatch())
        return false;
    *rest = m.captured(1).trimmed();
    return true;
}

FilterReply parseFilterReply(const QString &reply)
{
    FilterReply out;
    QString text = reply;

    // Reasoning models may put their thinking in the reply.
    static const QRegularExpression thinkBlock(QStringLiteral("<think>.*?</think>"),
                                               QRegularExpression::DotMatchesEverythingOption |
                                                   QRegularExpression::CaseInsensitiveOption);
    text.remove(thinkBlock);
    const qsizetype thinkEnd = text.lastIndexOf(QStringLiteral("</think>"), -1, Qt::CaseInsensitive);
    if (thinkEnd >= 0)
        text = text.mid(thinkEnd + 8);

    // A code fence holds the filter; anything outside it may hold the MEANS line.
    static const QRegularExpression fence(QStringLiteral("```[A-Za-z0-9_-]*[ \\t]*\\n?(.*?)```"),
                                          QRegularExpression::DotMatchesEverythingOption);
    QString fenced;
    const QRegularExpressionMatch fm = fence.match(text);
    if (fm.hasMatch()) {
        fenced = fm.captured(1);
        text = text.left(fm.capturedStart()) + QLatin1Char('\n') + text.mid(fm.capturedEnd());
    }

    QStringList plain; // untagged lines, in order
    for (const QString &raw : text.split(QLatin1Char('\n'))) {
        const QString line = raw.trimmed();
        if (line.isEmpty())
            continue;
        QString rest;
        if (takeTag(line, QStringLiteral("UNSUPPORTED"), &rest)) {
            out.unsupported = true;
            out.advice.reason = rest;
        } else if (line.compare(QStringLiteral("UNSUPPORTED"), Qt::CaseInsensitive) == 0 ||
                   QString(line).remove(QLatin1Char('*')).trimmed().compare(QStringLiteral("UNSUPPORTED"),
                                                                            Qt::CaseInsensitive) == 0) {
            out.unsupported = true;
        } else if (takeTag(line, QStringLiteral("HELP"), &rest)) {
            out.help = true;
            out.advice.reason = rest;
        } else if (takeTag(line, QStringLiteral("MEANS"), &rest)) {
            out.explanation = rest;
        } else if (takeTag(line, QStringLiteral("TRY"), &rest)) {
            if (!rest.isEmpty())
                out.advice.whereToLook.append(rest);
        } else if (takeTag(line, QStringLiteral("ASK"), &rest)) {
            // Models sometimes put two questions on one line: "A? Or: B?"
            static const QRegularExpression orSplit(QStringLiteral("\\s+or:\\s+"),
                                                    QRegularExpression::CaseInsensitiveOption);
            for (const QString &ask : rest.split(orSplit, Qt::SkipEmptyParts)) {
                const QString a = stripPair(ask.trimmed(), QLatin1Char('"'), QLatin1Char('"'));
                if (!a.isEmpty())
                    out.advice.askInstead.append(a);
            }
        } else if (takeTag(line, QStringLiteral("FILTER"), &rest)) {
            const SuggestedFilter s = splitSuggestion(rest);
            if (!s.filter.isEmpty())
                out.advice.filters.append(s);
        } else {
            plain.append(line);
        }
    }

    if (out.help) {
        out.unsupported = false; // help wins if a model mixes the two
        return out;
    }
    if (out.unsupported)
        return out;

    // A plain answer: the filter is the fenced text, else the first untagged line.
    if (!fenced.trimmed().isEmpty()) {
        for (const QString &l : fenced.split(QLatin1Char('\n'))) {
            if (!l.trimmed().isEmpty()) {
                out.filter = cleanFilter(l);
                break;
            }
        }
    } else if (!plain.isEmpty()) {
        out.filter = cleanFilter(plain.first());
    } else if (!out.advice.filters.isEmpty()) {
        // The model wrote "FILTER: x | y" for an ordinary answer.
        out.filter = out.advice.filters.first().filter;
        if (out.explanation.isEmpty())
            out.explanation = out.advice.filters.first().description;
        out.advice = FilterAdvice();
    }
    return out;
}

struct FilterAssistant::Run {
    QList<ChatMessage> messages;
    Done done;
    FilterOutcome outcome;
    bool cancelled = false;
};

FilterAssistant::FilterAssistant(ChatBackend *backend, FilterValidator validator, int maxRepairs)
    : backend_(backend), maxRepairs_(maxRepairs)
{
    // The model writes the filters; refuse absurdly long ones before they
    // reach Wireshark's compiler.
    validator_ = [inner = std::move(validator)](const QString &filter, QString *error) {
        if (filter.size() > guard::kMaxFilterChars) {
            if (error)
                *error = QStringLiteral("The filter is longer than %1 characters.").arg(guard::kMaxFilterChars);
            return false;
        }
        return inner(filter, error);
    };
}

void FilterAssistant::cancel()
{
    if (current_) {
        current_->cancelled = true;
        current_.reset();
        backend_->cancel();
    }
}

void FilterAssistant::generate(const FilterRequest &req, Done done)
{
    cancel();
    auto run = std::make_shared<Run>();
    run->messages = {
        {ChatMessage::Role::System, filterSystemPrompt()},
        {ChatMessage::Role::User, filterUserPrompt(req)},
    };
    run->done = std::move(done);
    current_ = run;
    step(run);
}

void FilterAssistant::step(std::shared_ptr<Run> run)
{
    run->outcome.attempts++;
    // Streamed, even though only the final text is used: a server notices when
    // a stream is dropped and stops working, so Stop really stops it.
    auto ignoreDelta = [](const QString &) {};
    auto onReasoning = [this, run](const QString &reasoning) {
        if (!run->cancelled && progress_)
            progress_(reasoning.size());
    };
    backend_->chatStream(run->messages, ignoreDelta, [this, run](const ChatResult &res) {
        if (run->cancelled)
            return;

        auto finish = [this, run](FilterOutcome::Status status, const QString &message) {
            run->outcome.status = status;
            run->outcome.message = message;
            if (current_ == run)
                current_.reset();
            run->done(run->outcome);
        };

        if (!res.ok) {
            finish(FilterOutcome::Status::Failed, res.error);
            return;
        }

        const FilterReply reply = parseFilterReply(res.text);
        if (reply.help) {
            run->outcome.advice = reply.advice;
            finish(FilterOutcome::Status::Help, reply.advice.reason);
            return;
        }
        if (reply.unsupported) {
            FilterAdvice advice = reply.advice;
            if (advice.reason.isEmpty())
                advice.reason = QStringLiteral("This can't be done with a display filter alone.");
            // Keep only suggestions that compile; the rest would just be errors.
            QList<SuggestedFilter> valid;
            for (const SuggestedFilter &s : advice.filters) {
                if (validator_(s.filter, nullptr))
                    valid.append(s);
            }
            advice.filters = valid;
            run->outcome.advice = advice;
            finish(FilterOutcome::Status::Unsupported, advice.reason);
            return;
        }
        if (reply.filter.isEmpty()) {
            finish(FilterOutcome::Status::Failed, QStringLiteral("The model's reply did not contain a filter."));
            return;
        }

        run->outcome.filter = reply.filter;
        run->outcome.explanation = reply.explanation;
        QString compilerError;
        if (validator_(reply.filter, &compilerError)) {
            finish(FilterOutcome::Status::Ok, QString());
            return;
        }

        run->outcome.explanation.clear(); // it described a filter that does not work

        // A plain-English answer ("Yes, you can use || ...") is not a broken
        // filter: show it as an answer instead of asking for repairs.
        if (looksLikeProse(reply.filter)) {
            run->outcome.filter.clear();
            run->outcome.advice = FilterAdvice();
            run->outcome.advice.reason = guard::singleLine(res.text, 1200);
            finish(FilterOutcome::Status::Help, run->outcome.advice.reason);
            return;
        }

        if (run->outcome.attempts > maxRepairs_) {
            finish(FilterOutcome::Status::Invalid, compilerError);
            return;
        }

        // Show the model its answer and the compiler's complaint, and ask again.
        run->messages.append({ChatMessage::Role::Assistant, res.text});
        run->messages.append({ChatMessage::Role::User, filterRepairPrompt(reply.filter, compilerError)});
        step(run);
    }, onReasoning);
}

bool looksLikeProse(const QString &text)
{
    // Count tokens that are plain words ("Yes,", "you", "can"). Filters are
    // mostly field names with dots, operators and values.
    static const QRegularExpression word(QStringLiteral("^[A-Za-z']+[,.;:?!]?$"));
    // Display filter keywords are words too, but they make a filter, not a sentence.
    static const QStringList keywords = {
        QStringLiteral("or"), QStringLiteral("and"), QStringLiteral("not"), QStringLiteral("xor"),
        QStringLiteral("in"), QStringLiteral("contains"), QStringLiteral("matches"), QStringLiteral("eq"),
        QStringLiteral("ne"), QStringLiteral("gt"), QStringLiteral("lt"), QStringLiteral("ge"),
        QStringLiteral("le"), QStringLiteral("any"), QStringLiteral("all"),
    };
    const QStringList tokens = text.split(QLatin1Char(' '), Qt::SkipEmptyParts);
    int words = 0;
    for (const QString &t : tokens) {
        if (word.match(t).hasMatch() && !keywords.contains(t, Qt::CaseInsensitive))
            words++;
    }
    return words >= 5 && words * 3 >= static_cast<int>(tokens.size()) * 2;
}

} // namespace smartshark
