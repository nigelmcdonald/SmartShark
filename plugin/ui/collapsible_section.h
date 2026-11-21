/* collapsible_section.h
 *
 * A titled section with a status, whose body (Markdown) can be collapsed.
 * Used by the investigation panel.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <functional>

#include <QTextBrowser>
#include <QWidget>

class QLabel;
class QToolButton;

namespace smartshark {

// A read-only Markdown view that grows to fit its text (the panel scrolls, not
// each section) and never loads anything: no links opened, no images, no HTML.
class SafeMarkdownView : public QTextBrowser {
    Q_OBJECT
public:
    explicit SafeMarkdownView(QWidget *parent = nullptr);
    void setSafeMarkdown(const QString &markdown);
    QVariant loadResource(int type, const QUrl &name) override;
    bool hasToolTips() const; // for tests: true if any text carries a tooltip

protected:
    bool event(QEvent *e) override;
    bool viewportEvent(QEvent *e) override;

private:
    void fitHeight();
};

class CollapsibleSection : public QWidget {
    Q_OBJECT
public:
    enum class State { Idle, Waiting, Working, Done, Failed };

    CollapsibleSection(const QString &title, QWidget *parent = nullptr);

    void setMarkdown(const QString &markdown);
    void setState(State state, const QString &note = QString());
    void setExpanded(bool expanded);
    bool isExpanded() const;

    // Make links in this section clickable. A click calls onClick with the
    // URL; it decides whether to open it. Off by default.
    void setLinkHandler(std::function<void(const QUrl &)> onClick);

private:
    QToolButton *header_;
    QLabel *status_;
    SafeMarkdownView *body_;
};

// Text as a Markdown code block that the text cannot break out of.
QString markdownCodeBlock(QString text);

} // namespace smartshark
