/* collapsible_section.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ui/collapsible_section.h"

#include <QAbstractTextDocumentLayout>
#include <QHBoxLayout>
#include <QImage>
#include <QEvent>
#include <QLabel>
#include <QTextBlock>
#include <QTextCursor>
#include <QTextDocument>
#include <QToolButton>
#include <QVBoxLayout>

namespace smartshark {

SafeMarkdownView::SafeMarkdownView(QWidget *parent) : QTextBrowser(parent)
{
    setOpenLinks(false);
    setOpenExternalLinks(false);
    setReadOnly(true);
    setFrameShape(QFrame::NoFrame);
    setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
    connect(document()->documentLayout(), &QAbstractTextDocumentLayout::documentSizeChanged, this,
            [this](const QSizeF &) { fitHeight(); });
    fitHeight();
}

void SafeMarkdownView::setSafeMarkdown(const QString &markdown)
{
    // GitHub-flavoured Markdown, with raw HTML switched off: the text comes
    // from a model that has read attacker-controlled packet data.
    document()->setMarkdown(markdown, QTextDocument::MarkdownFeatures(QTextDocument::MarkdownDialectGitHub |
                                                                       QTextDocument::MarkdownNoHTML));
    // A link title ([text](url "title")) becomes a tooltip, and Qt shows
    // tooltips as rich text that can load images from anywhere, including
    // network paths. Remove every tooltip; event() also refuses to show any.
    for (QTextBlock block = document()->begin(); block.isValid(); block = block.next()) {
        for (auto it = block.begin(); !it.atEnd(); ++it) {
            const QTextFragment fragment = it.fragment();
            QTextCharFormat format = fragment.charFormat();
            if (!format.hasProperty(QTextFormat::TextToolTip))
                continue;
            format.clearProperty(QTextFormat::TextToolTip);
            QTextCursor cursor(document());
            cursor.setPosition(fragment.position());
            cursor.setPosition(fragment.position() + fragment.length(), QTextCursor::KeepAnchor);
            cursor.setCharFormat(format);
        }
    }
    fitHeight();
}

bool SafeMarkdownView::event(QEvent *e)
{
    if (e->type() == QEvent::ToolTip)
        return true;
    return QTextBrowser::event(e);
}

bool SafeMarkdownView::viewportEvent(QEvent *e)
{
    if (e->type() == QEvent::ToolTip)
        return true;
    return QTextBrowser::viewportEvent(e);
}

bool SafeMarkdownView::hasToolTips() const
{
    for (QTextBlock block = document()->begin(); block.isValid(); block = block.next()) {
        for (auto it = block.begin(); !it.atEnd(); ++it) {
            if (it.fragment().charFormat().hasProperty(QTextFormat::TextToolTip))
                return true;
        }
    }
    return false;
}

QVariant SafeMarkdownView::loadResource(int, const QUrl &)
{
    // Never load images or other resources. An empty QVariant is not enough:
    // Qt then opens the path itself, which for file://host/share/... would
    // make Windows connect to that host. Hand back a blank 1x1 image instead.
    static const QImage blank = []() {
        QImage img(1, 1, QImage::Format_ARGB32);
        img.fill(Qt::transparent);
        return img;
    }();
    return blank;
}

void SafeMarkdownView::fitHeight()
{
    const int h = static_cast<int>(document()->size().height()) + contentsMargins().top() +
                  contentsMargins().bottom() + 4;
    setFixedHeight(qMax(h, 8));
}

CollapsibleSection::CollapsibleSection(const QString &title, QWidget *parent) : QWidget(parent)
{
    header_ = new QToolButton(this);
    header_->setText(title);
    header_->setCheckable(true);
    header_->setChecked(true);
    header_->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    header_->setArrowType(Qt::DownArrow);
    header_->setAutoRaise(true);
    header_->setStyleSheet(QStringLiteral("QToolButton { font-weight: bold; border: none; }"));
    header_->setCursor(Qt::PointingHandCursor);

    status_ = new QLabel(this);
    status_->setTextFormat(Qt::PlainText);
    status_->setStyleSheet(QStringLiteral("color: palette(mid);"));

    auto *headerRow = new QHBoxLayout;
    headerRow->setContentsMargins(0, 0, 0, 0);
    headerRow->addWidget(header_);
    headerRow->addStretch();
    headerRow->addWidget(status_);

    body_ = new SafeMarkdownView(this);

    auto *line = new QFrame(this);
    line->setFrameShape(QFrame::HLine);
    line->setFrameShadow(QFrame::Sunken);

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 2, 0, 2);
    layout->setSpacing(2);
    layout->addLayout(headerRow);
    layout->addWidget(body_);
    layout->addWidget(line);

    connect(header_, &QToolButton::toggled, this, &CollapsibleSection::setExpanded);
}

void CollapsibleSection::setMarkdown(const QString &markdown)
{
    body_->setSafeMarkdown(markdown);
}

void CollapsibleSection::setState(State state, const QString &note)
{
    QString text = note;
    if (text.isEmpty()) {
        switch (state) {
        case State::Idle: text.clear(); break;
        case State::Waiting: text = QStringLiteral("waiting"); break;
        case State::Working: text = QStringLiteral("writing..."); break;
        case State::Done: text.clear(); break;
        case State::Failed: text = QStringLiteral("failed"); break;
        }
    }
    status_->setText(text);
    status_->setStyleSheet(state == State::Failed ? QStringLiteral("color: #c0392b;")
                                                  : QStringLiteral("color: palette(mid);"));
}

void CollapsibleSection::setExpanded(bool expanded)
{
    if (header_->isChecked() != expanded)
        header_->setChecked(expanded); // re-enters through toggled
    header_->setArrowType(expanded ? Qt::DownArrow : Qt::RightArrow);
    body_->setVisible(expanded);
}

bool CollapsibleSection::isExpanded() const
{
    return header_->isChecked();
}

void CollapsibleSection::setLinkHandler(std::function<void(const QUrl &)> onClick)
{
    body_->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard |
                                   Qt::LinksAccessibleByMouse);
    connect(body_, &QTextBrowser::anchorClicked, this, [onClick](const QUrl &url) { onClick(url); });
}

QString markdownCodeBlock(QString text)
{
    // A zero-width space keeps a ``` inside the text from closing the block.
    text.replace(QStringLiteral("```"), QStringLiteral("``") + QChar(0x200B) + QStringLiteral("`"));
    return QStringLiteral("```\n") + text + QStringLiteral("\n```\n");
}

} // namespace smartshark
