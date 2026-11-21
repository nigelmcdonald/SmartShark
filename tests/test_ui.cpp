/* test_ui.cpp
 *
 * Tests for the panel's Markdown view, which shows text written by a model
 * that has read attacker-controlled packets. Runs offscreen.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <QApplication>
#include <QDir>
#include <QHelpEvent>
#include <QImage>
#include <QTemporaryDir>
#include <QTextBlock>
#include <QTextDocument>
#include <QToolTip>
#include <QUrl>
#include <QtTest>

#include "core/research.h"
#include "ui/collapsible_section.h"

using namespace smartshark;

class UiTests : public QObject {
    Q_OBJECT
private slots:
    void linkTitleGivesNoToolTip();
    void imagesAreNotLoaded();
    void rawHtmlIsShownAsText();
    void sourceUrlCannotAddALink();
};

void UiTests::linkTitleGivesNoToolTip()
{
    SafeMarkdownView view;
    view.resize(400, 200);
    view.setSafeMarkdown(QStringLiteral("Intro\n\n[hover me](https://example.com \"<img src='file://attacker.example/s/x.png'>\")\n"));
    QVERIFY(!view.hasToolTips());

    view.show();
    QCoreApplication::processEvents();
    QHelpEvent help(QEvent::ToolTip, QPoint(20, 30), view.viewport()->mapToGlobal(QPoint(20, 30)));
    QCoreApplication::sendEvent(view.viewport(), &help);
    QCoreApplication::processEvents();
    QVERIFY(!QToolTip::isVisible());
}

void UiTests::imagesAreNotLoaded()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString png = QDir(dir.path()).absoluteFilePath(QStringLiteral("probe.png"));
    QImage img(321, 123, QImage::Format_RGB32);
    img.fill(Qt::red);
    QVERIFY(img.save(png));

    SafeMarkdownView view;
    view.resize(400, 200);
    view.setSafeMarkdown(QStringLiteral("![x](%1)\n").arg(QUrl::fromLocalFile(png).toString()));
    // A loaded image would make the document at least as tall as the image.
    QVERIFY(view.document()->size().height() < 100);
}

void UiTests::rawHtmlIsShownAsText()
{
    SafeMarkdownView view;
    view.setSafeMarkdown(QStringLiteral("<b>bold</b> <a href='http://x'>l</a>"));
    QVERIFY(view.toPlainText().contains(QStringLiteral("<b>bold</b>")));
}

void UiTests::sourceUrlCannotAddALink()
{
    anthropic::WebSource s;
    s.url = QStringLiteral("https://trusted.example/search?q=)[Click](https://evil.example/");
    s.title = QStringLiteral("Trusted");
    SafeMarkdownView view;
    view.setSafeMarkdown(sourcesMarkdown({s}, {}));

    QStringList hrefs;
    for (QTextBlock b = view.document()->begin(); b.isValid(); b = b.next()) {
        for (auto it = b.begin(); !it.atEnd(); ++it) {
            const QTextCharFormat f = it.fragment().charFormat();
            if (f.isAnchor() && !hrefs.contains(f.anchorHref()))
                hrefs.append(f.anchorHref());
        }
    }
    QCOMPARE(hrefs.size(), 1);
    QVERIFY(hrefs.first().startsWith(QStringLiteral("https://trusted.example/")));
    // The click check compares the same encoded form.
    QCOMPARE(sourceLinkTarget(QString::fromLatin1(QUrl(hrefs.first()).toEncoded())), sourceLinkTarget(s.url));
}

int main(int argc, char **argv)
{
    qputenv("QT_QPA_PLATFORM", "offscreen");
    QApplication app(argc, argv);
    UiTests tests;
    return QTest::qExec(&tests, argc, argv);
}

#include "test_ui.moc"
