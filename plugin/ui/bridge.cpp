/* bridge.cpp
 *
 * Qt side of the menu callbacks.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ui/bridge.h"

#include <QApplication>
#include <QDockWidget>
#include <QTabWidget>
#include <QMainWindow>
#include <QMessageBox>
#include <QPointer>
#include <QString>
#include <QWidget>

#include "ui/capture_panel.h"
#include "ui/filter_dialog.h"
#include "ui/investigation_panel.h"
#include "ui/research_panel.h"
#include "ui/settings_dialog.h"
#include "ui/ws_services.h"

using namespace smartshark;

namespace {

// Wireshark's main window, so dialogs are centred on it and stay on top of it.
QWidget *mainWindow()
{
    const auto widgets = QApplication::topLevelWidgets();
    for (QWidget *w : widgets) {
        if (qobject_cast<QMainWindow *>(w) && w->isVisible())
            return w;
    }
    return QApplication::activeWindow();
}

// Show a non-modal dialog, reusing the open one if there is one.
template <typename Dialog>
void showSingleton(QPointer<Dialog> &instance)
{
    if (!instance) {
        instance = new Dialog(mainWindow());
        instance->setAttribute(Qt::WA_DeleteOnClose);
    }
    instance->show();
    instance->raise();
    instance->activateWindow();
}

QPointer<FilterDialog> g_filterDialog;
QPointer<QDockWidget> g_panelDock;
QPointer<QTabWidget> g_tabs;
QPointer<InvestigationPanel> g_packetPanel;
QPointer<CapturePanel> g_capturePanel;
QPointer<ResearchPanel> g_researchPanel;

// The side panel, docked on the right of Wireshark's main window, with a
// Packet tab (explain one packet), a Capture tab (the whole capture) and a
// Research tab (web research).
void ensurePanel()
{
    if (g_panelDock)
        return;
    auto *main = qobject_cast<QMainWindow *>(mainWindow());
    g_panelDock = new QDockWidget(QStringLiteral("SmartShark"), main);
    g_panelDock->setObjectName(QStringLiteral("SmartSharkPanel"));
    g_tabs = new QTabWidget(g_panelDock);
    g_packetPanel = new InvestigationPanel(g_tabs);
    g_capturePanel = new CapturePanel(g_tabs);
    g_researchPanel = new ResearchPanel(g_tabs);
    g_tabs->addTab(g_packetPanel, QStringLiteral("Packet"));
    g_tabs->addTab(g_capturePanel, QStringLiteral("Capture"));
    g_tabs->addTab(g_researchPanel, QStringLiteral("Research"));
    g_panelDock->setWidget(g_tabs);
    g_panelDock->setMinimumWidth(320);
    if (main) {
        main->addDockWidget(Qt::RightDockWidgetArea, g_panelDock);
        main->resizeDocks({g_panelDock}, {qMax(380, main->width() / 3)}, Qt::Horizontal);
    } else {
        g_panelDock->setFloating(true);
        g_panelDock->resize(460, 700);
    }
}

void showTab(QWidget *tab)
{
    ensurePanel();
    g_tabs->setCurrentWidget(tab);
    g_panelDock->show();
    g_panelDock->raise();
}

} // namespace

// Used by the filter dialog: answer a question a display filter cannot.
void smartshark_ui_ask_capture(const QString &question)
{
    ensurePanel();
    showTab(g_capturePanel);
    g_capturePanel->analyse(question);
}

extern "C" void smartshark_ui_generate_filter(void)
{
    showSingleton(g_filterDialog);
}

extern "C" void smartshark_ui_explain_packet(void)
{
    ensurePanel();
    showTab(g_packetPanel);
    g_packetPanel->explainSelectedPacket();
}

extern "C" void smartshark_ui_summarize(void)
{
    ensurePanel();
    showTab(g_capturePanel);
    g_capturePanel->analyse();
}

extern "C" void smartshark_ui_research_packet(void)
{
    ensurePanel();
    showTab(g_researchPanel);
    g_researchPanel->researchSelectedPacket();
}

extern "C" void smartshark_ui_settings(void)
{
    SettingsDialog dlg(mainWindow());
    dlg.exec();
}

extern "C" void smartshark_ui_about(void)
{
    QMessageBox::about(
        mainWindow(), QStringLiteral("About SmartShark"),
        QStringLiteral(
            "<h3>SmartShark " PLUGIN_VERSION "</h3>"
            "<p>LLM assistance for Wireshark: plain-language display filters "
            "and packet summaries.</p>"
            "<p>Free software under the GNU GPL, version 2 or later.<br>"
            "<a href=\"https://github.com/nigelmcdonald/SmartShark\">"
            "github.com/nigelmcdonald/SmartShark</a></p>"
            "<p>Built for Wireshark %1, Qt %2.<br>Settings file: %3</p>")
            .arg(ws::wiresharkVersion(), QString::fromLatin1(qVersion()), ws::settingsFilePath().toHtmlEscaped()));
}
