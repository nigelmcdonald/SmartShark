/* bridge.h
 *
 * C entry points from the plugin's menu callbacks into the Qt user interface.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SMARTSHARK_UI_BRIDGE_H
#define SMARTSHARK_UI_BRIDGE_H

#ifdef __cplusplus
extern "C" {
#endif

void smartshark_ui_generate_filter(void);
void smartshark_ui_explain_packet(void);
void smartshark_ui_summarize(void);
void smartshark_ui_research_packet(void);
void smartshark_ui_settings(void);
void smartshark_ui_about(void);

#ifdef __cplusplus
}

#include <QString>

// Open the Capture tab and answer a question from the displayed packets.
void smartshark_ui_ask_capture(const QString &question);
#endif

#endif /* SMARTSHARK_UI_BRIDGE_H */
