/* smartshark.c
 *
 * SmartShark - LLM assistance for Wireshark.
 * Plugin registration: the protocol handle and the Tools > SmartShark menu.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/funnel.h>
#include <epan/plugin_if.h>

#include "ui/bridge.h"

void proto_register_smartshark(void);
void proto_reg_handoff_smartshark(void);

static int proto_smartshark;

static void
on_generate_filter(ext_menubar_gui_type gui_type _U_, void *gui_data _U_, void *user_data _U_)
{
    smartshark_ui_generate_filter();
}

static void
on_summarize(ext_menubar_gui_type gui_type _U_, void *gui_data _U_, void *user_data _U_)
{
    smartshark_ui_summarize();
}

static void
on_explain(ext_menubar_gui_type gui_type _U_, void *gui_data _U_, void *user_data _U_)
{
    smartshark_ui_explain_packet();
}

/* Right-click menu in the packet list. The field list is not needed: the
 * panel reads the selected packet's full dissection itself. */
static void
on_packet_menu_explain(void *callback_data _U_, GPtrArray *finfo_array _U_)
{
    smartshark_ui_explain_packet();
}

static void
on_research(ext_menubar_gui_type gui_type _U_, void *gui_data _U_, void *user_data _U_)
{
    smartshark_ui_research_packet();
}

static void
on_packet_menu_research(void *callback_data _U_, GPtrArray *finfo_array _U_)
{
    smartshark_ui_research_packet();
}

static void
on_settings(ext_menubar_gui_type gui_type _U_, void *gui_data _U_, void *user_data _U_)
{
    smartshark_ui_settings();
}

static void
on_about(ext_menubar_gui_type gui_type _U_, void *gui_data _U_, void *user_data _U_)
{
    smartshark_ui_about();
}

void
proto_register_smartshark(void)
{
    /* A protocol handle is needed to own the menu. SmartShark does not dissect anything. */
    proto_smartshark = proto_register_protocol("SmartShark LLM Assistant", "SmartShark", "smartshark");

    ext_menu_t *menu = ext_menubar_register_menu(proto_smartshark, "SmartShark", true);
    ext_menubar_set_parentmenu(menu, "Tools");

    ext_menubar_add_entry(menu, "Generate Display &Filter...",
                          "Describe what you want to see, and SmartShark writes the display filter",
                          on_generate_filter, NULL);
    ext_menubar_add_entry(menu, "E&xplain Selected Packet",
                          "Open the SmartShark panel and explain the selected packet",
                          on_explain, NULL);
    ext_menubar_add_entry(menu, "&Summarize Displayed Packets",
                          "Count and explain the packets the current display filter shows",
                          on_summarize, NULL);
    ext_menubar_add_entry(menu, "&Research Selected Packet on the Web",
                          "Let Claude look up the most unusual things in the selected packet",
                          on_research, NULL);
    ext_menubar_add_separator(menu);
    ext_menubar_add_entry(menu, "S&ettings...",
                          "Choose the LLM provider, model and API key",
                          on_settings, NULL);
    ext_menubar_add_entry(menu, "&About SmartShark",
                          "Version and license information",
                          on_about, NULL);

    /* Packet list right-click menu: SmartShark > Explain This Packet */
    funnel_register_packet_menu("SmartShark/Explain This Packet", "", on_packet_menu_explain, NULL, false);
    funnel_register_packet_menu("SmartShark/Research This Packet on the Web", "", on_packet_menu_research, NULL,
                                false);
}

void
proto_reg_handoff_smartshark(void)
{
}
