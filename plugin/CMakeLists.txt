# SmartShark - LLM assistance for Wireshark
#
# This directory is built as part of a Wireshark source build. It is linked
# into the Wireshark tree at plugins/epan/smartshark and enabled with
#   -DCUSTOM_PLUGIN_SRC_DIR=plugins/epan/smartshark
# See docs/building-windows.md.
#
# SPDX-License-Identifier: GPL-2.0-or-later

include(WiresharkPlugin)

# Plugin name and version (major minor micro extra)
set_module_info(smartshark 0 1 0 0)

set(CMAKE_AUTOMOC ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets Network)

# Wireshark-independent logic (unit-tested in tests/)
set(SMARTSHARK_CORE_SRC
	core/capture_explainer.cpp
	core/capture_stats.cpp
	core/anthropic_backend.cpp
	core/filter_assistant.cpp
	core/http_backend.cpp
	core/input_guard.cpp
	core/ip_facts.cpp
	core/openai_compat.cpp
	core/packet_explainer.cpp
	core/privacy.cpp
	core/research.cpp
	core/provider.cpp
	core/secret_store.cpp
	core/settings.cpp
	core/sse.cpp
)

set(SMARTSHARK_SRC
	smartshark.c
	ui/bridge.cpp
	ui/capture_panel.cpp
	ui/cloud_consent.cpp
	ui/collapsible_section.cpp
	ui/filter_dialog.cpp
	ui/investigation_panel.cpp
	ui/ip_lookup.cpp
	ui/research_panel.cpp
	ui/settings_dialog.cpp
	ui/ws_services.cpp
	${SMARTSHARK_CORE_SRC}
)

set(PLUGIN_FILES
	plugin.c
	${SMARTSHARK_SRC}
)

set_source_files_properties(
	plugin.c
	PROPERTIES
	SKIP_AUTOGEN ON
)

set_source_files_properties(
	${PLUGIN_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

register_plugin_files(plugin.c
	plugin
	${SMARTSHARK_SRC}
)

add_wireshark_plugin_library(smartshark epan)

target_include_directories(smartshark PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(smartshark PRIVATE SMARTSHARK_WS_VERSION="${PROJECT_VERSION}")

target_link_libraries(smartshark
	epan
	Qt6::Core
	Qt6::Gui
	Qt6::Widgets
	Qt6::Network
	advapi32
)

install_plugin(smartshark epan)
