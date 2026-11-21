# Unit tests for SmartShark's Wireshark-independent code (plugin/core).
# Needs only Qt, not a Wireshark build. Run with scripts\test.cmd.
#
# SPDX-License-Identifier: GPL-2.0-or-later

cmake_minimum_required(VERSION 3.16)
project(SmartSharkTests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Network Test)

set(CORE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../plugin)

add_executable(core_tests
	test_core.cpp
	${CORE_DIR}/core/capture_explainer.cpp
	${CORE_DIR}/core/capture_stats.cpp
	${CORE_DIR}/core/anthropic_backend.cpp
	${CORE_DIR}/core/filter_assistant.cpp
	${CORE_DIR}/core/http_backend.cpp
	${CORE_DIR}/core/input_guard.cpp
	${CORE_DIR}/core/ip_facts.cpp
	${CORE_DIR}/core/openai_compat.cpp
	${CORE_DIR}/core/packet_explainer.cpp
	${CORE_DIR}/core/privacy.cpp
	${CORE_DIR}/core/research.cpp
	${CORE_DIR}/core/provider.cpp
	${CORE_DIR}/core/settings.cpp
	${CORE_DIR}/core/sse.cpp
)
target_include_directories(core_tests PRIVATE ${CORE_DIR})
target_link_libraries(core_tests PRIVATE Qt6::Core Qt6::Network Qt6::Test)

enable_testing()
add_test(NAME core_tests COMMAND core_tests)
