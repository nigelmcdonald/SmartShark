# Developing SmartShark

Notes for anyone changing the code. Building is covered in [building-windows.md](building-windows.md), and the design in [design.md](design.md).

## Code layout

- `plugin/smartshark.c`: plugin registration, the **Tools > SmartShark** menu and the packet list's right-click menu.
- `plugin/core/`: the logic, with no Wireshark headers, so it can be unit-tested on its own: model backends, prompts, reply parsing, settings, statistics, address facts, privacy and input checks.
- `plugin/ui/`: Qt dialogs, the side panel and its tabs, and the glue to Wireshark. Only `ui/ws_services.cpp` includes Wireshark headers.
- `tests/`: unit tests for `plugin/core/` (`test_core.cpp`) and for the panel's safe Markdown view (`test_ui.cpp`, run offscreen), both with Qt Test. Run them with `scripts\test.cmd`; they need Qt only, not a Wireshark build. Security-relevant changes should keep [SECURITY.md](../SECURITY.md) accurate.

## Conventions

- Use Qt for networking (`QNetworkAccessManager`) and JSON (`QJsonDocument`).
- Treat everything that comes from the network, a packet or a model as untrusted. See the safety rules in [design.md](design.md#safety-rules); `core/input_guard.*` has the shared checks.
- Never show model or server text as HTML.
- Add a unit test for new logic in `plugin/core/`.
- License headers: every source file carries `SPDX-License-Identifier: GPL-2.0-or-later`.

## Matching Wireshark

The plugin only loads into a Wireshark built with the same version, the same Qt version and a compatible MSVC toolchain. Packet access needs `capture_file` from Wireshark's internal `cfile.h`, so the plugin is built inside a Wireshark source tree rather than against the public headers alone. Plugin entry points change between 4.x releases; check them against `doc/plugins.example` for the target version.

## README

The README is the project's front page. Update it in the same change as anything a user would notice: a new feature, a changed menu or setting, a new provider or requirement. Keep it in plain, friendly English for people who may be new to Wireshark, with exact menu paths in bold (for example **Tools > SmartShark > Settings**). Never describe a feature as working before it is built and tested. Check screenshots for MAC addresses, host names and other personal details before adding them to `docs/images/`.
