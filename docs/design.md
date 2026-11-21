# How SmartShark works

This document describes SmartShark's design for contributors: how the pieces fit together, where packet data goes, and the safety rules the code follows. For building, see [building-windows.md](building-windows.md). For code layout and conventions, see [development.md](development.md).

## Overview

SmartShark is a native Wireshark plugin (a DLL) written in C and C++ with Qt. It adds a **Tools > SmartShark** menu, a right-click **SmartShark** menu on the packet list, a dialog for generating display filters, and a side panel with three tabs:

| Tab | What it does | Data it works from |
|---|---|---|
| **Packet** | Explains the selected packet: overview, layers, endpoints, payload, anything notable | The packet's dissection tree, address facts and decoded payload |
| **Capture** | Summarises the displayed packets and answers questions about them | Statistics SmartShark counts over the displayed packets |
| **Research** | Has Claude pick the most unusual things in a packet or capture and look them up on the web | The same data as the Packet or Capture tab |

The panel is a `QDockWidget` docked on the right of Wireshark's main window. It can be undocked, resized and closed.

## Talking to models

Two backends share one base class, `HttpBackend` (`core/http_backend.*`), which handles one request at a time, URL and key checks, redirects, size limits, a hard time limit on streamed replies and readable error messages.

- **OpenAI-compatible** (`core/openai_compat.*`): `POST {base}/chat/completions` and `GET {base}/models`. Used for OpenAI, Google Gemini (its OpenAI-compatible endpoint), Moonshot Kimi, DeepSeek, LM Studio, Ollama and any other compatible server.
- **Anthropic** (`core/anthropic_backend.*`): the Messages API (`POST /v1/messages`, API version `2026-10-21`). On models that support it, requests send `"fallbacks": "default"`, so a safety decline is retried on a suitable model in the same request.

Provider presets (`core/provider.*`) carry base URLs only. Model names come live from each provider's model list.

Replies are streamed (Server-Sent Events). The model writes Markdown under fixed headings, and the panel routes each heading's text into its own collapsible section as it arrives.

## Getting packet data

All Wireshark access is in `ui/ws_services.cpp`, the only file that includes Wireshark headers.

- **The selected packet:** `plugin_if_get_capture_file()` gives the `capture_file`, and `cf->edt` is the selected packet's dissection. SmartShark walks the tree with `proto_tree_children_foreach()` and `proto_item_fill_label()` to get indented text, capped in size.
- **Data sources:** the dissection's data sources (frame bytes, "Decrypted TLS", "Reassembled TCP", "Uncompressed entity body" and so on) give the decoded payload. SmartShark shows what Wireshark could decode or decrypt; it never tries to break encryption. When a packet is encrypted and Wireshark has no keys, the panel explains how to set up a TLS key log file for the user's own browser traffic.
- **Capture statistics:** the displayed packets are re-dissected with Wireshark's retap mechanism and a frame tap, and counted in `core/capture_stats.*` (protocols, endpoints, conversations, connection attempts, resets, retransmissions, DNS, TLS and HTTP names).
- **Right-click menu:** `funnel_register_packet_menu()`.

## IP address facts

Facts about addresses are gathered by SmartShark, not invented by the model (`core/ip_facts.*`, `ui/ip_lookup.*`):

1. **Offline, always:** the address class (private, carrier-grade NAT, link-local, multicast, loopback, documentation, reserved), well-known public resolvers, and names Wireshark already resolved from DNS in the capture.
2. **Online, only with the user's permission:** reverse DNS through the system resolver, and the registry owner, network, country and range through RDAP (`https://rdap.org/ip/<address>`). Only the address is sent. SmartShark asks once (Allow, Not now, Never), and the choice can be changed in Settings.

The model cannot trigger lookups. Only the user's settings do, so a crafted packet cannot make SmartShark contact arbitrary hosts.

## Web research

The Research tab (`core/research.*`, `ui/research_panel.*`, `AnthropicBackend::research`) works only with Anthropic Claude, because the OpenAI-compatible Chat Completions API has no standard web search.

- It uses Anthropic's server-side web search tool (`web_search_20250305`, available on every Claude model) with at most five searches per turn.
- Claude chooses what to research from the packet or statistics message. The system prompt tells it never to search for address placeholders, private addresses or anything that identifies the user, and that search results are untrusted.
- The stream is rebuilt block by block (`ContentAccumulator`), so a paused turn (`pause_turn`) can be resumed by sending it back unchanged.
- Sources come from the search results and citations, not from the model's text. Only those URLs can be opened, only http and https, and only when the user clicks one. Citations are always shown, as Anthropic requires.

## Privacy

`core/privacy.*` and `ui/cloud_consent.*`:

- **Cloud confirmation.** Before packet data or capture statistics first go to a server that is not on this computer or local network, the panel shows what will be sent and to whom, with **Send**, **Settings...** and **Cancel**. "Local" means localhost, loopback, private or link-local IP addresses, and names that cannot be public (no dot, or ending in `.local`, `.lan`, `.internal` or `.home.arpa`). An approval is remembered per provider and server host, so changing the URL asks again. Settings can forget all approvals.
- **Size limits:** the dissection text sent per packet (2,000 to 100,000 characters, default 24,000) and the decoded payload sent (0 to 16,384 bytes, default 2,048; 0 sends none).
- **Address hiding** (off by default): `AddressMasker` replaces MAC addresses (colon, dash and dotted forms, Wireshark's `Intel_4e:66:a1`, `Maker_e:66:a1` and `Maker_6:a1` short forms, and, for a device already seen, its bare `0800274e66a1`-style and hex-dump forms), the public addresses of this computer's network adapters (also inside reverse-DNS `in-addr.arpa` names and dashed ISP host names), and IPv6 addresses with a MAC address built in (EUI-64) with placeholders such as `MAC-1` and `HOST-1`. One masker is used per conversation, so placeholders stay consistent across follow-up questions, and the panel maps them back for display. Server and private addresses are kept, because they help the model and identify no one. Other host names are not hidden. If hiding is switched on mid-conversation, follow-ups are refused until the conversation is restarted, because the stored first message holds real addresses. Online lookups skip this computer's own addresses while hiding is on.
- **Sent to the AI:** each tab has a collapsed section showing the exact message the model received.

## Safety rules

Packet contents, host names, registry records, server replies, model output and web pages can all be written by an attacker. The code follows these rules:

- Data sent to a model goes inside clearly marked blocks, and the system prompt says it is untrusted data, not instructions. Data cannot close its block early.
- Model and server text is shown as Markdown with HTML disabled (`QTextDocument::MarkdownNoHTML`). Nothing is loaded automatically: no images, no remote resources, no links opened, except the Research tab's source links described above. Link titles would become rich-text tooltips (which can load images, including from network paths), so `SafeMarkdownView` strips every tooltip and refuses tooltip events. Source link targets percent-encode brackets and parentheses so a URL cannot add a second link.
- API keys are stored in Windows Credential Manager (`SmartShark/<provider id>`), never in a file. They are never sent over plain http except to this computer, and redirects to other hosts are not followed.
- Replies are capped in size, and a streamed reply is stopped after 10 minutes.
- Settings are stored in `smartshark.ini` in Wireshark's per-user configuration folder.
