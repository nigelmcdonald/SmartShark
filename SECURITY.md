# Security

SmartShark sends data from your packet captures to an AI model. This page explains what leaves your computer, the risks we considered, how the code protects you, what a security review found, and how to report a problem.

## Reporting a vulnerability

Please report security problems privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. Please don't open a public issue for a security problem. You'll get a reply as soon as possible, and fixes are credited to you in the release notes if you wish.

## Who wrote and reviewed this code

SmartShark's code was written by an AI model (Claude, by Anthropic) under the direction of the project owner. The security review below was also done by an AI model. **It is not a paid third-party audit.** We publish the review so you can judge it yourself, and the source is open so anyone can check the code. Independent reviews and reports are very welcome.

## What leaves your computer

Nothing is sent until you use a SmartShark feature. Then:

| Feature | What is sent | To whom |
|---|---|---|
| Generate a display filter | your request and the current filter (no packet data) | the AI provider you chose |
| Explain a packet | its decoded fields (24,000 characters by default), up to 2 KB of decoded payload, facts about its IP addresses, your follow-up questions | the AI provider |
| Ask about the capture | statistics (counts, busiest hosts and conversations with their addresses, names seen such as DNS and TLS server names), your questions | the AI provider |
| Research on the web | the same as a packet explanation or capture question; Claude's web searches run on Anthropic's servers | Anthropic |
| Online IP lookups (only if you allow them) | public IP addresses only, no packet data | rdap.org (and the regional registry it redirects to) and your DNS server |

- With a server on your own computer (LM Studio, Ollama and similar), packet data stays on your computer. A server elsewhere on your local network receives it over your network.
- Before packet data first goes to a server outside your computer and local network, SmartShark asks, once per provider and server, and lists what will be sent. It warns if the address uses unencrypted `http://`.
- In **Tools > SmartShark > Settings > Privacy** you can send fewer packet fields, send no payload, and hide MAC addresses, this computer's public IP addresses and any addresses you add (such as your router's public IP) behind placeholders such as `MAC-1` and `HOST-1`. The panel's **Sent to the AI** section shows the packet or capture message exactly as sent.
- What the provider does with the data is governed by its own terms.

## Risks we designed against

| Risk | Example | Protection |
|---|---|---|
| A hostile packet attacks the panel | a DNS name or web page containing HTML, image links or network paths | AI output and network names are shown as Markdown with HTML, images and tooltips switched off; nothing is loaded from disk or network; network names in tables are escaped |
| A hostile packet steers the AI (prompt injection) | a packet saying "ignore your instructions" | packet data is wrapped in marked blocks that the data cannot close or fake, and the model is told it is untrusted data. This reduces the risk but cannot remove it (see Known limits) |
| A hostile or broken server | an endless or enormous reply, malformed data, a misleading link | replies over 200,000 characters and requests over 10 minutes are stopped; response sizes are capped; error text is shortened; only source links from Claude's search results open, only when clicked, only http(s) |
| Data sent without consent | a follow-up question after switching to a cloud provider | every send, follow-ups included, checks consent against the same settings used to build the request |
| API key theft | a key sent to the wrong server, or over plain http | keys live in Windows Credential Manager, never in a file, log or URL; never sent over `http://` except to `localhost`; each key is tied to the server it was entered for, and SmartShark asks before sending it to a different one; requests do not follow redirects to other hosts |
| Crashes from hostile captures | huge fields, odd encodings | bounded buffers, size limits on everything sent and shown, Wireshark's own filter compiler checks every filter before it is applied |

## Security review, 2026-11-21

- **Reviewer:** Fable 5.2 (model ID `claude-fable-5-2`), an AI model by Anthropic, working independently: it was given the source code and a list of threats, not the conclusions of earlier reviews.
- **Commit reviewed:** `3203d5c`. Method: reading the whole code base and tracing data end to end, plus a small test program to confirm the most important findings.
- **Overall result:** no critical or high-severity problems. Two medium and six low-severity problems, all fixed before the first release. The full report: [docs/security-review-2026-11-21.md](docs/security-review-2026-11-21.md).

| # | Severity | Finding | What we did |
|---|---|---|---|
| 1 | Medium | A link title in AI output became a rich-text tooltip that could load a file from a network path on mouse-over, which on Windows can leak your login hash | Tooltips are stripped and tooltip events refused in every panel view. Regression test added |
| 2 | Medium | Address hiding missed Wireshark's short MAC forms for small vendor blocks (`Maker_1:23:45`, `Maker_1:23`) and MACs written without separators | All short forms are recognised; a device already seen is also hidden in bare (`0800274e66a1`) and hex-dump forms. Tests added |
| 3 | Low | Turning on address hiding mid-conversation didn't apply to follow-ups, although the consent text said it did | Follow-ups are refused until the conversation is restarted with hiding on |
| 4 | Low | "My public IP" covers only addresses on this computer's adapters; reverse-DNS and ISP-style names and online lookups could still reveal your own address | Own addresses are also hidden in `in-addr.arpa` and dashed host names, and are not looked up online while hiding is on. A new **Also hide** box in Settings covers your router's public IP, which no adapter carries |
| 5 | Low | A crafted source URL could add a second, misleading link to the Sources list | Brackets and parentheses in link targets are percent-encoded. Regression test added |
| 6 | Low | A hostile server could slow Wireshark down: no reply cap on the Anthropic path, slow text handling, uncapped error text and filter length | Reply cap on every path, faster text handling, error text shortened to 500 characters, filters over 4,000 characters rejected before compiling, list sizes capped |
| 7 | Low | A saved API key followed the provider, not the server, so changing a server address could send the key to a new host | Keys are tied to their server; SmartShark asks before sending a saved key elsewhere. Tests added |
| 8 | Low | Packet data could go unencrypted to an `http://` server, and some "nothing leaves your computer" wording overstated | The cloud question warns about `http://`; only `localhost` counts as this computer for keys; Settings and README wording corrected |
| 9 | Info | Prompt injection is reduced, not prevented | All prompt tags are now neutralised in every block, including the address lines; documented as a known limit |
| 10 | Info | Online lookups follow rdap.org's redirects | By design (rdap.org redirects to the regional registry; no keys or packet data are sent). README corrected |
| 11 | Info | Release process: checksums, pinned build inputs | Releases publish SHA-256 checksums (see below) |
| 12 | Info | Two screenshots carried author metadata | Metadata removed |

The reviewer also checked, and found sound: API key storage and handling, TLS (Qt defaults, no overrides), URL validation, the consent checks on every send path, JSON and stream parsing, object lifetimes and re-entrancy, the Wireshark integration (buffers, retap, filter validation) and the build scripts.

## Known limits

- **Prompt injection cannot be ruled out.** A packet crafted by an attacker might make the model give a wrong verdict or misleading advice. The model has no tools that can act on your computer, it cannot open links or start lookups, and its web searches go to Anthropic, not to an attacker. Still, treat answers about suspicious traffic as a second opinion, not proof.
- **Your router's public IP is only hidden if you add it.** Behind a home router your public IPv4 address belongs to the router, not your computer, so SmartShark can't detect it. Type it into **Also hide** in Settings; it may otherwise appear in some traffic (for example STUN or UPnP replies).
- **Host names are sent**, including names Wireshark resolved, unless they contain one of your hidden addresses.
- **Raw payload bytes** can contain an address in a form SmartShark doesn't recognise.
- **A research turn** can make up to three requests of up to 10 minutes each when Claude pauses a long search.
- **Other programs running as you** can read Windows Credential Manager, like any app's saved credentials.
- **A Wireshark plugin runs with Wireshark's full rights.** Only install `smartshark.dll` from this repository's Releases page, and check its SHA-256 checksum.

## Verifying a download

Each release lists the SHA-256 checksum of every file. In PowerShell:

```
Get-FileHash .\smartshark.dll -Algorithm SHA256
```

The result must match the checksum on the release page exactly.
