/* provider.h
 *
 * LLM provider presets and the connection settings for one provider.
 * No Wireshark dependencies, so this can be unit-tested on its own.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QList>
#include <QString>

namespace smartshark {

// Wire protocol a provider speaks.
enum class ApiKind {
    OpenAiCompatible,  // POST {base}/chat/completions, GET {base}/models
    AnthropicMessages, // POST {base}/messages, GET {base}/models (Anthropic's own API)
};

struct ProviderPreset {
    QString id;          // stable key, used in settings and the credential name
    QString displayName;
    ApiKind api;
    QString baseUrl;     // empty for "custom"
    bool needsApiKey;
    bool isLocal;
    QString keyHelpUrl;  // where to get an API key; empty for local servers
};

// Built-in presets. Model names are not hardcoded: they change often, so the
// settings dialog fetches the live list from the provider's /models endpoint.
const QList<ProviderPreset> &providerPresets();

// The preset with this id, or nullptr.
const ProviderPreset *findPreset(const QString &id);

// Everything a client needs to make a request.
struct ProviderConfig {
    QString providerId;
    ApiKind api = ApiKind::OpenAiCompatible;
    QString baseUrl;
    QString apiKey;     // empty for local servers
    QString model;
    int timeoutSec = 120;
};

// Join a base URL and an endpoint path without doubling or dropping the slash.
QString joinUrl(const QString &baseUrl, const QString &path);

} // namespace smartshark
