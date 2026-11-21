/* provider.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "core/provider.h"

namespace smartshark {

const QList<ProviderPreset> &providerPresets()
{
    // Base URLs checked against each provider's documentation in November 2026.
    static const QList<ProviderPreset> presets = {
        {QStringLiteral("lmstudio"), QStringLiteral("LM Studio (local)"), ApiKind::OpenAiCompatible,
         QStringLiteral("http://localhost:1234/v1"), false, true, QString()},
        {QStringLiteral("ollama"), QStringLiteral("Ollama (local)"), ApiKind::OpenAiCompatible,
         QStringLiteral("http://localhost:11434/v1"), false, true, QString()},
        {QStringLiteral("openai"), QStringLiteral("OpenAI"), ApiKind::OpenAiCompatible,
         QStringLiteral("https://api.openai.com/v1"), true, false,
         QStringLiteral("https://platform.openai.com/api-keys")},
        {QStringLiteral("anthropic"), QStringLiteral("Anthropic Claude"), ApiKind::AnthropicMessages,
         QStringLiteral("https://api.anthropic.com/v1"), true, false,
         QStringLiteral("https://platform.claude.com/settings/keys")},
        {QStringLiteral("gemini"), QStringLiteral("Google Gemini"), ApiKind::OpenAiCompatible,
         QStringLiteral("https://generativelanguage.googleapis.com/v1beta/openai"), true, false,
         QStringLiteral("https://aistudio.google.com/apikey")},
        {QStringLiteral("kimi"), QStringLiteral("Moonshot Kimi"), ApiKind::OpenAiCompatible,
         QStringLiteral("https://api.moonshot.ai/v1"), true, false,
         QStringLiteral("https://platform.kimi.ai")},
        {QStringLiteral("deepseek"), QStringLiteral("DeepSeek"), ApiKind::OpenAiCompatible,
         QStringLiteral("https://api.deepseek.com/v1"), true, false,
         QStringLiteral("https://platform.deepseek.com/api_keys")},
        {QStringLiteral("custom"), QStringLiteral("Other OpenAI-compatible server (llama.cpp, vLLM, ...)"), ApiKind::OpenAiCompatible,
         QString(), false, false, QString()},
    };
    return presets;
}

const ProviderPreset *findPreset(const QString &id)
{
    for (const ProviderPreset &p : providerPresets()) {
        if (p.id == id)
            return &p;
    }
    return nullptr;
}

QString joinUrl(const QString &baseUrl, const QString &path)
{
    QString base = baseUrl.trimmed();
    while (base.endsWith(QLatin1Char('/')))
        base.chop(1);
    QString tail = path;
    while (tail.startsWith(QLatin1Char('/')))
        tail.remove(0, 1);
    return base + QLatin1Char('/') + tail;
}

} // namespace smartshark
