/* backend_factory.h
 *
 * Create the chat backend for the provider chosen in settings.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include "core/http_backend.h"
#include "core/secret_store.h"
#include "core/settings.h"
#include "ui/ws_services.h"

namespace smartshark {

// The backend for the provider in these settings. Build it from the same
// Settings snapshot that the cloud consent check used. The caller owns the
// result through Qt's parent. *config receives the settings used (without
// the key), for messages such as "no model chosen".
// The stored API key for cfg's provider, or an empty string if there is none
// or it was saved for a different server (see Settings::keyMayBeSentTo).
inline QString storedApiKey(const Settings &settings, const ProviderConfig &cfg)
{
    if (!settings.keyMayBeSentTo(cfg.providerId, cfg.baseUrl))
        return QString();
    return secrets::loadApiKey(cfg.providerId);
}

inline HttpBackend *makeBackend(const Settings &settings, QObject *parent, ProviderConfig *config = nullptr)
{
    ProviderConfig cfg = settings.activeConfig();
    if (config)
        *config = cfg;
    cfg.apiKey = storedApiKey(settings, cfg);
    return createBackend(cfg, parent);
}

} // namespace smartshark
