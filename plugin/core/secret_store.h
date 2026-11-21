/* secret_store.h
 *
 * API keys live in the operating system's credential store, never in the
 * settings file. On Windows that is Credential Manager, under the generic
 * credential "SmartShark/<provider id>".
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QString>

namespace smartshark::secrets {

// Returns an empty string if there is no stored key.
QString loadApiKey(const QString &providerId);

// An empty key deletes the stored one. Returns false on failure.
bool saveApiKey(const QString &providerId, const QString &key);

} // namespace smartshark::secrets
