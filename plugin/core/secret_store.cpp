/* secret_store.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "core/secret_store.h"

#include <string>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wincred.h>
#endif

namespace smartshark::secrets {

#ifdef _WIN32

static std::wstring targetName(const QString &providerId)
{
    return (QStringLiteral("SmartShark/") + providerId).toStdWString();
}

QString loadApiKey(const QString &providerId)
{
    PCREDENTIALW cred = nullptr;
    const std::wstring target = targetName(providerId);
    if (!CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &cred))
        return QString();
    QString key = QString::fromUtf8(reinterpret_cast<const char *>(cred->CredentialBlob),
                                    static_cast<qsizetype>(cred->CredentialBlobSize));
    SecureZeroMemory(cred->CredentialBlob, cred->CredentialBlobSize);
    CredFree(cred);
    return key;
}

bool saveApiKey(const QString &providerId, const QString &key)
{
    const std::wstring target = targetName(providerId);
    if (key.isEmpty()) {
        if (CredDeleteW(target.c_str(), CRED_TYPE_GENERIC, 0))
            return true;
        return GetLastError() == ERROR_NOT_FOUND;
    }

    QByteArray blob = key.toUtf8();
    const std::wstring user = L"api-key";
    CREDENTIALW cred = {};
    cred.Type = CRED_TYPE_GENERIC;
    cred.TargetName = const_cast<LPWSTR>(target.c_str());
    cred.UserName = const_cast<LPWSTR>(user.c_str());
    cred.CredentialBlobSize = static_cast<DWORD>(blob.size());
    cred.CredentialBlob = reinterpret_cast<LPBYTE>(blob.data());
    cred.Persist = CRED_PERSIST_LOCAL_MACHINE; // this user, this PC; not roamed
    const bool ok = CredWriteW(&cred, 0) != FALSE;
    SecureZeroMemory(blob.data(), static_cast<size_t>(blob.size()));
    return ok;
}

#else

// Other platforms are not supported yet. Keys are not persisted.
QString loadApiKey(const QString &) { return QString(); }
bool saveApiKey(const QString &, const QString &) { return false; }

#endif

} // namespace smartshark::secrets
