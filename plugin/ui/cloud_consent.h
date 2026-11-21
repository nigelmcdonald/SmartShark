/* cloud_consent.h
 *
 * The question SmartShark asks before packet data first goes to a cloud
 * provider: what is sent, to whom, and the choice to send, change settings
 * or cancel. Shown inside a panel, not as a pop-up.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <functional>

#include <QFrame>

#include "core/settings.h"

class QLabel;

namespace smartshark {

class CloudConsent : public QFrame {
    Q_OBJECT
public:
    explicit CloudConsent(QWidget *parent = nullptr);

    // True if packet data may go to the active provider without asking: it
    // is on this computer or network, or the user already agreed.
    static bool approved(const Settings &settings);

    // Show the question. whatIsSent lists the data, as HTML list items.
    // After "Send" (the approval is saved) or after the Settings dialog
    // closes, proceed() runs; it should check approved() again. After
    // "Cancel", cancelled() runs.
    void ask(const Settings &settings, const QString &whatIsSent, std::function<void()> proceed,
             std::function<void()> cancelled);

private:
    QLabel *text_;
    std::function<void()> proceed_;
    std::function<void()> cancelled_;
    QString approvalKey_;
};

// Text for the panels when the user cancels: nothing was sent, and how to
// keep packet data on this computer.
QString cloudCancelledMessage();

// Public IP addresses on this computer's network adapters.
QStringList localPublicAddresses();

// Addresses online lookups must skip: this computer's own public addresses
// when address hiding is on, otherwise none.
QStringList ownAddressesToSkip(const Settings &settings);

// True if address hiding is on now but the conversation started without it.
// Its stored messages then hold real addresses, so a follow-up must not send
// them; the panel shows hidingSwitchedOnMessage() instead.
bool hidingSwitchedOn(bool conversationMasked, const Settings &settings);
QString hidingSwitchedOnMessage(const QString &startAgain);

// Clear the masker and set its scope for a new conversation. Returns true
// if addresses are to be hidden.
bool setUpMasker(AddressMasker *masker, const Settings &settings);

// Markdown for the panels' "Sent to the AI" section: what was hidden, and
// the first message exactly as the model received it.
QString sentToAiMarkdown(const QString &message, const Settings &settings, const AddressMasker &masker);

} // namespace smartshark
