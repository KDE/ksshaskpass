/*
 *   SPDX-FileCopyrightText: 2006 Hans van Leeuwen <hanz@hanz.nl>
 *   SPDX-FileCopyrightText: 2008-2010 Armin Berres <armin@space-based.de>
 *   SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "prompt.h"
#include "debug.h"

#include <QRegularExpression>

void parsePrompt(PromptType promptType, const QString &prompt, QString &identifier, bool &ignoreKeychain, DisplayType &displayType)
{
    if (promptType == PromptType::Confirm) {
        displayType = DisplayType::Confirm;
        ignoreKeychain = true;
        return;
    }

    if (promptType == PromptType::None) {
        displayType = DisplayType::ConfirmCancel;
        ignoreKeychain = true;
        return;
    }

    // "Entry" prompt type: password or text input. We parse several known prompts from openssh and git (which have no i18n)
    // to extract credential names and determine whether to use cleartext.
    QRegularExpressionMatch match;

    // openssh sshconnect2.c
    // Case: password for authentication on remote ssh server
    match = QRegularExpression(QStringLiteral("^(.*@.*)'s password: $")).match(prompt);
    if (match.hasMatch()) {
        identifier = match.captured(1);
        displayType = DisplayType::Password;
        ignoreKeychain = false;
        return;
    }

    // Case: password for authentication on remote ssh server, also supports PAM format
    match = QRegularExpression(QStringLiteral("^\\((.*@.*)\\) Password: $")).match(prompt);
    if (match.hasMatch()) {
        identifier = match.captured(1);
        displayType = DisplayType::Password;
        ignoreKeychain = false;
        return;
    }

    // openssh sshconnect2.c
    // Case: password change request
    match = QRegularExpression(QStringLiteral("^(Enter|Retype) (.*@.*)'s (old|new) password: $")).match(prompt);
    if (match.hasMatch()) {
        identifier = match.captured(2);
        displayType = DisplayType::Password;
        ignoreKeychain = true;
        return;
    }

    // openssh ssh-keygen.c
    // Case: ssh-keygen asking for passphrase, newer ssh-keygen includes the path.
    match = QRegularExpression(QStringLiteral("^Enter passphrase (for \"(.*?)\" )?\\(empty for no passphrase\\): $")).match(prompt);
    if (match.hasMatch()) {
        identifier = QString();
        displayType = DisplayType::Password;
        ignoreKeychain = true;
        return;
    }

    // openssh ssh-keygen.c
    // Case: ssh-keygen asking for passphrase when changing existing key
    match = QRegularExpression(QStringLiteral("^Enter new passphrase \\(empty for no passphrase\\): $")).match(prompt);
    if (match.hasMatch()) {
        identifier = QString();
        displayType = DisplayType::Password;
        ignoreKeychain = true;
        return;
    }

    // openssh ssh-keygen.c
    // Case: ssh-keygen asking to confirm passphrase
    match = QRegularExpression(QStringLiteral("^Enter same passphrase again: $")).match(prompt);
    if (match.hasMatch()) {
        identifier = QString();
        displayType = DisplayType::Password;
        ignoreKeychain = true;
        return;
    }

    // openssh sshconnect2.c and sshconnect1.c
    // Case: asking for passphrase for a certain keyfile
    match = QRegularExpression(QStringLiteral("^Enter passphrase for( RSA)? key '(.*)': $")).match(prompt);
    if (match.hasMatch()) {
        identifier = match.captured(2);
        displayType = DisplayType::Password;
        ignoreKeychain = false;
        return;
    }

    // openssh ssh-add.c
    // Case: asking for passphrase for a certain keyfile for the first time => we should try a password from the keychain
    match = QRegularExpression(QStringLiteral("^Enter passphrase for (.*?)( \\(will confirm each use\\))?: $")).match(prompt);
    if (match.hasMatch()) {
        identifier = match.captured(1);
        displayType = DisplayType::Password;
        ignoreKeychain = false;
        return;
    }

    // openssh ssh-add.c
    // Case: re-asking for passphrase for a certain keyfile => probably we’ve tried a password from the keychain, no point
    // in trying it again
    match = QRegularExpression(QStringLiteral("^Bad passphrase, try again for (.*?)( \\(will confirm each use\\))?: $")).match(prompt);
    if (match.hasMatch()) {
        identifier = match.captured(1);
        displayType = DisplayType::Password;
        ignoreKeychain = true;
        return;
    }

    // openssh ssh-pkcs11.c
    // Case: asking for PIN for some token label
    match = QRegularExpression(QStringLiteral("Enter PIN for '(.*)': $")).match(prompt);
    if (match.hasMatch()) {
        identifier = match.captured(1);
        displayType = DisplayType::Password;
        ignoreKeychain = false;
        return;
    }

    // openssh ssh-agent.c
    // Case: asking to provide the PIN of the security key device
    // match after "for" is key type, match after "key" is SHA digest of key
    match = QRegularExpression(QStringLiteral("^Enter PIN( and confirm user presence)? for (.*?) key (.*?): $")).match(prompt);
    if (match.hasMatch()) {
        identifier = QStringLiteral("PIN:") + match.captured(3);
        displayType = DisplayType::Password;
        ignoreKeychain = true;
        return;
    }

    // google-authenticator-libpam pam_google_authenticator.c
    // Case: OTP verification code request from remote ssh server through PAM module
    match = QRegularExpression(QStringLiteral("Verification code: $")).match(prompt);
    if (match.hasMatch()) {
        identifier = QString();
        displayType = DisplayType::ClearText;
        ignoreKeychain = true;
        return;
    }

    // git credential.c
    // Case: asking for username by git without specifying any other information
    match = QRegularExpression(QStringLiteral("^Username: $")).match(prompt);
    if (match.hasMatch()) {
        identifier = QString();
        displayType = DisplayType::ClearText;
        ignoreKeychain = true;
        return;
    }

    // git credential.c
    // Case: asking for password by git without specifying any other information
    match = QRegularExpression(QStringLiteral("^Password: $")).match(prompt);
    if (match.hasMatch()) {
        identifier = QString();
        displayType = DisplayType::Password;
        ignoreKeychain = true;
        return;
    }

    // git credential.c
    // Case: asking for username by git for some identifier
    match = QRegularExpression(QStringLiteral("^Username for '(.*)': $")).match(prompt);
    if (match.hasMatch()) {
        identifier = match.captured(1);
        displayType = DisplayType::ClearText;
        ignoreKeychain = false;
        return;
    }

    // git credential.c
    // Case: asking for password by git for some identifier
    match = QRegularExpression(QStringLiteral("^Password for '(.*)': $")).match(prompt);
    if (match.hasMatch()) {
        identifier = match.captured(1);
        displayType = DisplayType::Password;
        ignoreKeychain = false;
        return;
    }

    // Case: username extraction from git-lfs
    match = QRegularExpression(QStringLiteral("^Username for \"(.*?)\"$")).match(prompt);
    if (match.hasMatch()) {
        identifier = match.captured(1);
        displayType = DisplayType::ClearText;
        ignoreKeychain = false;
        return;
    }

    // Case: password extraction from git-lfs
    match = QRegularExpression(QStringLiteral("^Password for \"(.*?)\"$")).match(prompt);
    if (match.hasMatch()) {
        identifier = match.captured(1);
        displayType = DisplayType::Password;
        ignoreKeychain = false;
        return;
    }

    // Case: unknown SSH host
    match = QRegularExpression(QStringLiteral("^The authenticity of host '([^']+)(?: \\(([^)]+)\\))?' can't be established\\.\n"
                                              "([A-Z0-9_-]+) key fingerprint is:? ([A-Za-z0-9:+/=]+)\\.\n"
                                              "(?:.*\n)*"
                                              "Are you sure you want to continue connecting \\(yes/no/\\[fingerprint\\]\\)\\?\\s*$"))
                .match(prompt);
    if (match.hasMatch()) {
        displayType = DisplayType::UnknownSshHost;
        ignoreKeychain = true;
        return;
    }

    // Nothing matched; either it was called by some sort of a script with a custom prompt (i.e. not ssh-add), or
    // strings we're looking for were broken. Issue a warning and continue without identifier.
    qCWarning(LOG_KSSHASKPASS) << "Unable to parse phrase" << prompt;
}
