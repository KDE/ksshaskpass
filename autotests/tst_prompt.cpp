/*
 * SPDX-FileCopyrightText: 2026 Kai Uwe Broulik <kde@broulik.de>
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "prompt.h"

#include <QString>
#include <QTest>

class PromptTest : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void testPrompt_data();
    void testPrompt();
};

void PromptTest::testPrompt_data()
{
    QTest::addColumn<PromptType>("promptType");
    QTest::addColumn<QString>("prompt");

    QTest::addColumn<QString>("expectedIdentifier");
    QTest::addColumn<DisplayType>("expectedDisplayType");
    QTest::addColumn<bool>("expectedIgnoreKeychain");

    // PromptType special cases

    QTest::newRow("confirm") << PromptType::Confirm << QStringLiteral("does not matter") << QString() << DisplayType::Confirm << true;

    QTest::newRow("none") << PromptType::None << QStringLiteral("does not matter") << QString() << DisplayType::ConfirmCancel << true;

    // OpenSSH

    QTest::newRow("ssh-password") << PromptType::Entry << QStringLiteral("user@example.com's password: ") << QStringLiteral("user@example.com")
                                  << DisplayType::Password << false;

    QTest::newRow("ssh-pam") << PromptType::Entry << QStringLiteral("(user@example.com) Password: ") << QStringLiteral("user@example.com")
                             << DisplayType::Password << false;

    // Password change

    QTest::newRow("enter-old-password") << PromptType::Entry << QStringLiteral("Enter user@example.com's old password: ") << QStringLiteral("user@example.com")
                                        << DisplayType::Password << true;

    QTest::newRow("enter-new-password") << PromptType::Entry << QStringLiteral("Enter user@example.com's new password: ") << QStringLiteral("user@example.com")
                                        << DisplayType::Password << true;

    QTest::newRow("retype-new-password") << PromptType::Entry << QStringLiteral("Retype user@example.com's new password: ")
                                         << QStringLiteral("user@example.com") << DisplayType::Password << true;

    // SSH keys

    QTest::newRow("rsa-key") << PromptType::Entry << QStringLiteral("Enter passphrase for RSA key '/home/test/.ssh/id_rsa': ")
                             << QStringLiteral("/home/test/.ssh/id_rsa") << DisplayType::Password << false;

    QTest::newRow("key") << PromptType::Entry << QStringLiteral("Enter passphrase for key '/home/test/.ssh/id_ed25519': ")
                         << QStringLiteral("/home/test/.ssh/id_ed25519") << DisplayType::Password << false;

    QTest::newRow("ssh-add") << PromptType::Entry << QStringLiteral("Enter passphrase for /home/test/.ssh/id_ed25519: ")
                             << QStringLiteral("/home/test/.ssh/id_ed25519") << DisplayType::Password << false;

    QTest::newRow("ssh-add-confirm") << PromptType::Entry << QStringLiteral("Enter passphrase for /home/test/.ssh/id_ed25519 (will confirm each use): ")
                                     << QStringLiteral("/home/test/.ssh/id_ed25519") << DisplayType::Password << false;

    QTest::newRow("ssh-add-retry") << PromptType::Entry << QStringLiteral("Bad passphrase, try again for /home/test/.ssh/id_ed25519: ")
                                   << QStringLiteral("/home/test/.ssh/id_ed25519") << DisplayType::Password << true;

    QTest::newRow("ssh-add-retry-confirm") << PromptType::Entry
                                           << QStringLiteral("Bad passphrase, try again for /home/test/.ssh/id_ed25519 (will confirm each use): ")
                                           << QStringLiteral("/home/test/.ssh/id_ed25519") << DisplayType::Password << true;

    // PGP PIN

    QTest::newRow("pkcs11-pin") << PromptType::Entry << QStringLiteral("Enter PIN for 'OpenPGP': ") << QStringLiteral("OpenPGP") << DisplayType::Password
                                << false;

    QTest::newRow("security-key-pin") << PromptType::Entry << QStringLiteral("Enter PIN for ED25519-SK key SHA256:abcdef: ")
                                      << QStringLiteral("PIN:SHA256:abcdef") << DisplayType::Password << true;

    QTest::newRow("security-key-pin-presence") << PromptType::Entry << QStringLiteral("Enter PIN and confirm user presence for ECDSA-SK key SHA256:xyz: ")
                                               << QStringLiteral("PIN:SHA256:xyz") << DisplayType::Password << true;

    // OTP

    QTest::newRow("verification-code") << PromptType::Entry << QStringLiteral("Verification code: ") << QString() << DisplayType::ClearText << true;

    // Git

    QTest::newRow("git-username") << PromptType::Entry << QStringLiteral("Username: ") << QString() << DisplayType::ClearText << true;

    QTest::newRow("git-password") << PromptType::Entry << QStringLiteral("Password: ") << QString() << DisplayType::Password << true;

    QTest::newRow("git-username-url") << PromptType::Entry << QStringLiteral("Username for 'https://invent.kde.org': ")
                                      << QStringLiteral("https://invent.kde.org") << DisplayType::ClearText << false;

    QTest::newRow("git-password-url") << PromptType::Entry << QStringLiteral("Password for 'https://invent.kde.org': ")
                                      << QStringLiteral("https://invent.kde.org") << DisplayType::Password << false;

    // git-lfs

    QTest::newRow("git-lfs-username") << PromptType::Entry << QStringLiteral("Username for \"https://invent.kde.org\"")
                                      << QStringLiteral("https://invent.kde.org") << DisplayType::ClearText << false;

    QTest::newRow("git-lfs-password") << PromptType::Entry << QStringLiteral("Password for \"https://invent.kde.org\"")
                                      << QStringLiteral("https://invent.kde.org") << DisplayType::Password << false;

    // Unknown host

    QTest::newRow("unknown-host") << PromptType::Entry
                                  << QStringLiteral(
                                         "The authenticity of host 'invent.kde.org (1.2.3.4)' can't be established.\n"
                                         "ED25519 key fingerprint is SHA256:1234567890abcdef.\n"
                                         "This key is not known by any other names.\n"
                                         "Are you sure you want to continue connecting (yes/no/[fingerprint])? ")
                                  << QString() << DisplayType::UnknownSshHost << true;

    QTest::newRow("unknown-host-colon") << PromptType::Entry
                                        << QStringLiteral(
                                               "The authenticity of host 'invent.kde.org (1.2.3.4)' can't be established.\n"
                                               "ED25519 key fingerprint is: SHA256:1234567890abcdef.\n"
                                               "This key is not known by any other names.\n"
                                               "Are you sure you want to continue connecting (yes/no/[fingerprint])? ")
                                        << QString() << DisplayType::UnknownSshHost << true;
}

void PromptTest::testPrompt()
{
    QFETCH(PromptType, promptType);
    QFETCH(QString, prompt);

    QFETCH(QString, expectedIdentifier);
    QFETCH(DisplayType, expectedDisplayType);
    QFETCH(bool, expectedIgnoreKeychain);

    QString identifier;
    bool ignoreKeychain = false;
    DisplayType displayType = DisplayType::Unknown;
    parsePrompt(promptType, prompt, identifier, ignoreKeychain, displayType);

    QCOMPARE(identifier, expectedIdentifier);
    QCOMPARE(displayType, expectedDisplayType);
    QCOMPARE(ignoreKeychain, expectedIgnoreKeychain);
}

QTEST_GUILESS_MAIN(PromptTest)
#include "tst_prompt.moc"
