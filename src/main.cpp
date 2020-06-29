/***************************************************************************
 *   Copyright (C) 2006 Hans van Leeuwen <hanz@hanz.nl>                    *
 *   Copyright (C) 2008-2010 Armin Berres <armin@space-based.de>           *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA          *
 ***************************************************************************/

#include <sys/resource.h>
#include <memory>

#include <kwallet.h>
#include <KPasswordDialog>
#include <KAboutData>
#include <KLocalizedString>
#include <KMessageBox>

#include <QApplication>
#include <QCommandLineParser>
#include <QTextStream>
#include <QCommandLineOption>
#include <QInputDialog>
#include <QPointer>
#include <QRegularExpression>
#include <QLoggingCategory>
#include <QDesktopWidget>

Q_LOGGING_CATEGORY(LOG_KSSHASKPASS, "ksshaskpass")

enum Type {
        TypePassword,
        TypeClearText,
        TypeConfirm,
};

// Try to understand what we're asked for by parsing the phrase. Unfortunately, sshaskpass interface does not
// include any saner methods to pass the action or the name of the keyfile. Fortunately, openssh and git
// has no i18n, so this should work for all languages as long as the string is unchanged.
static void parsePrompt(const QString &prompt, QString& identifier, bool& ignoreWallet, enum Type& type)
{
        QRegularExpressionMatch match;

        // openssh sshconnect2.c
        // Case: password for authentication on remote ssh server
        match = QRegularExpression(QStringLiteral("^(.*@.*)'s password( \\(JPAKE\\))?: $")).match(prompt);
        if (match.hasMatch()) {
            identifier = match.captured(1);
            type = TypePassword;
            ignoreWallet = false;
            return;
        }

        // openssh sshconnect2.c
        // Case: password change request
        match = QRegularExpression(QStringLiteral("^(Enter|Retype) (.*@.*)'s (old|new) password: $")).match(prompt);
        if (match.hasMatch()) {
            identifier = match.captured(2);
            type = TypePassword;
            ignoreWallet = true;
            return;
        }

        // openssh sshconnect2.c and sshconnect1.c
        // Case: asking for passphrase for a certain keyfile
        match = QRegularExpression(QStringLiteral("^Enter passphrase for( RSA)? key '(.*)': $")).match(prompt);
        if (match.hasMatch()) {
            identifier = match.captured(2);
            type = TypePassword;
            ignoreWallet = false;
            return;
        }

        // openssh ssh-add.c
        // Case: asking for passphrase for a certain keyfile for the first time => we should try a password from the wallet
        match = QRegularExpression(QStringLiteral("^Enter passphrase for (.*?)( \\(will confirm each use\\))?: $")).match(prompt);
        if (match.hasMatch()) {
            identifier = match.captured(1);
            type = TypePassword;
            ignoreWallet = false;
            return;
        }

        // openssh ssh-add.c
        // Case: re-asking for passphrase for a certain keyfile => probably we've tried a password from the wallet, no point
        // in trying it again
        match = QRegularExpression(QStringLiteral("^Bad passphrase, try again for (.*?)( \\(will confirm each use\\))?: $")).match(prompt);
        if (match.hasMatch()) {
            identifier = match.captured(1);
            type = TypePassword;
            ignoreWallet = true;
            return;
        }

        // openssh ssh-pkcs11.c
        // Case: asking for PIN for some token label
        match = QRegularExpression(QStringLiteral("Enter PIN for '(.*)': $")).match(prompt);
        if (match.hasMatch()) {
            identifier = match.captured(1);
            type = TypePassword;
            ignoreWallet = false;
            return;
        }

        // openssh mux.c
        match = QRegularExpression(QStringLiteral("^(Allow|Terminate) shared connection to (.*)\\? $")).match(prompt);
        if (match.hasMatch()) {
            identifier = match.captured(2);
            type = TypeConfirm;
            ignoreWallet = true;
            return;
        }

        // openssh mux.c
        match = QRegularExpression(QStringLiteral("^Open (.* on .*)?$")).match(prompt);
        if (match.hasMatch()) {
            identifier = match.captured(1);
            type = TypeConfirm;
            ignoreWallet = true;
            return;
        }

        // openssh mux.c
        match = QRegularExpression(QStringLiteral("^Allow forward to (.*:.*)\\? $")).match(prompt);
        if (match.hasMatch()) {
            identifier = match.captured(1);
            type = TypeConfirm;
            ignoreWallet = true;
            return;
        }

        // openssh mux.c
        match = QRegularExpression(QStringLiteral("^Disable further multiplexing on shared connection to (.*)? $")).match(prompt);
        if (match.hasMatch()) {
            identifier = match.captured(1);
            type = TypeConfirm;
            ignoreWallet = true;
            return;
        }

        // openssh ssh-agent.c
        match = QRegularExpression(QStringLiteral("^Allow use of key (.*)?\\nKey fingerprint .*\\.$")).match(prompt);
        if (match.hasMatch()) {
            identifier = match.captured(1);
            type = TypeConfirm;
            ignoreWallet = true;
            return;
        }

        // openssh sshconnect.c
        match = QRegularExpression(QStringLiteral("^Add key (.*) \\(.*\\) to agent\\?$")).match(prompt);
        if (match.hasMatch()) {
            identifier = match.captured(1);
            type = TypeConfirm;
            ignoreWallet = true;
            return;
        }

        // git imap-send.c
        // Case: asking for password by git imap-send
        match = QRegularExpression(QStringLiteral("^Password \\((.*@.*)\\): $")).match(prompt);
        if (match.hasMatch()) {
            identifier = match.captured(1);
            type = TypePassword;
            ignoreWallet = false;
            return;
        }

        // git credential.c
        // Case: asking for username by git without specifying any other information
        match = QRegularExpression(QStringLiteral("^Username: $")).match(prompt);
        if (match.hasMatch()) {
            identifier = QString();
            type = TypeClearText;
            ignoreWallet = true;
            return;
        }

        // git credential.c
        // Case: asking for password by git without specifying any other information
        match = QRegularExpression(QStringLiteral("^Password: $")).match(prompt);
        if (match.hasMatch()) {
            identifier = QString();
            type = TypePassword;
            ignoreWallet = true;
            return;
        }

        // git credential.c
        // Case: asking for username by git for some identifier
        match = QRegularExpression(QStringLiteral("^Username for '(.*)': $")).match(prompt);
        if (match.hasMatch()) {
            identifier = match.captured(1);
            type = TypeClearText;
            ignoreWallet = false;
            return;
        }

        // git credential.c
        // Case: asking for password by git for some identifier
        match = QRegularExpression(QStringLiteral("^Password for '(.*)': $")).match(prompt);
        if (match.hasMatch()) {
            identifier = match.captured(1);
            type = TypePassword;
            ignoreWallet = false;
            return;
        }

        // Case: username extraction from git-lfs
        match = QRegularExpression(QStringLiteral("^Username for \"(.*?)\"$")).match(prompt);
        if (match.hasMatch()) {
            identifier = match.captured(1);
            type = TypeClearText;
            ignoreWallet = false;
            return;
        }

        // Case: password extraction from git-lfs
        match = QRegularExpression(QStringLiteral("^Password for \"(.*?)\"$")).match(prompt);
        if (match.hasMatch()) {
            identifier = match.captured(1);
            type = TypePassword;
            ignoreWallet = false;
            return;
        }

        // Case: password extraction from mercurial, see bug 380085
        match = QRegularExpression(QStringLiteral("^(.*?)'s password: $")).match(prompt);
        if (match.hasMatch()) {
            identifier = match.captured(1);
            type = TypePassword;
            ignoreWallet = false;
            return;
        }

        // Nothing matched; either it was called by some sort of a script with a custom prompt (i.e. not ssh-add), or
        // strings we're looking for were broken. Issue a warning and continue without identifier.
        qCWarning(LOG_KSSHASKPASS) << "Unable to parse phrase" << prompt;
}

int main(int argc, char **argv)
{
    QGuiApplication::setAttribute(Qt::AA_UseHighDpiPixmaps, true);

    QApplication app(argc, argv);
    KLocalizedString::setApplicationDomain("ksshaskpass");

    //TODO update it.
    KAboutData about(
        QStringLiteral("ksshaskpass"),
        i18n("Ksshaskpass"),
        QStringLiteral(PROJECT_VERSION),
        i18n("KDE version of ssh-askpass"),
        KAboutLicense::GPL,
        i18n("(c) 2006 Hans van Leeuwen\n(c) 2008-2010 Armin Berres\n(c) 2013 Pali Rohár"),
        i18n("Ksshaskpass allows you to interactively prompt users for a passphrase for ssh-add"),
        QStringLiteral("https://commits.kde.org/ksshaskpass"),
        QStringLiteral("armin@space-based.de")
    );

    about.addAuthor(i18n("Armin Berres"), i18n("Current author"), QStringLiteral("armin@space-based.de"));
    about.addAuthor(i18n("Hans van Leeuwen"), i18n("Original author"), QStringLiteral("hanz@hanz.nl"));
    about.addAuthor(i18n("Pali Rohár"), i18n("Contributor"), QStringLiteral("pali.rohar@gmail.com"));
    about.addAuthor(i18n("Armin Berres"), i18n("Current author"), QStringLiteral("armin@space-based.de"), QString());
    about.addAuthor(i18n("Hans van Leeuwen"), i18n("Original author"), QStringLiteral("hanz@hanz.nl"), QString());
    about.addAuthor(i18n("Pali Rohár"), i18n("Contributor"), QStringLiteral("pali.rohar@gmail.com"), QString());
    KAboutData::setApplicationData(about);

    QCommandLineParser parser;
    about.setupCommandLine(&parser);
    parser.addOption(QCommandLineOption(QStringList() <<  QStringLiteral("+[prompt]"), i18nc("Name of a prompt for a password", "Prompt")));

    parser.process(app);
    about.processCommandLine(&parser);

    const QString walletFolder = app.applicationName();
    QString dialog = i18n("Please enter passphrase");  // Default dialog text.
    QString identifier;
    QString item;
    bool ignoreWallet = false;
    enum Type type = TypePassword;

    // Parse commandline arguments
    if (!parser.positionalArguments().isEmpty()) {
        dialog = parser.positionalArguments().at(0);
        parsePrompt(dialog, identifier, ignoreWallet, type);
    }

    // Open KWallet to see if an item was previously stored
    WId winId = QApplication::desktop()->winId();
    std::auto_ptr<KWallet::Wallet> wallet(ignoreWallet ? 0 : KWallet::Wallet::openWallet(KWallet::Wallet::NetworkWallet(), winId));

    if ((!ignoreWallet) && (!identifier.isNull()) && wallet.get() && wallet->hasFolder(walletFolder)) {
        wallet->setFolder(walletFolder);

        QString retrievedItem;
        wallet->readPassword(identifier, retrievedItem);

        if (!retrievedItem.isEmpty()) {
            item = retrievedItem;
        } else {
            // There was a bug in previous versions of ksshaskpass that caused it to create keys with extra space
            // appended to key file name. Try these keys too, and, if there's a match, ensure that it's properly
            // replaced with proper one.
            const QString keyFile = identifier + QLatin1Char(' ');
            wallet->readPassword(keyFile, retrievedItem);
            if (!retrievedItem.isEmpty()) {
                qCWarning(LOG_KSSHASKPASS) << "Detected legacy key for " << identifier << ", enabling workaround";
                item = retrievedItem;
                wallet->renameEntry(keyFile, identifier);
            }
        }
    }

    if (!item.isEmpty()) {
        QTextStream(stdout) << item;
        return 0;
    }

    // Item could not be retrieved from wallet. Open dialog
    switch (type) {
        case TypeConfirm: {
            if (KMessageBox::questionYesNo(0, dialog, i18n("Ksshaskpass")) != KMessageBox::Yes) {
                // dialog has been canceled
                return 1;
            }
            item = QStringLiteral("yes\n");
            break;
        }
        case TypeClearText:
            // Should use a dialog with visible input, but KPasswordDialog doesn't support that and
            // other available dialog types don't have a "Keep" checkbox.
            /* fallthrough */
        case TypePassword: {
            // create the password dialog, but only show "Enable Keep" button, if the wallet is open
            KPasswordDialog::KPasswordDialogFlag flag(KPasswordDialog::NoFlags);
            if (wallet.get()) {
                flag = KPasswordDialog::ShowKeepPassword;
            }
            QPointer<KPasswordDialog> kpd = new KPasswordDialog(nullptr, flag);

            kpd->setPrompt(dialog);
            kpd->setWindowTitle(i18n("Ksshaskpass"));
            // We don't want to dump core when the password dialog is shown, because it could contain the entered password.
            // KPasswordDialog::disableCoreDumps() seems to be gone in KDE 4 -- do it manually
            struct rlimit rlim;
            rlim.rlim_cur = rlim.rlim_max = 0;
            setrlimit(RLIMIT_CORE, &rlim);

            if (kpd->exec() == QDialog::Accepted) {
                item = kpd->password();
                // If "Enable Keep" is enabled, open/create a folder in KWallet and store the password.
                if ((!identifier.isNull()) && wallet.get() && kpd->keepPassword()) {
                    if (!wallet->hasFolder(walletFolder)) {
                        wallet->createFolder(walletFolder);
                    }
                    wallet->setFolder(walletFolder);
                    wallet->writePassword(identifier, item);
                }
            } else {
                // dialog has been canceled
                return 1;
            }
            break;
        }
    }

    QTextStream out(stdout);
    out << item << "\n";
    return 0;
}

