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

#include <QApplication>
#include <QCommandLineParser>
#include <QTextStream>
#include <QCommandLineOption>
#include <QPointer>

int main(int argc, char **argv)
{
    KLocalizedString::setApplicationDomain("ksshaskpass");

    //TODO update it.
    KAboutData about(
        QStringLiteral("ksshaskpass"),
        i18n("Ksshaskpass"),
        PROJECT_VERSION,
        i18n("KDE version of ssh-askpass"),
        KAboutLicense::GPL,
        i18n("(c) 2006 Hans van Leeuwen\n(c) 2008-2010 Armin Berres"),
        i18n("Ksshaskpass allows you to interactively prompt users for a passphrase for ssh-add"),
        QStringLiteral("http://www.kde-apps.org/content/show.php?action=content&content=50971"),
        QStringLiteral("armin@space-based.de")
    );

    about.addAuthor(i18n("Armin Berres"), i18n("Current author"), QStringLiteral("armin@space-based.de"), 0);
    about.addAuthor(i18n("Hans van Leeuwen"), i18n("Original author"), QStringLiteral("hanz@hanz.nl"), 0);

    QCommandLineParser parser;
    QApplication app(argc, argv);
    KAboutData::setApplicationData(about);
    parser.addVersionOption();
    parser.addHelpOption();
    parser.addOption(QCommandLineOption(QStringList() <<  QStringLiteral("+[prompt]"), i18nc("Name of a prompt for a password", "Prompt")));

    about.setupCommandLine(&parser);
    parser.process(app);
    about.processCommandLine(&parser);

    const QString walletFolder = app.applicationName();
    QString dialog = i18n("Please enter passphrase");  // Default dialog text.
    QString keyFile;
    QString password;
    bool wrongPassphrase = false;

    // Parse commandline arguments
    if (!parser.positionalArguments().isEmpty()) {
        dialog = parser.positionalArguments().at(0);
        keyFile = dialog.section(' ', -2).remove(':');

        // If the ssh-agent prompt starts with "Bad passphrase, try again for", then previously typed passphrase
        // or retrived passphrase from kwallet was wrong.
        // At least Debian's ssh-add has no i18n, so this should work for all languages as long as the string is unchanged.
        wrongPassphrase = parser.positionalArguments().at(0).startsWith(QLatin1String("Bad passphrase, try again for"));
    }

    // Open KWallet to see if a password was previously stored
    std::auto_ptr<KWallet::Wallet> wallet(KWallet::Wallet::openWallet(KWallet::Wallet::NetworkWallet(), 0));

    if ((!wrongPassphrase) && wallet.get() && wallet->hasFolder(walletFolder)) {
        wallet->setFolder(walletFolder);

        QString retrievedPass;
        wallet->readPassword(keyFile, retrievedPass);

        if (!retrievedPass.isEmpty()) {
            password = retrievedPass;
        }
    }

    // Password could not be retrieved from wallet. Open password dialog
    if (password.isEmpty()) {
        // create the password dialog, but only show "Enable Keep" button, if the wallet is open
        KPasswordDialog::KPasswordDialogFlag flag(KPasswordDialog::NoFlags);
        if (wallet.get()) {
            flag = KPasswordDialog::ShowKeepPassword;
        }
        QPointer<KPasswordDialog> kpd = new KPasswordDialog(0, flag);

        kpd->setPrompt(dialog);
        kpd->setWindowTitle(i18n("Ksshaskpass"));
        // We don't want to dump core when the password dialog is shown, because it could contain the entered password.
        // KPasswordDialog::disableCoreDumps() seems to be gone in KDE 4 -- do it manually
        struct rlimit rlim;
        rlim.rlim_cur = rlim.rlim_max = 0;
        setrlimit(RLIMIT_CORE, &rlim);

        if (kpd->exec() == QDialog::Accepted) {
            password = kpd->password();
            // If "Enable Keep" is enabled, open/create a folder in KWallet and store the password.
            if (wallet.get() && kpd->keepPassword()) {
                if (!wallet->hasFolder(walletFolder)) {
                    wallet->createFolder(walletFolder);
                }
                wallet->setFolder(walletFolder);
                wallet->writePassword(keyFile, password);
            }
        } else {
            // dialog has been canceled
            return 1;
        }
    }

    QTextStream out(stdout);
    out << password;
    return 0;
}

