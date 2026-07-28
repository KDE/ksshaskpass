/*
 *   SPDX-FileCopyrightText: 2006 Hans van Leeuwen <hanz@hanz.nl>
 *   SPDX-FileCopyrightText: 2008-2010 Armin Berres <armin@space-based.de>
 *   SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <memory>
#include <sys/resource.h>

#include <KAboutData>
#include <KLocalizedString>
#include <KMessageBox>
#include <KPasswordDialog>

#include <QApplication>
#include <QCommandLineParser>
#include <QInputDialog>
#include <QPointer>
#include <QRegularExpression>
#include <QStyle>
#include <QStyleOption>
#include <QTextStream>

#include <qt6keychain/keychain.h>

#include "debug.h"
#include "prompt.h"
#include "ui_cleartextinputdialog.h"

constexpr const char *PROMPT_TYPE_ENV_VAR = "SSH_ASKPASS_PROMPT";

static void execQKeychainJobBlocking(QKeychain::Job &job)
{
    QEventLoop loop;
    job.connect(&job, &QKeychain::Job::finished, &loop, &QEventLoop::quit);
    job.setAutoDelete(false);  // Prevent job from auto-freeing its data after the `Job::finished` signal
    job.start();
    loop.exec();

    if (job.error() != QKeychain::NoError && job.error() != QKeychain::EntryNotFound)
    {
        qCWarning(LOG_KSSHASKPASS) << "QtKeychain returned unexpected error: " << job.errorString();
    }
}

void cancelDialog(QWidget *parent, const QString &text)
{
    QDialog *d = new QDialog(parent);
    d->setObjectName(QStringLiteral("information"));

    QDialogButtonBox *buttonBox = new QDialogButtonBox(d);
    buttonBox->setStandardButtons(QDialogButtonBox::Cancel);

    KMessageBox::createKMessageBox(d, buttonBox, QMessageBox::Information, text, QStringList(), QString(), nullptr, KMessageBox::Notify);
}

int main(int argc, char **argv)
{
    QApplication app(argc, argv);
    KLocalizedString::setApplicationDomain(QByteArrayLiteral("ksshaskpass"));

    // TODO update it.
    KAboutData about(QStringLiteral("ksshaskpass"),
                     i18n("SSH Credentials"),
                     QStringLiteral(PROJECT_VERSION),
                     i18n("KDE version of ssh-askpass"),
                     KAboutLicense::GPL,
                     i18n("(c) 2006 Hans van Leeuwen\n(c) 2008-2010 Armin Berres\n(c) 2013 Pali Rohár"),
                     i18n("Ksshaskpass allows you to interactively prompt users for a passphrase for ssh-add"),
                     QStringLiteral("https://commits.kde.org/ksshaskpass"),
                     QStringLiteral("armin@space-based.de"));

    about.addAuthor(i18n("Armin Berres"), i18n("Current author"), QStringLiteral("armin@space-based.de"));
    about.addAuthor(i18n("Hans van Leeuwen"), i18n("Original author"), QStringLiteral("hanz@hanz.nl"));
    about.addAuthor(i18n("Pali Rohár"), i18n("Contributor"), QStringLiteral("pali.rohar@gmail.com"));
    KAboutData::setApplicationData(about);

    QCommandLineParser parser;
    about.setupCommandLine(&parser);
    parser.addOption(QCommandLineOption(QStringList() << QStringLiteral("+[prompt]"), i18nc("Name of a prompt for a password", "Prompt")));

    parser.process(app);
    about.processCommandLine(&parser);

    const QString promptTypeString = qEnvironmentVariable(PROMPT_TYPE_ENV_VAR);
    PromptType promptType = PromptType::Entry;
    if (promptTypeString == QLatin1String("confirm")) {
        promptType = PromptType::Confirm;
    } else if (promptTypeString == QLatin1String("none")) {
        promptType = PromptType::None;
    }

    QString dialog = i18n("Please enter passphrase"); // Default dialog text.
    QString identifier;
    QString item;
    bool ignoreKeychain = false;
    DisplayType displayType = DisplayType::Password;

    // Parse commandline arguments
    if (!parser.positionalArguments().isEmpty()) {
        dialog = parser.positionalArguments().at(0);
        parsePrompt(promptType, dialog, identifier, ignoreKeychain, displayType);
    }

    if ((!ignoreKeychain) && (!identifier.isNull())) {
        QKeychain::ReadPasswordJob job(app.applicationName());
        job.setKey(identifier);
        execQKeychainJobBlocking(job);

        item = job.textData();
        if (job.error() != QKeychain::NoError) {
            // There was a bug in previous versions of ksshaskpass that caused it to create keys with single quotes
            // around the identifier and even older versions have an extra space appended to the identifier.
            // key file name. Try these keys too, and, if there's a match, ensure that it's properly
            // replaced with proper one.
            for (auto templ : QStringList{QStringLiteral("'%0'"), QStringLiteral("%0 "), QStringLiteral("'%0' ")}) {
                const QString keyFile = templ.arg(identifier);

                QKeychain::ReadPasswordJob job(app.applicationName());
                job.setKey(keyFile);
                execQKeychainJobBlocking(job);

                item = job.textData();
                if (job.error() == QKeychain::NoError) {
                    qCWarning(LOG_KSSHASKPASS) << "Detected legacy key for " << identifier << ", enabling workaround";

                    // Emulate rename using write-then-delete, since QKeychain doens’t support native renames
                    QKeychain::WritePasswordJob jobWrite(app.applicationName());
                    jobWrite.setKey(identifier);
                    jobWrite.setTextData(item);
                    execQKeychainJobBlocking(jobWrite);

                    QKeychain::DeletePasswordJob jobDelete(app.applicationName());
                    jobDelete.setKey(keyFile);
                    execQKeychainJobBlocking(jobDelete);

                    break;
                }
            }
        }
    }

    if (!item.isEmpty()) {
        QTextStream(stdout) << item;
        return 0;
    }

    std::optional<bool> remember;

    // Item could not be retrieved from keychain. Open dialog
    switch (displayType) {
    case DisplayType::ConfirmCancel: {
        cancelDialog(nullptr, dialog);
        // dialog can only be canceled
        return 1;
    }
    case DisplayType::Confirm: {
        if (KMessageBox::questionTwoActions(nullptr,
                                            dialog,
                                            QString(),
                                            KGuiItem(i18nc("@action:button", "Accept"), QStringLiteral("dialog-ok")),
                                            KStandardGuiItem::cancel())
            != KMessageBox::PrimaryAction) {
            // dialog has been canceled
            return 1;
        }
        item = QStringLiteral("yes\n");
        break;
    }
    case DisplayType::UnknownSshHost: {
        auto cancelButton = KStandardGuiItem::cancel();
        cancelButton.setText("No");

        // update dialog for readability purposes
        dialog.remove("(yes/no/[fingerprint])");
        dialog.replace("Are you sure", "\nAre you sure");

        if (KMessageBox::questionTwoActions(nullptr,
                                            dialog,
                                            i18nc("@title:window", "Unknown SSH Host Key"),
                                            KGuiItem(i18nc("@action:button", "Yes"), QStringLiteral("dialog-ok")),
                                            cancelButton)
            != KMessageBox::PrimaryAction) {
            // dialog has been canceled
            return 1;
        }
        item = QStringLiteral("yes\n");
        break;
    }
    case DisplayType::Unknown: // just in case.
    case DisplayType::ClearText:
    case DisplayType::Password: {
        // custom dialog inspired by KPasswordDialog, including "Remember" option,
        // but has the ability to show the password.
        QDialog dlg;

        Ui_ClearTextInputDialog ui;
        ui.setupUi(&dlg);

        ui.prompt->setText(dialog);
        ui.keepCheckBox->setVisible(!identifier.isEmpty() && QKeychain::isAvailable());

        QStyleOption option;
        option.initFrom(&dlg);
        const int iconSize = dlg.style()->pixelMetric(QStyle::PM_MessageBoxIconSize, &option, &dlg);
        ui.pixmapLabel->setPixmap(QIcon::fromTheme(QIcon::ThemeIcon::DialogPassword).pixmap(iconSize));

        if (displayType == DisplayType::Password) {
            ui.keepCheckBox->setText(i18nc("@option:check", "Remember password"));

            // We don't want to dump core when the password dialog is shown, because it could contain the entered password.
            // KPasswordDialog::disableCoreDumps() seems to be gone in KDE 4 -- do it manually
            struct rlimit rlim;
            rlim.rlim_cur = rlim.rlim_max = 0;
            setrlimit(RLIMIT_CORE, &rlim);
        } else {
            ui.lineEdit->setEchoMode(QLineEdit::Normal);
            ui.lineEdit->setRevealPasswordMode(KPassword::RevealMode::Never);
            ui.passwordLabel->hide();
        }

        if (dlg.exec() == QDialog::Accepted) {
            item = ui.lineEdit->password();
            remember = ui.keepCheckBox->isChecked();
        } else {
            // dialog has been canceled
            return 1;
        }
        break;
    }
    }

    if (!identifier.isEmpty() && remember.has_value()) {
        if (remember.value()) {
            QKeychain::WritePasswordJob job(app.applicationName());
            job.setKey(identifier);
            job.setTextData(item);
            execQKeychainJobBlocking(job);
        } else {
            QKeychain::DeletePasswordJob job(app.applicationName());
            job.setKey(identifier);
            execQKeychainJobBlocking(job);
        }
    }

    QTextStream out(stdout);
    out << item << "\n";
    return 0;
}
