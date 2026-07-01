/*
 *   SPDX-FileCopyrightText: 2006 Hans van Leeuwen <hanz@hanz.nl>
 *   SPDX-FileCopyrightText: 2008-2010 Armin Berres <armin@space-based.de>
 *   SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

class QString;

// Standard prompt types defined by openssh.
enum class PromptType {
    Confirm,
    Entry,
    None,
};

// Implemented UI display types.
enum class DisplayType {
    Unknown,
    Password,
    ClearText,
    Confirm,
    ConfirmCancel,
    UnknownSshHost
};

void parsePrompt(PromptType promptType, const QString &prompt, QString &identifier, bool &ignoreKeychain, DisplayType &displayType);
