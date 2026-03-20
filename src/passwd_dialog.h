#pragma once

#include "app.h"

/*
 * Show the Change Password dialog for principal_name (always pre-filled).
 *
 * On success: updates the keyring if the principal has store_password set,
 * re-authenticates to obtain a fresh TGT with the new password, and calls
 * krbtray_app_refresh().
 *
 * Returns TRUE on success, FALSE on cancel or failure.
 *
 * If must_change is TRUE a notice is shown explaining that the password
 * must be changed before the account can be used.
 */
gboolean krbtray_passwd_dialog_run (KrbTrayApp  *app,
                                    const gchar *principal_name,
                                    gboolean     must_change);
