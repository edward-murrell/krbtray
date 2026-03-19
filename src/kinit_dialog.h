#pragma once

#include "app.h"

/*
 * Show the "Authenticate" dialog for principal_name (pre-filled).
 * If principal_name is NULL the principal field is left editable.
 *
 * On success (user clicked Authenticate and kinit succeeded) returns TRUE
 * and calls krbtray_app_refresh() to update the tray.
 * On cancel or failure returns FALSE.
 */
gboolean krbtray_kinit_dialog_run (KrbTrayApp  *app,
                                   const gchar *principal_name);
