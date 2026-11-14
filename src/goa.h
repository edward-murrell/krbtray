#pragma once

#include "app.h"

/*
 * GNOME Online Accounts (GOA) creates a Kerberos account for every principal
 * it sees in the default cache.  When another principal becomes the default,
 * GOA can no longer see the old one's tickets and shows "Failed to sign in".
 * krbtray turns off GOA ticketing for the principals it looks after, so GOA
 * leaves them alone.  Nothing happens if GOA is not running.
 */

/* Start watching GOA's accounts on the session bus. */
void krbtray_goa_init   (KrbTrayApp *app);

/* Turn off GOA ticketing for every principal krbtray currently tracks. */
void krbtray_goa_sync   (KrbTrayApp *app);

/* Stop watching and release resources. */
void krbtray_goa_uninit (KrbTrayApp *app);
