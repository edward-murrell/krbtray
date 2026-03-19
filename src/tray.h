#pragma once

#include "app.h"

/* Create and wire up the GtkStatusIcon. */
void krbtray_tray_create (KrbTrayApp *app);

/* Update icon image and tooltip to reflect current state. */
void krbtray_tray_update (KrbTrayApp *app);
