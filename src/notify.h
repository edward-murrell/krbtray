#pragma once

#include <glib.h>

void krbtray_notify_init   (void);
void krbtray_notify_uninit (void);

/* Show a critical desktop notification when automatic renewal fails. */
void krbtray_notify_renewal_failed (const gchar *principal_name,
                                    const gchar *error_message);
