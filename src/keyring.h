#pragma once

#include <glib.h>

/*
 * Store, retrieve, and delete a Kerberos password in the system Secret Service
 * (GNOME Keyring / KWallet via libsecret).
 *
 * All functions are synchronous; call from the main thread only.
 * Returned passwords must be freed with g_free().
 */

gboolean krbtray_keyring_store_password  (const gchar *principal_name,
                                          const gchar *password);

gchar   *krbtray_keyring_lookup_password (const gchar *principal_name);

gboolean krbtray_keyring_delete_password (const gchar *principal_name);
