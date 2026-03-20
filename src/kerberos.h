#pragma once

#include <krb5.h>
#include <glib.h>
#include <time.h>

#include "app.h"   /* for KrbState */

/*
 * Summary of one TGT found in a credential cache.
 * Caller is responsible for freeing principal_name with g_free().
 */
typedef struct {
    gchar   *principal_name; /* client principal, e.g. "alice@EXAMPLE.COM" */
    time_t   expiry;         /* TGT endtime (Unix timestamp)                */
    time_t   renew_till;     /* max renewable lifetime (Unix timestamp)     */
    gboolean renewable;
} KrbCacheInfo;

/*
 * Scan all ccaches in the credential cache collection.
 * Returns a GList of KrbCacheInfo * (caller frees contents and list).
 *
 * NOTE: For multi-principal support the KCM or DIR ccache type is recommended
 * (set KRB5CCNAME=KCM: or use the KCM daemon).  With a plain FILE: cache only
 * the default cache is usually visible.
 */
GList      *krbtray_krb_scan_caches  (krb5_context ctx);

/*
 * Look up the KrbCacheInfo for a single principal (NULL if not found).
 * Caller frees the returned pointer and its principal_name with g_free().
 */
KrbCacheInfo *krbtray_krb_get_cache_info (krb5_context  ctx,
                                          const gchar  *principal_name);

/*
 * Compute the display state for a TGT given its expiry and the renewal
 * threshold in minutes.
 */
KrbState krbtray_krb_compute_state (time_t expiry,
                                    gint   renewal_threshold_mins);

/* Renew the TGT for principal_name in-place. */
krb5_error_code krbtray_krb_renew  (krb5_context  ctx,
                                    const gchar  *principal_name);

/* Obtain a new TGT using a password (kinit). */
krb5_error_code krbtray_krb_kinit  (krb5_context  ctx,
                                    const gchar  *principal_name,
                                    const gchar  *password);

/* Destroy all tickets for principal_name. */
krb5_error_code krbtray_krb_destroy (krb5_context  ctx,
                                     const gchar  *principal_name);

/* Change the Kerberos password for principal_name.
 * Authenticates with old_password, then sets new_password via the kadmin
 * password-change protocol.  On protocol-level rejection the server's
 * reason is surfaced through krb5_get_error_message(). */
krb5_error_code krbtray_krb_change_password (krb5_context  ctx,
                                              const gchar  *principal_name,
                                              const gchar  *old_password,
                                              const gchar  *new_password);

/* Human-readable time-remaining string, e.g. "3h 42m".  Caller frees. */
gchar *krbtray_krb_time_remaining (time_t expiry);
