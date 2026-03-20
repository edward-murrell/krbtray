#include "kerberos.h"

#include <string.h>
#include <time.h>

/* ── Internal helpers ────────────────────────────────────────────────────── */

/*
 * Return TRUE if `server` is a krbtgt/REALM@REALM principal.
 * Uses the string representation to avoid Heimdal internals.
 */
static gboolean is_tgt_principal(krb5_context ctx, krb5_principal server)
{
    char    *name = NULL;
    gboolean result = FALSE;

    if (krb5_unparse_name(ctx, server, &name) == 0) {
        result = g_str_has_prefix(name, "krbtgt/");
        free(name);
    }
    return result;
}

/*
 * Extract TGT info from ccache.  Returns NULL if no TGT is found.
 * The caller is responsible for freeing principal_name and the struct.
 */
static KrbCacheInfo *cache_info_from_ccache(krb5_context ctx,
                                             krb5_ccache  ccache)
{
    krb5_principal client = NULL;
    if (krb5_cc_get_principal(ctx, ccache, &client) != 0)
        return NULL;

    char *principal_name = NULL;
    if (krb5_unparse_name(ctx, client, &principal_name) != 0) {
        krb5_free_principal(ctx, client);
        return NULL;
    }
    krb5_free_principal(ctx, client);

    /* Iterate credentials looking for the TGT. */
    krb5_cc_cursor cursor;
    if (krb5_cc_start_seq_get(ctx, ccache, &cursor) != 0) {
        free(principal_name);
        return NULL;
    }

    KrbCacheInfo  *info = NULL;
    krb5_creds     creds;

    while (krb5_cc_next_cred(ctx, ccache, &cursor, &creds) == 0) {
        if (is_tgt_principal(ctx, creds.server)) {
            info = g_new0(KrbCacheInfo, 1);
            info->principal_name = g_strdup(principal_name);
            info->expiry         = (time_t)creds.times.endtime;
            info->renew_till     = (time_t)creds.times.renew_till;
            info->renewable      = (gboolean)creds.flags.b.renewable;
            krb5_free_cred_contents(ctx, &creds);
            break;
        }
        krb5_free_cred_contents(ctx, &creds);
    }
    krb5_cc_end_seq_get(ctx, ccache, &cursor);
    free(principal_name);
    return info;
}

/* ── Public API ──────────────────────────────────────────────────────────── */

/* Walk every ccache in the collection and return a list of KrbCacheInfo
 * for each one that contains a valid TGT. */
GList *krbtray_krb_scan_caches(krb5_context ctx)
{
    krb5_cccol_cursor col_cursor;
    if (krb5_cccol_cursor_new(ctx, &col_cursor) != 0)
        return NULL;

    GList      *result  = NULL;
    krb5_ccache ccache;

    while (krb5_cccol_cursor_next(ctx, col_cursor, &ccache) == 0
           && ccache != NULL) {
        KrbCacheInfo *info = cache_info_from_ccache(ctx, ccache);
        if (info)
            result = g_list_append(result, info);
        krb5_cc_close(ctx, ccache);
    }

    krb5_cccol_cursor_free(ctx, &col_cursor);
    return result;
}

/* Look up the ccache for a specific principal and return its TGT info.
 * Returns NULL if no matching cache exists. */
KrbCacheInfo *krbtray_krb_get_cache_info(krb5_context  ctx,
                                          const gchar  *principal_name)
{
    krb5_principal principal = NULL;
    if (krb5_parse_name(ctx, principal_name, &principal) != 0)
        return NULL;

    krb5_ccache ccache = NULL;
    krb5_error_code ret = krb5_cc_cache_match(ctx, principal, &ccache);
    krb5_free_principal(ctx, principal);

    if (ret != 0)
        return NULL;

    KrbCacheInfo *info = cache_info_from_ccache(ctx, ccache);
    krb5_cc_close(ctx, ccache);
    return info;
}

/* Classify a TGT into a display state based on how much time remains
 * relative to the renewal threshold. */
KrbState krbtray_krb_compute_state(time_t expiry,
                                   gint   renewal_threshold_mins)
{
    if (expiry == 0)
        return KRB_STATE_NO_TICKETS;

    time_t now       = time(NULL);
    time_t threshold = (time_t)(renewal_threshold_mins * 60);

    if (now >= expiry)
        return KRB_STATE_EXPIRED;
    if ((expiry - now) <= threshold)
        return KRB_STATE_EXPIRING;
    return KRB_STATE_VALID;
}

/* Renew the TGT for the named principal in-place, extending its lifetime
 * without requiring the user's password. */
krb5_error_code krbtray_krb_renew(krb5_context ctx, const gchar *principal_name)
{
    krb5_principal  principal = NULL;
    krb5_ccache     ccache    = NULL;
    krb5_creds      new_creds;
    krb5_error_code ret;

    memset(&new_creds, 0, sizeof(new_creds));

    ret = krb5_parse_name(ctx, principal_name, &principal);
    if (ret) return ret;

    ret = krb5_cc_cache_match(ctx, principal, &ccache);
    if (ret) goto out_principal;

    ret = krb5_get_renewed_creds(ctx, &new_creds, principal, ccache, NULL);
    if (ret) goto out_ccache;

    ret = krb5_cc_initialize(ctx, ccache, principal);
    if (ret) goto out_creds;

    ret = krb5_cc_store_cred(ctx, ccache, &new_creds);

out_creds:
    krb5_free_cred_contents(ctx, &new_creds);
out_ccache:
    krb5_cc_close(ctx, ccache);
out_principal:
    krb5_free_principal(ctx, principal);
    return ret;
}

/* Obtain a fresh TGT for the named principal using the supplied password,
 * requesting a 7-day renewable lifetime. */
krb5_error_code krbtray_krb_kinit(krb5_context  ctx,
                                   const gchar  *principal_name,
                                   const gchar  *password)
{
    krb5_principal             principal = NULL;
    krb5_ccache                ccache    = NULL;
    krb5_creds                 creds;
    krb5_get_init_creds_opt   *opt       = NULL;
    krb5_error_code            ret;

    memset(&creds, 0, sizeof(creds));

    ret = krb5_parse_name(ctx, principal_name, &principal);
    if (ret) return ret;

    ret = krb5_get_init_creds_opt_alloc(ctx, &opt);
    if (ret) goto out_principal;

    /* Request renewable tickets with a 7-day maximum lifetime. */
    krb5_get_init_creds_opt_set_renew_life(opt, 7 * 24 * 3600);

    ret = krb5_get_init_creds_password(ctx, &creds, principal,
                                       (char *)password,
                                       NULL, NULL, 0, NULL, opt);
    if (ret) goto out_opt;

    /* Find or create the ccache for this principal. */
    if (krb5_cc_cache_match(ctx, principal, &ccache) != 0) {
        ret = krb5_cc_default(ctx, &ccache);
        if (ret) goto out_creds;
    }

    ret = krb5_cc_initialize(ctx, ccache, principal);
    if (ret) goto out_ccache;

    ret = krb5_cc_store_cred(ctx, ccache, &creds);

out_ccache:
    krb5_cc_close(ctx, ccache);
out_creds:
    krb5_free_cred_contents(ctx, &creds);
out_opt:
    krb5_get_init_creds_opt_free(ctx, opt);
out_principal:
    krb5_free_principal(ctx, principal);
    return ret;
}

/* Destroy the credential cache for the named principal, invalidating all
 * its tickets immediately. */
krb5_error_code krbtray_krb_destroy(krb5_context ctx, const gchar *principal_name)
{
    krb5_principal  principal = NULL;
    krb5_ccache     ccache    = NULL;
    krb5_error_code ret;

    ret = krb5_parse_name(ctx, principal_name, &principal);
    if (ret) return ret;

    ret = krb5_cc_cache_match(ctx, principal, &ccache);
    krb5_free_principal(ctx, principal);
    if (ret) return ret;

    ret = krb5_cc_destroy(ctx, ccache);
    /* krb5_cc_destroy closes the ccache even on failure. */
    return ret;
}

/* Change the Kerberos password for the named principal.  Acquires a
 * short-lived credential for the kadmin/changepw service, then submits
 * the new password via the RFC 3244 password-change protocol. */
krb5_error_code krbtray_krb_change_password(krb5_context  ctx,
                                             const gchar  *principal_name,
                                             const gchar  *old_password,
                                             const gchar  *new_password)
{
    krb5_principal           principal = NULL;
    krb5_creds               creds;
    krb5_get_init_creds_opt *opt       = NULL;
    krb5_error_code          ret;
    int                      result_code = 0;
    krb5_data                result_code_string, result_string;

    memset(&creds, 0, sizeof(creds));
    krb5_data_zero(&result_code_string);
    krb5_data_zero(&result_string);

    ret = krb5_parse_name(ctx, principal_name, &principal);
    if (ret) return ret;

    ret = krb5_get_init_creds_opt_alloc(ctx, &opt);
    if (ret) goto out_principal;

    /* Obtain credentials specifically for the password-change service. */
    ret = krb5_get_init_creds_password(ctx, &creds, principal,
                                       (char *)old_password,
                                       NULL, NULL, 0,
                                       "kadmin/changepw",
                                       opt);
    if (ret) goto out_opt;

    ret = krb5_change_password(ctx, &creds, (char *)new_password,
                               &result_code,
                               &result_code_string,
                               &result_string);

    /* A zero return but non-zero result_code means the KDC rejected the
     * new password (e.g. quality policy).  Surface the reason string. */
    if (ret == 0 && result_code != 0) {
        if (result_string.length > 0) {
            krb5_set_error_message(ctx, KRB5KDC_ERR_POLICY,
                                   "%.*s",
                                   (int)result_string.length,
                                   (char *)result_string.data);
        } else {
            krb5_set_error_message(ctx, KRB5KDC_ERR_POLICY,
                                   "Password change rejected by server "
                                   "(code %d)", result_code);
        }
        ret = KRB5KDC_ERR_POLICY;
    }

    krb5_data_free(&result_code_string);
    krb5_data_free(&result_string);
    krb5_free_cred_contents(ctx, &creds);
out_opt:
    krb5_get_init_creds_opt_free(ctx, opt);
out_principal:
    krb5_free_principal(ctx, principal);
    return ret;
}

/* Return a human-readable string for how long until the TGT expires,
 * e.g. "3h 42m", "expired", or "no tickets". Caller must g_free(). */
gchar *krbtray_krb_time_remaining(time_t expiry)
{
    if (expiry == 0)
        return g_strdup("no tickets");

    time_t now  = time(NULL);
    time_t diff = expiry - now;

    if (diff <= 0)
        return g_strdup("expired");

    gint hours = (gint)(diff / 3600);
    gint mins  = (gint)((diff % 3600) / 60);

    if (hours > 0)
        return g_strdup_printf("%dh %dm", hours, mins);
    return g_strdup_printf("%dm", mins);
}
