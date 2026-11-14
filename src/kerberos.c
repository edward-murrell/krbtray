#include "kerberos.h"

#include <string.h>
#include <time.h>
#include <errno.h>
#include <glib/gi18n.h>

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
#ifdef KRBTRAY_MIT
            info->renewable      =
                (creds.ticket_flags & TKT_FLG_RENEWABLE) != 0;
#else
            info->renewable      = (gboolean)creds.flags.b.renewable;
#endif
            krb5_free_cred_contents(ctx, &creds);
            break;
        }
        krb5_free_cred_contents(ctx, &creds);
    }
    krb5_cc_end_seq_get(ctx, ccache, &cursor);
    free(principal_name);
    return info;
}

#ifdef KRBTRAY_MIT
/* Choose a ccache for a principal that has none yet.  On collection types
 * (KCM:, KEYRING:, DIR: — Fedora and RHEL default to KCM: via sssd-kcm) the
 * default cache is the collection's primary one, which may already belong to
 * another principal; MIT's kinit creates a fresh cache in the collection in
 * that case rather than overwriting it, and so do we. */
static krb5_error_code mit_new_ccache(krb5_context ctx, krb5_ccache *out)
{
    krb5_ccache     def = NULL;
    krb5_principal  existing = NULL;
    krb5_error_code ret;

    ret = krb5_cc_default(ctx, &def);
    if (ret) return ret;

    /* An empty primary cache, or a type with only one cache, is used as is. */
    if (!krb5_cc_support_switch(ctx, krb5_cc_get_type(ctx, def)) ||
        krb5_cc_get_principal(ctx, def, &existing) != 0) {
        *out = def;
        return 0;
    }
    krb5_free_principal(ctx, existing);

    ret = krb5_cc_new_unique(ctx, krb5_cc_get_type(ctx, def), NULL, out);
    krb5_cc_close(ctx, def);
    return ret;
}
#endif

/* ── Per-principal cache store ───────────────────────────────────────────── */

/* Free a KrbCacheInfo and its contents.  Accepts NULL. */
static void cache_info_free(KrbCacheInfo *info)
{
    if (!info) return;
    g_free(info->principal_name);
    g_free(info);
}

/* TRUE when the default cache can hold only one principal, so krbtray must
 * keep its own cache per principal to let several stay signed in at once.
 * Heimdal's DIR: collection is treated as a single cache because listing
 * or switching it is broken in Heimdal 7. */
static gboolean store_mode(krb5_context ctx)
{
    krb5_ccache def = NULL;
    if (krb5_cc_default(ctx, &def) != 0)
        return TRUE;

    const char *type   = krb5_cc_get_type(ctx, def);
    gboolean    single = !krb5_cc_support_switch(ctx, type);
#ifdef KRBTRAY_HEIMDAL
    if (g_strcmp0(type, "DIR") == 0)
        single = TRUE;
#endif
    krb5_cc_close(ctx, def);
    return single;
}

/* Directory holding the per-principal caches.  The user runtime directory
 * is private to the user and cleared at logout.  Caller frees. */
static gchar *store_dir(void)
{
    gchar *dir = g_build_filename(g_get_user_runtime_dir(), "krbtray", NULL);
    g_mkdir_with_parents(dir, 0700);
    return dir;
}

/* Open the store cache for principal_name.  The file need not exist yet.
 * Characters that are unsafe in a file name are replaced. */
static krb5_error_code store_resolve(krb5_context  ctx,
                                     const gchar  *principal_name,
                                     krb5_ccache  *out)
{
    GString *file = g_string_new("krb5cc_");
    for (const gchar *p = principal_name; *p; p++) {
        if (g_ascii_isalnum(*p) || strchr("._@-", *p))
            g_string_append_c(file, *p);
        else if (*p == '/')
            g_string_append_c(file, '+');
        else
            g_string_append_c(file, '_');
    }

    gchar *dir  = store_dir();
    gchar *name = g_strdup_printf("FILE:%s/%s", dir, file->str);
    krb5_error_code ret = krb5_cc_resolve(ctx, name, out);

    g_free(name);
    g_free(dir);
    g_string_free(file, TRUE);
    return ret;
}

/* Replace the contents of `to` with everything in `from`. */
static krb5_error_code copy_cache(krb5_context ctx,
                                  krb5_ccache  from,
                                  krb5_ccache  to)
{
    krb5_principal  principal = NULL;
    krb5_cc_cursor  cursor;
    krb5_creds      creds;
    krb5_error_code ret;

    ret = krb5_cc_get_principal(ctx, from, &principal);
    if (ret) return ret;
    ret = krb5_cc_initialize(ctx, to, principal);
    krb5_free_principal(ctx, principal);
    if (ret) return ret;

    ret = krb5_cc_start_seq_get(ctx, from, &cursor);
    if (ret) return ret;
    while ((ret = krb5_cc_next_cred(ctx, from, &cursor, &creds)) == 0) {
        ret = krb5_cc_store_cred(ctx, to, &creds);
        krb5_free_cred_contents(ctx, &creds);
        if (ret) break;
    }
    krb5_cc_end_seq_get(ctx, from, &cursor);
    return ret == KRB5_CC_END ? 0 : ret;
}

/* Principal held in the default cache, or NULL if it is empty.
 * Caller frees with g_free(). */
static gchar *default_principal_name(krb5_context ctx)
{
    krb5_ccache    def       = NULL;
    krb5_principal principal = NULL;
    char          *name      = NULL;
    gchar         *result    = NULL;

    if (krb5_cc_default(ctx, &def) != 0)
        return NULL;
    if (krb5_cc_get_principal(ctx, def, &principal) == 0) {
        if (krb5_unparse_name(ctx, principal, &name) == 0) {
            result = g_strdup(name);
            free(name);
        }
        krb5_free_principal(ctx, principal);
    }
    krb5_cc_close(ctx, def);
    return result;
}

/* Bring the default cache and the default principal's store cache in line,
 * copying whichever holds the later TGT over the other.  This picks up a
 * kinit run from a terminal and pushes renewals made in the store out to
 * the default cache. */
static void store_sync(krb5_context ctx)
{
    krb5_ccache def = NULL, st = NULL;
    if (krb5_cc_default(ctx, &def) != 0)
        return;

    KrbCacheInfo *di = cache_info_from_ccache(ctx, def);
    if (di && store_resolve(ctx, di->principal_name, &st) == 0) {
        KrbCacheInfo *si = cache_info_from_ccache(ctx, st);
        if (!si || di->expiry > si->expiry)
            copy_cache(ctx, def, st);
        else if (si->expiry > di->expiry)
            copy_cache(ctx, st, def);
        cache_info_free(si);
        krb5_cc_close(ctx, st);
    }
    cache_info_free(di);
    krb5_cc_close(ctx, def);
}

/* Find the cache holding tickets for principal: its store cache in store
 * mode, otherwise the matching cache in the collection. */
static krb5_error_code find_ccache(krb5_context   ctx,
                                   krb5_principal principal,
                                   krb5_ccache   *out)
{
    if (!store_mode(ctx))
        return krb5_cc_cache_match(ctx, principal, out);

    char *name = NULL;
    krb5_error_code ret = krb5_unparse_name(ctx, principal, &name);
    if (ret) return ret;

    store_sync(ctx);
    ret = store_resolve(ctx, name, out);
    free(name);
    if (ret) return ret;

    /* An empty or missing store file means no tickets. */
    krb5_principal held = NULL;
    if (krb5_cc_get_principal(ctx, *out, &held) != 0) {
        krb5_cc_close(ctx, *out);
        *out = NULL;
        return KRB5_CC_NOTFOUND;
    }
    krb5_free_principal(ctx, held);
    return 0;
}

/* Compare two KrbCacheInfo by principal name, for a stable menu order. */
static gint cache_info_cmp(gconstpointer a, gconstpointer b)
{
    return g_strcmp0(((const KrbCacheInfo *)a)->principal_name,
                     ((const KrbCacheInfo *)b)->principal_name);
}

/* List every principal in the store, marking the default one.  The default
 * cache is included directly if its store copy could not be written. */
static GList *store_scan(krb5_context ctx)
{
    store_sync(ctx);

    gchar   *def_name = default_principal_name(ctx);
    gboolean def_seen = FALSE;
    GList   *result   = NULL;
    gchar   *dir      = store_dir();
    GDir    *d        = g_dir_open(dir, 0, NULL);

    const gchar *file;
    while (d && (file = g_dir_read_name(d)) != NULL) {
        if (!g_str_has_prefix(file, "krb5cc_"))
            continue;
        gchar *name = g_strdup_printf("FILE:%s/%s", dir, file);
        krb5_ccache cc = NULL;
        if (krb5_cc_resolve(ctx, name, &cc) == 0) {
            KrbCacheInfo *info = cache_info_from_ccache(ctx, cc);
            if (info) {
                info->is_default =
                    g_strcmp0(info->principal_name, def_name) == 0;
                def_seen |= info->is_default;
                result = g_list_insert_sorted(result, info, cache_info_cmp);
            }
            krb5_cc_close(ctx, cc);
        }
        g_free(name);
    }
    if (d) g_dir_close(d);
    g_free(dir);

    if (def_name && !def_seen) {
        krb5_ccache def = NULL;
        if (krb5_cc_default(ctx, &def) == 0) {
            KrbCacheInfo *info = cache_info_from_ccache(ctx, def);
            if (info) {
                info->is_default = TRUE;
                result = g_list_insert_sorted(result, info, cache_info_cmp);
            }
            krb5_cc_close(ctx, def);
        }
    }
    g_free(def_name);
    return result;
}

/* ── Public API ──────────────────────────────────────────────────────────── */

/* Return a KrbCacheInfo for every principal that holds a TGT, from the
 * per-principal store or the native collection, with the default marked. */
GList *krbtray_krb_scan_caches(krb5_context ctx)
{
    if (store_mode(ctx))
        return store_scan(ctx);

    krb5_cccol_cursor col_cursor;
    if (krb5_cccol_cursor_new(ctx, &col_cursor) != 0)
        return NULL;

    gchar      *def_name = default_principal_name(ctx);
    GList      *result   = NULL;
    krb5_ccache ccache;

    while (krb5_cccol_cursor_next(ctx, col_cursor, &ccache) == 0
           && ccache != NULL) {
        KrbCacheInfo *info = cache_info_from_ccache(ctx, ccache);
        if (info) {
            info->is_default = g_strcmp0(info->principal_name, def_name) == 0;
            result = g_list_append(result, info);
        }
        krb5_cc_close(ctx, ccache);
    }

    krb5_cccol_cursor_free(ctx, &col_cursor);
    g_free(def_name);
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
    krb5_error_code ret = find_ccache(ctx, principal, &ccache);
    krb5_free_principal(ctx, principal);

    if (ret != 0)
        return NULL;

    KrbCacheInfo *info = cache_info_from_ccache(ctx, ccache);
    krb5_cc_close(ctx, ccache);
    if (info) {
        gchar *def_name = default_principal_name(ctx);
        info->is_default = g_strcmp0(info->principal_name, def_name) == 0;
        g_free(def_name);
    }
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

/* Renew the TGT for the named principal in place, extending its lifetime
 * without requiring the user's password.  A renewed default principal is
 * copied to the default cache too. */
krb5_error_code krbtray_krb_renew(krb5_context ctx, const gchar *principal_name)
{
    krb5_principal  principal = NULL;
    krb5_ccache     ccache    = NULL;
    krb5_creds      new_creds;
    krb5_error_code ret;

    memset(&new_creds, 0, sizeof(new_creds));

    ret = krb5_parse_name(ctx, principal_name, &principal);
    if (ret) return ret;

    ret = find_ccache(ctx, principal, &ccache);
    if (ret) goto out_principal;

    ret = krb5_get_renewed_creds(ctx, &new_creds, principal, ccache, NULL);
    if (ret) goto out_ccache;

    ret = krb5_cc_initialize(ctx, ccache, principal);
    if (ret) goto out_creds;

    ret = krb5_cc_store_cred(ctx, ccache, &new_creds);
    if (ret == 0 && store_mode(ctx))
        store_sync(ctx);

out_creds:
    krb5_free_cred_contents(ctx, &new_creds);
out_ccache:
    krb5_cc_close(ctx, ccache);
out_principal:
    krb5_free_principal(ctx, principal);
    return ret;
}

/* Obtain a fresh TGT for the named principal using the supplied password,
 * requesting a 7-day renewable lifetime.  In store mode the principal also
 * becomes the default if the default cache is empty, expired or already
 * holds it; another signed-in principal stays the default. */
krb5_error_code krbtray_krb_kinit(krb5_context  ctx,
                                   const gchar  *principal_name,
                                   const gchar  *password)
{
    krb5_principal             principal = NULL;
    krb5_ccache                ccache    = NULL;
    krb5_creds                 creds;
    krb5_get_init_creds_opt   *opt       = NULL;
    char                      *full_name = NULL; /* with realm, as stored */
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

    gboolean use_store = store_mode(ctx);

    /* Find or create the ccache for this principal. */
    if (use_store) {
        /* Save the current default principal to its store cache first, so
         * replacing the default cache below cannot lose its tickets. */
        store_sync(ctx);
        ret = krb5_unparse_name(ctx, principal, &full_name);
        if (ret) goto out_creds;
        ret = store_resolve(ctx, full_name, &ccache);
        if (ret) goto out_creds;
    } else if (krb5_cc_cache_match(ctx, principal, &ccache) != 0) {
#ifdef KRBTRAY_MIT
        ret = mit_new_ccache(ctx, &ccache);
#else
        ret = krb5_cc_default(ctx, &ccache);
#endif
        if (ret) goto out_creds;
    }

    ret = krb5_cc_initialize(ctx, ccache, principal);
    if (ret) goto out_ccache;

    ret = krb5_cc_store_cred(ctx, ccache, &creds);

    if (ret == 0 && use_store) {
        krb5_ccache def = NULL;
        if (krb5_cc_default(ctx, &def) == 0) {
            KrbCacheInfo *di = cache_info_from_ccache(ctx, def);
            if (!di || di->expiry <= time(NULL) ||
                g_strcmp0(di->principal_name, full_name) == 0)
                copy_cache(ctx, ccache, def);
            cache_info_free(di);
            krb5_cc_close(ctx, def);
        }
    }

out_ccache:
    krb5_cc_close(ctx, ccache);
out_creds:
    free(full_name);
    krb5_free_cred_contents(ctx, &creds);
out_opt:
    krb5_get_init_creds_opt_free(ctx, opt);
out_principal:
    krb5_free_principal(ctx, principal);
    return ret;
}

/* Destroy the credential cache for the named principal, invalidating all
 * its tickets immediately.  In store mode the default cache is destroyed
 * too if it holds the same principal. */
krb5_error_code krbtray_krb_destroy(krb5_context ctx, const gchar *principal_name)
{
    krb5_principal  principal = NULL;
    krb5_ccache     ccache    = NULL;
    krb5_error_code ret;

    ret = krb5_parse_name(ctx, principal_name, &principal);
    if (ret) return ret;

    ret = find_ccache(ctx, principal, &ccache);
    krb5_free_principal(ctx, principal);
    if (ret) return ret;

    ret = krb5_cc_destroy(ctx, ccache);
    /* krb5_cc_destroy closes the ccache even on failure. */

    if (store_mode(ctx)) {
        gchar *def_name = default_principal_name(ctx);
        krb5_ccache def = NULL;
        if (g_strcmp0(def_name, principal_name) == 0 &&
            krb5_cc_default(ctx, &def) == 0)
            krb5_cc_destroy(ctx, def);
        g_free(def_name);
    }
    return ret;
}

/* Make the named principal the one programs see in the default cache: copy
 * its store cache over the default cache, or switch the collection's
 * primary cache on collection types. */
krb5_error_code krbtray_krb_make_default(krb5_context  ctx,
                                         const gchar  *principal_name)
{
    krb5_principal  principal = NULL;
    krb5_ccache     ccache    = NULL;
    krb5_error_code ret;

    ret = krb5_parse_name(ctx, principal_name, &principal);
    if (ret) return ret;

    /* In store mode this also saves the current default principal's
     * tickets to its store cache before they are overwritten. */
    ret = find_ccache(ctx, principal, &ccache);
    krb5_free_principal(ctx, principal);
    if (ret) return ret;

    if (store_mode(ctx)) {
        krb5_ccache def = NULL;
        ret = krb5_cc_default(ctx, &def);
        if (ret == 0) {
            ret = copy_cache(ctx, ccache, def);
            krb5_cc_close(ctx, def);
        }
    } else {
        ret = krb5_cc_switch(ctx, ccache);
    }
    krb5_cc_close(ctx, ccache);
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
    memset(&result_code_string, 0, sizeof(result_code_string));
    memset(&result_string, 0, sizeof(result_string));

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
#ifdef KRBTRAY_MIT
        /* MIT can decode the server's reply, including Active Directory's
         * binary password-policy blob, into a readable sentence. */
        char *reason = NULL;
        if (krb5_chpw_message(ctx, &result_string, &reason) == 0 && reason) {
            krb5_set_error_message(ctx, KRB5KDC_ERR_POLICY, "%s", reason);
            krb5_free_string(ctx, reason);
        } else
#endif
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

#ifdef KRBTRAY_MIT
    krb5_free_data_contents(ctx, &result_code_string);
    krb5_free_data_contents(ctx, &result_string);
#else
    krb5_data_free(&result_code_string);
    krb5_data_free(&result_string);
#endif
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
        return g_strdup(_("no tickets"));

    time_t now  = time(NULL);
    time_t diff = expiry - now;

    if (diff <= 0)
        return g_strdup(_("expired"));

    gint hours = (gint)(diff / 3600);
    gint mins  = (gint)((diff % 3600) / 60);

    if (hours > 0)
        return g_strdup_printf("%dh %dm", hours, mins);
    return g_strdup_printf("%dm", mins);
}

/* Distinguish "could not reach the KDC" from "the KDC rejected us".  Only the
 * latter warrants telling the user; the former happens routinely whenever the
 * network is down or not yet up, and simply needs retrying later.  Covers both
 * the Kerberos-level codes and the socket/resolver errnos that Heimdal passes
 * through unchanged. */
gboolean krbtray_krb_error_is_transient(krb5_error_code ret)
{
    switch (ret) {
    /* Kerberos-level: no KDC answered, or the realm could not be located. */
    case KRB5_KDC_UNREACH:
    case KRB5_REALM_CANT_RESOLVE:
    case KRB5_REALM_UNKNOWN:
#ifdef HEIM_ERR_NOHOST
    /* Heimdal's mapping of EAI_NONAME / EAI_NODATA from getaddrinfo(). */
    case HEIM_ERR_NOHOST:
#endif
    /* Resolver or socket layer failures surfaced as plain errnos. */
    case EAGAIN:
    case ETIMEDOUT:
    case ECONNREFUSED:
    case ECONNRESET:
    case EHOSTUNREACH:
    case EHOSTDOWN:
    case ENETUNREACH:
    case ENETDOWN:
    case ENETRESET:
        return TRUE;
    default:
        return FALSE;
    }
}

/* Recognise "the password was wrong" however the implementation reports it.
 * An unknown principal is included because, to the user, a mistyped
 * principal and a mistyped password look the same. */
gboolean krbtray_krb_error_is_bad_password(krb5_error_code ret)
{
    switch (ret) {
    case KRB5KDC_ERR_PREAUTH_FAILED:
    case KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN:
#ifdef KRBTRAY_MIT
    /* MIT: the AS-REP could not be decrypted with the supplied password
     * (principal without the requires_preauth flag). */
    case KRB5KRB_AP_ERR_BAD_INTEGRITY:
#endif
        return TRUE;
    default:
        return FALSE;
    }
}
