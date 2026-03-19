#include "app.h"
#include "kerberos.h"
#include "tray.h"
#include "notify.h"
#include "keyring.h"

#include <glib/gstdio.h>
#include <string.h>
#include <stdio.h>

/* ── Defaults ────────────────────────────────────────────────────────────── */

#define DEFAULT_RENEWAL_THRESHOLD_MINS 30
#define DEFAULT_CHECK_INTERVAL_SECS    60
#define CONFIG_GROUP_GENERAL           "General"
#define CONFIG_GROUP_PRINCIPALS        "Principals"
#define CONFIG_PREFIX_PRINCIPAL        "Principal "   /* + name */
#define AUTOSTART_FILENAME             "krbtray.desktop"

/* ── Timer callback ──────────────────────────────────────────────────────── */

static gboolean on_refresh_timer(gpointer data)
{
    krbtray_app_refresh((KrbTrayApp *)data);
    return G_SOURCE_CONTINUE;
}

/* ── Entry helpers ───────────────────────────────────────────────────────── */

KrbPrincipalEntry *krbtray_app_get_or_create_entry(KrbTrayApp  *app,
                                                   const gchar *principal_name)
{
    for (GList *l = app->entries; l; l = l->next) {
        KrbPrincipalEntry *e = l->data;
        if (g_strcmp0(e->principal_name, principal_name) == 0)
            return e;
    }
    KrbPrincipalEntry *e = g_new0(KrbPrincipalEntry, 1);
    e->principal_name = g_strdup(principal_name);
    e->state = KRB_STATE_NO_TICKETS;
    app->entries = g_list_append(app->entries, e);
    return e;
}

static void entry_free(KrbPrincipalEntry *e)
{
    g_free(e->principal_name);
    g_free(e);
}

void krbtray_app_remove_principal(KrbTrayApp *app, const gchar *principal_name)
{
    for (GList *l = app->entries; l; l = l->next) {
        KrbPrincipalEntry *e = l->data;
        if (g_strcmp0(e->principal_name, principal_name) == 0) {
            app->entries = g_list_remove(app->entries, e);
            entry_free(e);
            krbtray_app_save_config(app);
            return;
        }
    }
}

/* ── Config ──────────────────────────────────────────────────────────────── */

void krbtray_app_load_config(KrbTrayApp *app)
{
    GError *err = NULL;
    g_key_file_load_from_file(app->config, app->config_path,
                              G_KEY_FILE_KEEP_COMMENTS, &err);
    if (err) {
        /* File may simply not exist yet; that is fine. */
        g_clear_error(&err);
    }

    app->renewal_threshold_mins =
        g_key_file_get_integer(app->config, CONFIG_GROUP_GENERAL,
                               "renewal_threshold_mins", NULL);
    if (app->renewal_threshold_mins <= 0)
        app->renewal_threshold_mins = DEFAULT_RENEWAL_THRESHOLD_MINS;

    app->check_interval_secs =
        g_key_file_get_integer(app->config, CONFIG_GROUP_GENERAL,
                               "check_interval_secs", NULL);
    if (app->check_interval_secs <= 0)
        app->check_interval_secs = DEFAULT_CHECK_INTERVAL_SECS;

    app->autostart =
        g_key_file_get_boolean(app->config, CONFIG_GROUP_GENERAL,
                               "autostart", NULL);

    /* Load managed principals. */
    gchar **groups = g_key_file_get_groups(app->config, NULL);
    for (gint i = 0; groups && groups[i]; i++) {
        if (!g_str_has_prefix(groups[i], CONFIG_PREFIX_PRINCIPAL))
            continue;
        const gchar *name = groups[i] + strlen(CONFIG_PREFIX_PRINCIPAL);
        KrbPrincipalEntry *e = krbtray_app_get_or_create_entry(app, name);
        e->managed = TRUE;
        e->store_password =
            g_key_file_get_boolean(app->config, groups[i], "store_password", NULL);
        e->auto_kinit =
            g_key_file_get_boolean(app->config, groups[i], "auto_kinit", NULL);
    }
    g_strfreev(groups);
}

void krbtray_app_save_config(KrbTrayApp *app)
{
    g_key_file_set_integer(app->config, CONFIG_GROUP_GENERAL,
                           "renewal_threshold_mins", app->renewal_threshold_mins);
    g_key_file_set_integer(app->config, CONFIG_GROUP_GENERAL,
                           "check_interval_secs", app->check_interval_secs);
    g_key_file_set_boolean(app->config, CONFIG_GROUP_GENERAL,
                           "autostart", app->autostart);

    /* Remove old principal groups then re-write them. */
    gchar **groups = g_key_file_get_groups(app->config, NULL);
    for (gint i = 0; groups && groups[i]; i++) {
        if (g_str_has_prefix(groups[i], CONFIG_PREFIX_PRINCIPAL))
            g_key_file_remove_group(app->config, groups[i], NULL);
    }
    g_strfreev(groups);

    for (GList *l = app->entries; l; l = l->next) {
        KrbPrincipalEntry *e = l->data;
        if (!e->managed) continue;
        gchar *group = g_strconcat(CONFIG_PREFIX_PRINCIPAL, e->principal_name, NULL);
        g_key_file_set_boolean(app->config, group, "store_password", e->store_password);
        g_key_file_set_boolean(app->config, group, "auto_kinit",     e->auto_kinit);
        g_free(group);
    }

    GError *err = NULL;
    gchar  *data = g_key_file_to_data(app->config, NULL, NULL);
    if (!g_file_set_contents(app->config_path, data, -1, &err)) {
        g_warning("Failed to save config: %s", err->message);
        g_clear_error(&err);
    }
    g_free(data);
}

/* ── Autostart ───────────────────────────────────────────────────────────── */

void krbtray_app_set_autostart(KrbTrayApp *app, gboolean enable)
{
    app->autostart = enable;
    krbtray_app_save_config(app);

    gchar *autostart_dir  = g_build_filename(g_get_user_config_dir(),
                                             "autostart", NULL);
    gchar *autostart_file = g_build_filename(autostart_dir,
                                             AUTOSTART_FILENAME, NULL);

    if (enable) {
        g_mkdir_with_parents(autostart_dir, 0755);

        /* Locate ourselves in PATH. */
        gchar *exec_path = g_find_program_in_path("krbtray");
        if (!exec_path) exec_path = g_strdup("krbtray");

        gchar *content = g_strdup_printf(
            "[Desktop Entry]\n"
            "Type=Application\n"
            "Name=Kerberos Tray\n"
            "Comment=Kerberos ticket management tray icon\n"
            "Exec=%s\n"
            "Icon=security-high\n"
            "StartupNotify=false\n"
            "X-GNOME-Autostart-enabled=true\n",
            exec_path);

        GError *err = NULL;
        if (!g_file_set_contents(autostart_file, content, -1, &err)) {
            g_warning("Could not write autostart file: %s", err->message);
            g_clear_error(&err);
        }
        g_free(content);
        g_free(exec_path);
    } else {
        g_unlink(autostart_file);
    }

    g_free(autostart_dir);
    g_free(autostart_file);
}

/* ── Timer management ────────────────────────────────────────────────────── */

void krbtray_app_restart_timer(KrbTrayApp *app)
{
    if (app->timer_id > 0) {
        g_source_remove(app->timer_id);
        app->timer_id = 0;
    }
    app->timer_id = g_timeout_add_seconds(app->check_interval_secs,
                                          on_refresh_timer, app);
}

/* ── Core refresh loop ───────────────────────────────────────────────────── */

void krbtray_app_refresh(KrbTrayApp *app)
{
    /* 1. Mark all entries as having no tickets so stale caches are cleared. */
    for (GList *l = app->entries; l; l = l->next) {
        KrbPrincipalEntry *e = l->data;
        e->has_tickets = FALSE;
        e->expiry      = 0;
        e->renew_till  = 0;
        e->renewable   = FALSE;
        e->state       = KRB_STATE_NO_TICKETS;
    }

    /* 2. Scan all credential caches; update / create entries. */
    GList *live = krbtray_krb_scan_caches(app->krb_ctx);
    for (GList *l = live; l; l = l->next) {
        KrbCacheInfo *ci = l->data;
        KrbPrincipalEntry *e =
            krbtray_app_get_or_create_entry(app, ci->principal_name);
        e->has_tickets = TRUE;
        e->expiry      = ci->expiry;
        e->renew_till  = ci->renew_till;
        e->renewable   = ci->renewable;
        e->state       = krbtray_krb_compute_state(
                             ci->expiry,
                             app->renewal_threshold_mins);
        g_free(ci->principal_name);
        g_free(ci);
    }
    g_list_free(live);

    /* 3. Remove unmanaged entries that no longer have tickets. */
    GList *next;
    for (GList *l = app->entries; l; l = next) {
        next = l->next;
        KrbPrincipalEntry *e = l->data;
        if (!e->has_tickets && !e->managed) {
            app->entries = g_list_remove(app->entries, e);
            entry_free(e);
        }
    }

    /* 4. For each entry: attempt renewal if needed. */
    for (GList *l = app->entries; l; l = l->next) {
        KrbPrincipalEntry *e = l->data;
        if (!e->has_tickets || !e->renewable)
            continue;
        if (e->state == KRB_STATE_EXPIRING || e->state == KRB_STATE_EXPIRED) {
            krb5_error_code ret =
                krbtray_krb_renew(app->krb_ctx, e->principal_name);
            if (ret != 0) {
                const char *msg =
                    krb5_get_error_message(app->krb_ctx, ret);
                krbtray_notify_renewal_failed(e->principal_name, msg);
                krb5_free_error_message(app->krb_ctx, msg);
            } else {
                /* Re-scan to pick up new expiry. */
                KrbCacheInfo *ci =
                    krbtray_krb_get_cache_info(app->krb_ctx, e->principal_name);
                if (ci) {
                    e->expiry     = ci->expiry;
                    e->renew_till = ci->renew_till;
                    e->state      = krbtray_krb_compute_state(
                                        ci->expiry,
                                        app->renewal_threshold_mins);
                    g_free(ci->principal_name);
                    g_free(ci);
                }
            }
        }
    }

    /* 5. For managed entries without tickets that have a stored password:
          attempt auto-kinit once (on startup the auto_kinit flag is TRUE). */
    for (GList *l = app->entries; l; l = l->next) {
        KrbPrincipalEntry *e = l->data;
        if (!e->managed || !e->auto_kinit || e->has_tickets)
            continue;
        if (!e->store_password)
            continue;
        gchar *pw = krbtray_keyring_lookup_password(e->principal_name);
        if (!pw) continue;
        krb5_error_code ret =
            krbtray_krb_kinit(app->krb_ctx, e->principal_name, pw);
        g_free(pw);
        if (ret == 0) {
            /* Don't keep re-trying auto_kinit in subsequent timer ticks. */
            e->auto_kinit = FALSE;
            /* Re-scan this entry. */
            KrbCacheInfo *ci =
                krbtray_krb_get_cache_info(app->krb_ctx, e->principal_name);
            if (ci) {
                e->has_tickets = TRUE;
                e->expiry      = ci->expiry;
                e->renew_till  = ci->renew_till;
                e->renewable   = ci->renewable;
                e->state       = krbtray_krb_compute_state(
                                     ci->expiry,
                                     app->renewal_threshold_mins);
                g_free(ci->principal_name);
                g_free(ci);
            }
        }
    }

    /* 6. Update the tray icon and menu. */
    krbtray_tray_update(app);
}

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

KrbTrayApp *krbtray_app_new(void)
{
    KrbTrayApp *app = g_new0(KrbTrayApp, 1);

    /* Kerberos context. */
    if (krb5_init_context(&app->krb_ctx) != 0) {
        g_printerr("krbtray: failed to initialise Kerberos context\n");
        g_free(app);
        return NULL;
    }

    /* Config file location. */
    gchar *config_dir = g_build_filename(g_get_user_config_dir(),
                                         "krbtray", NULL);
    g_mkdir_with_parents(config_dir, 0700);
    app->config_path = g_build_filename(config_dir, "krbtray.conf", NULL);
    g_free(config_dir);

    app->config = g_key_file_new();
    krbtray_app_load_config(app);

    /* libnotify. */
    krbtray_notify_init();

    /* Tray icon. */
    krbtray_tray_create(app);

    return app;
}

void krbtray_app_run(KrbTrayApp *app)
{
    /* Mark all managed principals for auto-kinit on startup. */
    for (GList *l = app->entries; l; l = l->next) {
        KrbPrincipalEntry *e = l->data;
        if (e->managed && e->auto_kinit && e->store_password)
            e->auto_kinit = TRUE;
    }

    /* Initial refresh, then start periodic timer. */
    krbtray_app_refresh(app);
    krbtray_app_restart_timer(app);
}

void krbtray_app_free(KrbTrayApp *app)
{
    if (!app) return;
    if (app->timer_id > 0)
        g_source_remove(app->timer_id);
    for (GList *l = app->entries; l; l = l->next)
        entry_free(l->data);
    g_list_free(app->entries);
    krb5_free_context(app->krb_ctx);
    g_key_file_free(app->config);
    g_free(app->config_path);
    krbtray_notify_uninit();
    g_free(app);
}
