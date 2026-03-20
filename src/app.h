#pragma once

#include <gtk/gtk.h>
#include <krb5.h>
#include <glib.h>
#include <gio/gio.h>

/* ── Ticket state ────────────────────────────────────────────────────────── */

typedef enum {
    KRB_STATE_NO_TICKETS, /* no ccache / no TGT found               */
    KRB_STATE_VALID,      /* tickets present and not near expiry     */
    KRB_STATE_EXPIRING,   /* within the renewal threshold            */
    KRB_STATE_EXPIRED,    /* past endtime                            */
} KrbState;

/* ── Per-principal entry (live state + config merged) ────────────────────── */

typedef struct {
    gchar   *principal_name; /* e.g. "alice@EXAMPLE.COM"             */

    /* live state – populated on each refresh */
    gboolean has_tickets;
    time_t   expiry;         /* Unix timestamp, 0 if no tickets      */
    time_t   renew_till;
    gboolean renewable;
    KrbState state;

    /* configuration flags */
    gboolean managed;        /* explicitly added by user in prefs    */
    gboolean store_password; /* password kept in the Secret Service  */
    gboolean auto_kinit;     /* kinit automatically using keyring    */
} KrbPrincipalEntry;

/* ── Application context ─────────────────────────────────────────────────── */

typedef struct {
    /* Kerberos */
    krb5_context  krb_ctx;

    /* Principal list (KrbPrincipalEntry *) */
    GList *entries;

    /* Configuration */
    GKeyFile *config;
    gchar    *config_path;
    gint      renewal_threshold_mins; /* renew this many minutes before expiry */
    gint      check_interval_secs;    /* how often to poll                     */
    gboolean  autostart;              /* manage ~/.config/autostart entry       */

    /* Tray */
    GtkStatusIcon *tray_icon;
    GtkWidget     *tray_menu;

    /* Timer source id */
    guint timer_id;

    /* Power-resume monitoring via logind D-Bus */
    GDBusConnection *system_bus;
    guint            sleep_signal_id;
} KrbTrayApp;

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

KrbTrayApp *krbtray_app_new      (void);
void        krbtray_app_run      (KrbTrayApp *app);
void        krbtray_app_free     (KrbTrayApp *app);

/* Triggered by timer and explicitly (e.g. after kinit/renew). */
void        krbtray_app_refresh  (KrbTrayApp *app);

/* Config persistence. */
void        krbtray_app_load_config (KrbTrayApp *app);
void        krbtray_app_save_config (KrbTrayApp *app);

/* Create / remove ~/.config/autostart/krbtray.desktop. */
void        krbtray_app_set_autostart (KrbTrayApp *app, gboolean enable);

/* Restart the periodic timer (call after check_interval changes). */
void        krbtray_app_restart_timer (KrbTrayApp *app);

/* Find an entry by name, or create+append a new one. */
KrbPrincipalEntry *krbtray_app_get_or_create_entry (KrbTrayApp  *app,
                                                     const gchar *principal_name);

/* Remove a managed principal and destroy its entry. */
void krbtray_app_remove_principal (KrbTrayApp *app, const gchar *principal_name);
