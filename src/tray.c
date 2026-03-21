#include "tray.h"
#include "kerberos.h"
#include "kinit_dialog.h"
#include "passwd_dialog.h"
#include "prefs.h"

#include <gtk/gtk.h>
#include <glib/gi18n.h>
#include <string.h>

/* ── Icon names per state ────────────────────────────────────────────────── */

/* Map a ticket state to the appropriate themed icon name. */
static const gchar *icon_for_state(KrbState state)
{
    switch (state) {
    case KRB_STATE_VALID:    return "security-high";
    case KRB_STATE_EXPIRING: return "security-medium";
    default:                 return "security-low";
    }
}

/* ── Compute the worst state across all entries ───────────────────────────── */

/*
 * Severity order for icon selection:
 *   EXPIRED   → security-low   (red)
 *   EXPIRING  → security-medium (yellow)
 *   NO_TICKETS→ security-low   (grey/red – nothing to show)
 *   VALID     → security-high  (green)
 */
static KrbState display_state(KrbTrayApp *app)
{
    gboolean any_valid    = FALSE;
    gboolean any_expiring = FALSE;
    gboolean any_expired  = FALSE;

    for (GList *l = app->entries; l; l = l->next) {
        KrbPrincipalEntry *e = l->data;
        switch (e->state) {
        case KRB_STATE_VALID:    any_valid    = TRUE; break;
        case KRB_STATE_EXPIRING: any_expiring = TRUE; break;
        case KRB_STATE_EXPIRED:  any_expired  = TRUE; break;
        default: break;
        }
    }

    if (any_expired)  return KRB_STATE_EXPIRED;
    if (any_expiring) return KRB_STATE_EXPIRING;
    if (any_valid)    return KRB_STATE_VALID;
    return KRB_STATE_NO_TICKETS;
}

/* ── Menu item data key ──────────────────────────────────────────────────── */

#define PRINCIPAL_KEY "krbtray-principal"

/* ── Menu callbacks ──────────────────────────────────────────────────────── */

/* Menu handler: attempt an immediate TGT renewal for the selected principal. */
static void on_menu_renew(GtkMenuItem *item, KrbTrayApp *app)
{
    const gchar *name = g_object_get_data(G_OBJECT(item), PRINCIPAL_KEY);
    if (!name) return;

    krb5_error_code ret = krbtray_krb_renew(app->krb_ctx, name);
    if (ret != 0) {
        const char *msg = krb5_get_error_message(app->krb_ctx, ret);
        GtkWidget *dlg = gtk_message_dialog_new(
            NULL, 0, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK,
            _("Renewal failed for %s:\n%s"), name, msg);
        gtk_dialog_run(GTK_DIALOG(dlg));
        gtk_widget_destroy(dlg);
        krb5_free_error_message(app->krb_ctx, msg);
    }
    krbtray_app_refresh(app);
}

/* Menu handler: confirm with the user then destroy the principal's tickets. */
static void on_menu_destroy(GtkMenuItem *item, KrbTrayApp *app)
{
    const gchar *name = g_object_get_data(G_OBJECT(item), PRINCIPAL_KEY);
    if (!name) return;

    GtkWidget *dlg = gtk_message_dialog_new(
        NULL, 0, GTK_MESSAGE_QUESTION, GTK_BUTTONS_YES_NO,
        _("Destroy Kerberos tickets for %s?"), name);
    gint r = gtk_dialog_run(GTK_DIALOG(dlg));
    gtk_widget_destroy(dlg);

    if (r == GTK_RESPONSE_YES) {
        krbtray_krb_destroy(app->krb_ctx, name);
        krbtray_app_refresh(app);
    }
}

/* Menu handler: authenticate the selected principal, using a stored password
 * silently where available, otherwise prompting with the kinit dialog. */
static void on_menu_authenticate(GtkMenuItem *item, KrbTrayApp *app)
{
    const gchar *name = g_object_get_data(G_OBJECT(item), PRINCIPAL_KEY);
    krbtray_app_authenticate(app, name);   /* name may be NULL → editable */
}

/* Menu handler: open the Change Password dialog for the selected principal. */
static void on_menu_change_password(GtkMenuItem *item, KrbTrayApp *app)
{
    const gchar *name = g_object_get_data(G_OBJECT(item), PRINCIPAL_KEY);
    if (!name) return;
    krbtray_passwd_dialog_run(app, name, FALSE);
}

/* Menu handler: open the Preferences dialog. */
static void on_menu_prefs(GtkMenuItem *item, KrbTrayApp *app)
{
    (void)item;
    krbtray_prefs_show(app);
}

/* Menu handler: exit the application. */
static void on_menu_quit(GtkMenuItem *item, KrbTrayApp *app)
{
    (void)item;
    (void)app;
    gtk_main_quit();
}

/* ── Helper: menu item that carries a principal name ─────────────────────── */

/* Create a menu item that carries the principal name as object data so
 * callback handlers can identify which principal was acted on. */
static GtkWidget *principal_item(const gchar *label, const gchar *principal,
                                 GCallback cb, KrbTrayApp *app)
{
    GtkWidget *item = gtk_menu_item_new_with_label(label);
    if (principal)
        g_object_set_data_full(G_OBJECT(item), PRINCIPAL_KEY,
                               g_strdup(principal), g_free);
    g_signal_connect(item, "activate", cb, app);
    return item;
}

/* ── Build the context menu ──────────────────────────────────────────────── */

/* Build the right-click context menu from the current principal list.
 * Each principal gets its own section with relevant ticket actions. */
static GtkWidget *build_menu(KrbTrayApp *app)
{
    GtkWidget *menu = gtk_menu_new();

    /* Title (insensitive). */
    GtkWidget *title = gtk_menu_item_new_with_label(_("Kerberos Tray Monitor"));
    gtk_widget_set_sensitive(title, FALSE);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), title);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), gtk_separator_menu_item_new());

    if (app->entries == NULL) {
        GtkWidget *none = gtk_menu_item_new_with_label(_("No tickets"));
        gtk_widget_set_sensitive(none, FALSE);
        gtk_menu_shell_append(GTK_MENU_SHELL(menu), none);
        gtk_menu_shell_append(GTK_MENU_SHELL(menu),
                              gtk_separator_menu_item_new());
    }

    /* One section per principal. */
    for (GList *l = app->entries; l; l = l->next) {
        KrbPrincipalEntry *e = l->data;

        /* Principal header with status. */
        gchar *time_str = krbtray_krb_time_remaining(e->expiry);
        gchar *header   = e->has_tickets
            ? g_strdup_printf("%s  (%s)", e->principal_name, time_str)
            : g_strdup_printf("%s  (%s)", e->principal_name, _("no tickets"));
        g_free(time_str);

        GtkWidget *hdr_item = gtk_menu_item_new();
        GtkWidget *hdr_lbl  = gtk_label_new(NULL);
        gchar *markup = g_markup_printf_escaped("<b>%s</b>", header);
        gtk_label_set_markup(GTK_LABEL(hdr_lbl), markup);
        g_free(markup);
        g_free(header);
        gtk_widget_set_halign(hdr_lbl, GTK_ALIGN_START);
        gtk_container_add(GTK_CONTAINER(hdr_item), hdr_lbl);
        gtk_widget_set_sensitive(hdr_item, FALSE);
        gtk_menu_shell_append(GTK_MENU_SHELL(menu), hdr_item);

        /* Actions. */
        if (e->has_tickets) {
            if (e->renewable) {
                GtkWidget *renew =
                    principal_item(_("  Renew Now"), e->principal_name,
                                   G_CALLBACK(on_menu_renew), app);
                gtk_menu_shell_append(GTK_MENU_SHELL(menu), renew);
            }
            GtkWidget *destroy =
                principal_item(_("  Destroy Tickets"), e->principal_name,
                               G_CALLBACK(on_menu_destroy), app);
            gtk_menu_shell_append(GTK_MENU_SHELL(menu), destroy);
        }

        GtkWidget *auth =
            principal_item(_("  Authenticate…"), e->principal_name,
                           G_CALLBACK(on_menu_authenticate), app);
        gtk_menu_shell_append(GTK_MENU_SHELL(menu), auth);

        GtkWidget *chpw =
            principal_item(_("  Change Password…"), e->principal_name,
                           G_CALLBACK(on_menu_change_password), app);
        gtk_menu_shell_append(GTK_MENU_SHELL(menu), chpw);

        gtk_menu_shell_append(GTK_MENU_SHELL(menu),
                              gtk_separator_menu_item_new());
    }

    /* Add principal (opens kinit dialog with empty principal). */
    GtkWidget *add_item =
        principal_item(_("Add Principal…"), NULL,
                       G_CALLBACK(on_menu_authenticate), app);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), add_item);

    gtk_menu_shell_append(GTK_MENU_SHELL(menu), gtk_separator_menu_item_new());

    /* Preferences. */
    GtkWidget *prefs_item = gtk_menu_item_new_with_mnemonic(_("_Preferences…"));
    g_signal_connect(prefs_item, "activate",
                     G_CALLBACK(on_menu_prefs), app);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), prefs_item);

    gtk_menu_shell_append(GTK_MENU_SHELL(menu), gtk_separator_menu_item_new());

    /* Quit. */
    GtkWidget *quit_item = gtk_menu_item_new_with_mnemonic(_("_Quit"));
    g_signal_connect(quit_item, "activate", G_CALLBACK(on_menu_quit), app);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), quit_item);

    gtk_widget_show_all(menu);
    return menu;
}

/* ── GtkStatusIcon signal handlers ───────────────────────────────────────── */

/* Right-click handler: rebuild and display the context menu at the tray icon. */
static void on_tray_popup_menu(GtkStatusIcon *icon, guint button,
                               guint activate_time, KrbTrayApp *app)
{
    if (app->tray_menu)
        gtk_widget_destroy(app->tray_menu);

    app->tray_menu = build_menu(app);

    gtk_menu_popup(GTK_MENU(app->tray_menu),
                   NULL, NULL,
                   gtk_status_icon_position_menu,
                   icon,
                   button, activate_time);
}

static void on_tray_activate(GtkStatusIcon *icon, KrbTrayApp *app)
{
    /* Left-click: show the same context menu. */
    on_tray_popup_menu(icon, 0,
                       gtk_get_current_event_time(), app);
}

/* ── Public API ──────────────────────────────────────────────────────────── */

/* Create the GtkStatusIcon and connect click/popup-menu signals. */
void krbtray_tray_create(KrbTrayApp *app)
{
    app->tray_icon = gtk_status_icon_new_from_icon_name("security-low");
    gtk_status_icon_set_title(app->tray_icon, _("Kerberos Tray"));
    gtk_status_icon_set_visible(app->tray_icon, TRUE);

    g_signal_connect(app->tray_icon, "activate",
                     G_CALLBACK(on_tray_activate), app);
    g_signal_connect(app->tray_icon, "popup-menu",
                     G_CALLBACK(on_tray_popup_menu), app);
}

/* Refresh the tray icon image and tooltip to reflect the current worst-case
 * ticket state across all principals. */
void krbtray_tray_update(KrbTrayApp *app)
{
    KrbState ds = display_state(app);

    gtk_status_icon_set_from_icon_name(app->tray_icon,
                                       icon_for_state(ds));

    /* Build a tooltip listing all principals. */
    GString *tip = g_string_new(_("Kerberos tickets:\n"));

    if (app->entries == NULL) {
        g_string_append(tip, _("  (none)"));
    } else {
        for (GList *l = app->entries; l; l = l->next) {
            KrbPrincipalEntry *e = l->data;
            gchar *rem = krbtray_krb_time_remaining(e->expiry);
            g_string_append_printf(tip, "  %s – %s\n",
                                   e->principal_name, rem);
            g_free(rem);
        }
    }

    gtk_status_icon_set_tooltip_text(app->tray_icon, tip->str);
    g_string_free(tip, TRUE);
}
