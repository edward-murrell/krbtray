#include "kinit_dialog.h"
#include "kerberos.h"
#include "keyring.h"

#include <gtk/gtk.h>
#include <string.h>

/* ── Dialog state ────────────────────────────────────────────────────────── */

typedef struct {
    GtkWidget *dialog;
    GtkWidget *entry_principal;
    GtkWidget *entry_password;
    GtkWidget *check_remember;
    GtkWidget *label_error;
    GtkWidget *btn_login;

    KrbTrayApp *app;
} KinitDialogData;

/* ── Callback: try to kinit ──────────────────────────────────────────────── */

/* Validate the form, attempt kinit, and on success mark the principal as
 * managed and optionally save the password to the keyring. */
static void on_login_clicked(GtkButton *btn, KinitDialogData *d)
{
    (void)btn;

    const gchar *principal =
        gtk_entry_get_text(GTK_ENTRY(d->entry_principal));
    const gchar *password  =
        gtk_entry_get_text(GTK_ENTRY(d->entry_password));

    if (!principal || *principal == '\0') {
        gtk_label_set_text(GTK_LABEL(d->label_error),
                           "Please enter a principal.");
        gtk_widget_show(d->label_error);
        return;
    }

    gtk_widget_set_sensitive(d->btn_login, FALSE);
    gtk_label_set_text(GTK_LABEL(d->label_error), "Authenticating…");
    gtk_widget_show(d->label_error);

    /* Process pending events so the UI updates before blocking in kinit. */
    while (gtk_events_pending())
        gtk_main_iteration_do(FALSE);

    krb5_error_code ret =
        krbtray_krb_kinit(d->app->krb_ctx, principal, password);

    if (ret != 0) {
        const char *msg = krb5_get_error_message(d->app->krb_ctx, ret);
        gchar *markup = g_markup_printf_escaped(
            "<span foreground='red'>%s</span>", msg);
        gtk_label_set_markup(GTK_LABEL(d->label_error), markup);
        gtk_widget_show(d->label_error);
        g_free(markup);
        krb5_free_error_message(d->app->krb_ctx, msg);
        gtk_widget_set_sensitive(d->btn_login, TRUE);
        return;
    }

    /* Ensure the principal is in the managed list. */
    KrbPrincipalEntry *entry =
        krbtray_app_get_or_create_entry(d->app, principal);
    entry->managed = TRUE;

    /* Optionally store the password. */
    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(d->check_remember))) {
        entry->store_password = TRUE;
        entry->auto_kinit     = TRUE;
        krbtray_keyring_store_password(principal, password);
    }

    krbtray_app_save_config(d->app);
    krbtray_app_refresh(d->app);

    gtk_dialog_response(GTK_DIALOG(d->dialog), GTK_RESPONSE_OK);
}

/* ── Callback: Enter key in password field ───────────────────────────────── */

/* Allow the user to press Enter in the password field to submit. */
static void on_password_activate(GtkEntry *entry, KinitDialogData *d)
{
    (void)entry;
    on_login_clicked(NULL, d);
}

/* ── Public ──────────────────────────────────────────────────────────────── */

/* Show the Authenticate dialog.  If principal_name is non-NULL it is
 * pre-filled and locked; otherwise the user may type any principal.
 * Returns TRUE if authentication succeeded, FALSE on cancel or error. */
gboolean krbtray_kinit_dialog_run(KrbTrayApp *app, const gchar *principal_name)
{
    KinitDialogData d = { .app = app };

    d.dialog = gtk_dialog_new_with_buttons(
        "Authenticate with Kerberos",
        NULL,
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        "_Cancel", GTK_RESPONSE_CANCEL,
        NULL);

    d.btn_login = gtk_button_new_with_mnemonic("_Authenticate");
    gtk_style_context_add_class(gtk_widget_get_style_context(d.btn_login),
                                GTK_STYLE_CLASS_SUGGESTED_ACTION);
    gtk_dialog_add_action_widget(GTK_DIALOG(d.dialog), d.btn_login,
                                 GTK_RESPONSE_OK);
    gtk_widget_set_can_default(d.btn_login, TRUE);
    gtk_window_set_default(GTK_WINDOW(d.dialog), d.btn_login);

    /* Content area. */
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(d.dialog));
    gtk_container_set_border_width(GTK_CONTAINER(content), 12);

    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 8);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 12);
    gtk_container_add(GTK_CONTAINER(content), grid);

    gint row = 0;

    /* Principal. */
    GtkWidget *lbl_p = gtk_label_new_with_mnemonic("_Principal:");
    gtk_widget_set_halign(lbl_p, GTK_ALIGN_END);
    d.entry_principal = gtk_entry_new();
    gtk_entry_set_width_chars(GTK_ENTRY(d.entry_principal), 32);
    if (principal_name) {
        gtk_entry_set_text(GTK_ENTRY(d.entry_principal), principal_name);
        gtk_widget_set_sensitive(d.entry_principal, FALSE);
    }
    gtk_label_set_mnemonic_widget(GTK_LABEL(lbl_p), d.entry_principal);
    gtk_grid_attach(GTK_GRID(grid), lbl_p,             0, row, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), d.entry_principal, 1, row, 1, 1);
    row++;

    /* Password. */
    GtkWidget *lbl_pw = gtk_label_new_with_mnemonic("Pass_word:");
    gtk_widget_set_halign(lbl_pw, GTK_ALIGN_END);
    d.entry_password = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(d.entry_password), FALSE);
    gtk_entry_set_input_purpose(GTK_ENTRY(d.entry_password),
                                GTK_INPUT_PURPOSE_PASSWORD);
    gtk_label_set_mnemonic_widget(GTK_LABEL(lbl_pw), d.entry_password);
    gtk_grid_attach(GTK_GRID(grid), lbl_pw,            0, row, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), d.entry_password,  1, row, 1, 1);
    row++;

    /* Remember password checkbox. */
    d.check_remember =
        gtk_check_button_new_with_mnemonic("_Remember password in keyring");

    /* Pre-check if the principal already has store_password set. */
    if (principal_name) {
        for (GList *l = app->entries; l; l = l->next) {
            KrbPrincipalEntry *e = l->data;
            if (g_strcmp0(e->principal_name, principal_name) == 0) {
                gtk_toggle_button_set_active(
                    GTK_TOGGLE_BUTTON(d.check_remember), e->store_password);
                break;
            }
        }
    }
    gtk_grid_attach(GTK_GRID(grid), d.check_remember, 0, row, 2, 1);
    row++;

    /* Error label (hidden until needed). */
    d.label_error = gtk_label_new("");
    gtk_label_set_use_markup(GTK_LABEL(d.label_error), TRUE);
    gtk_widget_set_halign(d.label_error, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), d.label_error, 0, row, 2, 1);

    /* Wire signals. */
    g_signal_connect(d.btn_login, "clicked",
                     G_CALLBACK(on_login_clicked), &d);
    g_signal_connect(d.entry_password, "activate",
                     G_CALLBACK(on_password_activate), &d);

    gtk_window_set_resizable(GTK_WINDOW(d.dialog), FALSE);
    gtk_widget_show_all(d.dialog);
    gtk_widget_hide(d.label_error);

    /* Focus password if principal is pre-filled, otherwise principal field. */
    if (principal_name)
        gtk_widget_grab_focus(d.entry_password);
    else
        gtk_widget_grab_focus(d.entry_principal);

    gint response = gtk_dialog_run(GTK_DIALOG(d.dialog));
    gtk_widget_destroy(d.dialog);

    return response == GTK_RESPONSE_OK;
}
