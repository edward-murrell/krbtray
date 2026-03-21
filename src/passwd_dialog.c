#include "passwd_dialog.h"
#include "kerberos.h"
#include "keyring.h"

#include <gtk/gtk.h>
#include <glib/gi18n.h>
#include <string.h>

/* ── Dialog state ────────────────────────────────────────────────────────── */

typedef struct {
    GtkWidget *dialog;
    GtkWidget *entry_current_pw;
    GtkWidget *entry_new_pw;
    GtkWidget *entry_confirm_pw;
    GtkWidget *label_error;
    GtkWidget *btn_change;

    KrbTrayApp  *app;
    const gchar *principal_name;
} PasswdDialogData;

/* ── Callback: attempt the password change ───────────────────────────────── */

/* Validate the form fields, call the Kerberos password-change API, and on
 * success update the keyring and obtain a fresh TGT with the new password. */
static void on_change_clicked(GtkButton *btn, PasswdDialogData *d)
{
    (void)btn;

    const gchar *current_pw =
        gtk_entry_get_text(GTK_ENTRY(d->entry_current_pw));
    const gchar *new_pw =
        gtk_entry_get_text(GTK_ENTRY(d->entry_new_pw));
    const gchar *confirm_pw =
        gtk_entry_get_text(GTK_ENTRY(d->entry_confirm_pw));

    if (!current_pw || *current_pw == '\0') {
        gtk_label_set_text(GTK_LABEL(d->label_error),
                           _("Please enter your current password."));
        gtk_widget_show(d->label_error);
        return;
    }

    if (!new_pw || *new_pw == '\0') {
        gtk_label_set_text(GTK_LABEL(d->label_error),
                           _("Please enter a new password."));
        gtk_widget_show(d->label_error);
        return;
    }

    if (g_strcmp0(new_pw, confirm_pw) != 0) {
        gtk_label_set_text(GTK_LABEL(d->label_error),
                           _("New passwords do not match."));
        gtk_widget_show(d->label_error);
        return;
    }

    gtk_widget_set_sensitive(d->btn_change, FALSE);
    gtk_label_set_text(GTK_LABEL(d->label_error), _("Changing password…"));
    gtk_widget_show(d->label_error);

    /* Flush UI before the blocking Kerberos call. */
    while (gtk_events_pending())
        gtk_main_iteration_do(FALSE);

    krb5_error_code ret = krbtray_krb_change_password(
        d->app->krb_ctx, d->principal_name, current_pw, new_pw);

    if (ret != 0) {
        const char *msg;
        gboolean free_msg = FALSE;

        if (ret == KRB5KDC_ERR_PREAUTH_FAILED ||
            ret == KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN) {
            msg = _("Current password is incorrect.");
        } else {
            msg = krb5_get_error_message(d->app->krb_ctx, ret);
            free_msg = TRUE;
        }

        gchar *markup = g_markup_printf_escaped(
            "<span foreground='red'>%s</span>", msg);
        gtk_label_set_markup(GTK_LABEL(d->label_error), markup);
        gtk_widget_show(d->label_error);
        g_free(markup);
        if (free_msg)
            krb5_free_error_message(d->app->krb_ctx, msg);
        gtk_widget_set_sensitive(d->btn_change, TRUE);
        return;
    }

    /* Update keyring if the principal has a stored password. */
    KrbPrincipalEntry *entry =
        krbtray_app_get_or_create_entry(d->app, d->principal_name);
    if (entry->store_password)
        krbtray_keyring_store_password(d->principal_name, new_pw);

    /* Re-authenticate with the new password to obtain a fresh TGT. */
    krbtray_krb_kinit(d->app->krb_ctx, d->principal_name, new_pw);

    krbtray_app_save_config(d->app);
    krbtray_app_refresh(d->app);

    gtk_dialog_response(GTK_DIALOG(d->dialog), GTK_RESPONSE_OK);
}

/* Allow Enter in any password field to submit the form. */
static void on_entry_activate(GtkEntry *entry, PasswdDialogData *d)
{
    (void)entry;
    on_change_clicked(NULL, d);
}

/* ── Public entry point ──────────────────────────────────────────────────── */

/* Build and run the Change Password dialog.  must_change adds a prominent
 * notice that the server requires a password change before login. */
gboolean krbtray_passwd_dialog_run(KrbTrayApp  *app,
                                   const gchar *principal_name,
                                   gboolean     must_change)
{
    PasswdDialogData d = { .app = app, .principal_name = principal_name };

    d.dialog = gtk_dialog_new_with_buttons(
        _("Change Kerberos Password"),
        NULL,
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        _("_Cancel"), GTK_RESPONSE_CANCEL,
        NULL);

    d.btn_change = gtk_button_new_with_mnemonic(_("_Change Password"));
    gtk_style_context_add_class(
        gtk_widget_get_style_context(d.btn_change),
        GTK_STYLE_CLASS_SUGGESTED_ACTION);
    gtk_dialog_add_action_widget(GTK_DIALOG(d.dialog), d.btn_change,
                                 GTK_RESPONSE_OK);
    gtk_widget_set_can_default(d.btn_change, TRUE);
    gtk_window_set_default(GTK_WINDOW(d.dialog), d.btn_change);

    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(d.dialog));
    gtk_container_set_border_width(GTK_CONTAINER(content), 12);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_add(GTK_CONTAINER(content), vbox);

    /* Optional must-change notice. */
    if (must_change) {
        GtkWidget *notice = gtk_label_new(NULL);
        gchar *notice_markup = g_markup_printf_escaped(
            "<b>%s</b>",
            _("Your password must be changed before you can log in."));
        gtk_label_set_markup(GTK_LABEL(notice), notice_markup);
        g_free(notice_markup);
        gtk_label_set_line_wrap(GTK_LABEL(notice), TRUE);
        gtk_widget_set_halign(notice, GTK_ALIGN_START);
        gtk_box_pack_start(GTK_BOX(vbox), notice, FALSE, FALSE, 0);

        gtk_box_pack_start(GTK_BOX(vbox),
                           gtk_separator_new(GTK_ORIENTATION_HORIZONTAL),
                           FALSE, FALSE, 4);
    }

    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 8);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 12);
    gtk_box_pack_start(GTK_BOX(vbox), grid, FALSE, FALSE, 0);

    gint row = 0;

    /* Principal (read-only display). */
    GtkWidget *lbl_p = gtk_label_new(_("Principal:"));
    gtk_widget_set_halign(lbl_p, GTK_ALIGN_END);
    GtkWidget *lbl_pval = gtk_label_new(principal_name);
    gtk_widget_set_halign(lbl_pval, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), lbl_p,    0, row, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), lbl_pval, 1, row, 1, 1);
    row++;

    /* Current password. */
    GtkWidget *lbl_cur = gtk_label_new_with_mnemonic(_("_Current password:"));
    gtk_widget_set_halign(lbl_cur, GTK_ALIGN_END);
    d.entry_current_pw = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(d.entry_current_pw), FALSE);
    gtk_entry_set_input_purpose(GTK_ENTRY(d.entry_current_pw),
                                GTK_INPUT_PURPOSE_PASSWORD);
    gtk_entry_set_width_chars(GTK_ENTRY(d.entry_current_pw), 32);
    gtk_label_set_mnemonic_widget(GTK_LABEL(lbl_cur), d.entry_current_pw);
    gtk_grid_attach(GTK_GRID(grid), lbl_cur,          0, row, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), d.entry_current_pw, 1, row, 1, 1);
    row++;

    /* New password. */
    GtkWidget *lbl_new = gtk_label_new_with_mnemonic(_("_New password:"));
    gtk_widget_set_halign(lbl_new, GTK_ALIGN_END);
    d.entry_new_pw = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(d.entry_new_pw), FALSE);
    gtk_entry_set_input_purpose(GTK_ENTRY(d.entry_new_pw),
                                GTK_INPUT_PURPOSE_PASSWORD);
    gtk_entry_set_width_chars(GTK_ENTRY(d.entry_new_pw), 32);
    gtk_label_set_mnemonic_widget(GTK_LABEL(lbl_new), d.entry_new_pw);
    gtk_grid_attach(GTK_GRID(grid), lbl_new,       0, row, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), d.entry_new_pw, 1, row, 1, 1);
    row++;

    /* Confirm new password. */
    GtkWidget *lbl_conf = gtk_label_new_with_mnemonic(_("C_onfirm password:"));
    gtk_widget_set_halign(lbl_conf, GTK_ALIGN_END);
    d.entry_confirm_pw = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(d.entry_confirm_pw), FALSE);
    gtk_entry_set_input_purpose(GTK_ENTRY(d.entry_confirm_pw),
                                GTK_INPUT_PURPOSE_PASSWORD);
    gtk_entry_set_width_chars(GTK_ENTRY(d.entry_confirm_pw), 32);
    gtk_label_set_mnemonic_widget(GTK_LABEL(lbl_conf), d.entry_confirm_pw);
    gtk_grid_attach(GTK_GRID(grid), lbl_conf,         0, row, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), d.entry_confirm_pw, 1, row, 1, 1);
    row++;

    /* Error label (hidden until needed). */
    d.label_error = gtk_label_new("");
    gtk_label_set_use_markup(GTK_LABEL(d.label_error), TRUE);
    gtk_label_set_line_wrap(GTK_LABEL(d.label_error), TRUE);
    gtk_widget_set_halign(d.label_error, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), d.label_error, 0, row, 2, 1);

    /* Wire signals. */
    g_signal_connect(d.btn_change, "clicked",
                     G_CALLBACK(on_change_clicked), &d);
    g_signal_connect(d.entry_current_pw, "activate",
                     G_CALLBACK(on_entry_activate), &d);
    g_signal_connect(d.entry_new_pw, "activate",
                     G_CALLBACK(on_entry_activate), &d);
    g_signal_connect(d.entry_confirm_pw, "activate",
                     G_CALLBACK(on_entry_activate), &d);

    gtk_window_set_resizable(GTK_WINDOW(d.dialog), FALSE);
    gtk_widget_show_all(d.dialog);
    gtk_widget_hide(d.label_error);

    gtk_widget_grab_focus(d.entry_current_pw);

    gint response = gtk_dialog_run(GTK_DIALOG(d.dialog));
    gtk_widget_destroy(d.dialog);

    return response == GTK_RESPONSE_OK;
}
