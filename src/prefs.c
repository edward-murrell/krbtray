#include "prefs.h"
#include "kerberos.h"
#include "keyring.h"
#include "kinit_dialog.h"

#include <gtk/gtk.h>
#include <string.h>

/* ── Column indices for the principals list store ────────────────────────── */

enum {
    COL_PRINCIPAL   = 0,
    COL_STATE_STR,
    COL_STORE_PW,
    COL_AUTO_KINIT,
    N_COLS
};

/* ── Internal context ────────────────────────────────────────────────────── */

typedef struct {
    KrbTrayApp *app;

    /* Widgets – General tab */
    GtkWidget *spin_threshold;
    GtkWidget *spin_interval;
    GtkWidget *check_autostart;

    /* Widgets – Principals tab */
    GtkWidget     *tree_view;
    GtkListStore  *store;
    GtkWidget     *btn_remove;
    GtkWidget     *btn_auth;
    GtkWidget     *btn_clear_pw;
} PrefsData;

/* ── Principals list helpers ─────────────────────────────────────────────── */

/* Convert a KrbState value to the display string shown in the principals list. */
static const gchar *state_string(KrbState state)
{
    switch (state) {
    case KRB_STATE_VALID:      return "Valid";
    case KRB_STATE_EXPIRING:   return "Expiring";
    case KRB_STATE_EXPIRED:    return "Expired";
    default:                   return "No tickets";
    }
}

/* Reload the principals list store from the current app entry list,
 * showing only managed principals. */
static void populate_store(PrefsData *pd)
{
    gtk_list_store_clear(pd->store);

    for (GList *l = pd->app->entries; l; l = l->next) {
        KrbPrincipalEntry *e = l->data;
        if (!e->managed) continue;

        GtkTreeIter iter;
        gtk_list_store_append(pd->store, &iter);
        gtk_list_store_set(pd->store, &iter,
            COL_PRINCIPAL,  e->principal_name,
            COL_STATE_STR,  state_string(e->state),
            COL_STORE_PW,   e->store_password,
            COL_AUTO_KINIT, e->auto_kinit,
            -1);
    }
}

/* Get the principal name of the currently selected row (caller frees). */
static gchar *selected_principal(PrefsData *pd)
{
    GtkTreeSelection *sel =
        gtk_tree_view_get_selection(GTK_TREE_VIEW(pd->tree_view));
    GtkTreeModel *model;
    GtkTreeIter   iter;

    if (!gtk_tree_selection_get_selected(sel, &model, &iter))
        return NULL;

    gchar *name = NULL;
    gtk_tree_model_get(model, &iter, COL_PRINCIPAL, &name, -1);
    return name;
}

/* ── Principals toolbar callbacks ────────────────────────────────────────── */

/* Toolbar handler: open the kinit dialog to add a new managed principal. */
static void on_add_principal(GtkButton *btn, PrefsData *pd)
{
    (void)btn;

    /* Show the kinit dialog with an empty principal field. */
    if (krbtray_kinit_dialog_run(pd->app, NULL))
        populate_store(pd);
}

/* Toolbar handler: confirm and remove the selected principal from management. */
static void on_remove_principal(GtkButton *btn, PrefsData *pd)
{
    (void)btn;
    gchar *name = selected_principal(pd);
    if (!name) return;

    /* Ask for confirmation. */
    GtkWidget *dlg = gtk_message_dialog_new(
        GTK_WINDOW(gtk_widget_get_toplevel(pd->tree_view)),
        GTK_DIALOG_MODAL,
        GTK_MESSAGE_QUESTION,
        GTK_BUTTONS_YES_NO,
        "Remove principal \"%s\" from the managed list?", name);
    gint r = gtk_dialog_run(GTK_DIALOG(dlg));
    gtk_widget_destroy(dlg);

    if (r == GTK_RESPONSE_YES) {
        krbtray_app_remove_principal(pd->app, name);
        populate_store(pd);
    }
    g_free(name);
}

/* Toolbar handler: open the kinit dialog for the selected principal. */
static void on_authenticate(GtkButton *btn, PrefsData *pd)
{
    (void)btn;
    gchar *name = selected_principal(pd);
    if (!name) return;
    if (krbtray_kinit_dialog_run(pd->app, name))
        populate_store(pd);
    g_free(name);
}

/* Toolbar handler: delete the stored keyring password and disable auto-kinit
 * for the selected principal. */
static void on_clear_password(GtkButton *btn, PrefsData *pd)
{
    (void)btn;
    gchar *name = selected_principal(pd);
    if (!name) return;

    krbtray_keyring_delete_password(name);

    KrbPrincipalEntry *e = krbtray_app_get_or_create_entry(pd->app, name);
    e->store_password = FALSE;
    e->auto_kinit     = FALSE;
    krbtray_app_save_config(pd->app);
    populate_store(pd);
    g_free(name);
}

/* Enable or disable the toolbar action buttons depending on whether a
 * principal is currently selected in the list. */
static void on_selection_changed(GtkTreeSelection *sel, PrefsData *pd)
{
    gboolean have_sel = gtk_tree_selection_count_selected_rows(sel) > 0;
    gtk_widget_set_sensitive(pd->btn_remove,   have_sel);
    gtk_widget_set_sensitive(pd->btn_auth,     have_sel);
    gtk_widget_set_sensitive(pd->btn_clear_pw, have_sel);
}

/* Toggle callbacks for tree view check-box columns. */
/* Inline toggle handler: flip the "store password" flag; also clears the
 * keyring entry and disables auto-kinit when the flag is turned off. */
static void on_store_pw_toggled(GtkCellRendererToggle *cell,
                                gchar                 *path_str,
                                PrefsData             *pd)
{
    (void)cell;
    GtkTreeIter iter;
    GtkTreePath *path = gtk_tree_path_new_from_string(path_str);
    gtk_tree_model_get_iter(GTK_TREE_MODEL(pd->store), &iter, path);
    gtk_tree_path_free(path);

    gchar    *name;
    gboolean  old_val;
    gtk_tree_model_get(GTK_TREE_MODEL(pd->store), &iter,
                       COL_PRINCIPAL, &name, COL_STORE_PW, &old_val, -1);

    gboolean new_val = !old_val;
    gtk_list_store_set(pd->store, &iter, COL_STORE_PW, new_val, -1);

    KrbPrincipalEntry *e = krbtray_app_get_or_create_entry(pd->app, name);
    e->store_password = new_val;
    if (!new_val) {
        /* Clearing store_password also removes the stored secret. */
        krbtray_keyring_delete_password(name);
        e->auto_kinit = FALSE;
        gtk_list_store_set(pd->store, &iter, COL_AUTO_KINIT, FALSE, -1);
    }
    g_free(name);
}

/* Inline toggle handler: flip the "auto kinit" flag for the selected row. */
static void on_auto_kinit_toggled(GtkCellRendererToggle *cell,
                                  gchar                 *path_str,
                                  PrefsData             *pd)
{
    (void)cell;
    GtkTreeIter iter;
    GtkTreePath *path = gtk_tree_path_new_from_string(path_str);
    gtk_tree_model_get_iter(GTK_TREE_MODEL(pd->store), &iter, path);
    gtk_tree_path_free(path);

    gchar    *name;
    gboolean  old_val;
    gtk_tree_model_get(GTK_TREE_MODEL(pd->store), &iter,
                       COL_PRINCIPAL, &name, COL_AUTO_KINIT, &old_val, -1);

    gboolean new_val = !old_val;
    gtk_list_store_set(pd->store, &iter, COL_AUTO_KINIT, new_val, -1);

    KrbPrincipalEntry *e = krbtray_app_get_or_create_entry(pd->app, name);
    e->auto_kinit = new_val;
    g_free(name);
}

/* ── Build individual notebook pages ─────────────────────────────────────── */

/* Construct the General tab with renewal threshold, check interval, and
 * autostart controls. */
static GtkWidget *build_general_page(PrefsData *pd)
{
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 12);
    gtk_container_set_border_width(GTK_CONTAINER(grid), 16);

    gint row = 0;

    /* Renewal threshold. */
    GtkWidget *lbl1 = gtk_label_new_with_mnemonic(
        "Renew TGT ___ minutes before expiry:");
    gtk_widget_set_halign(lbl1, GTK_ALIGN_START);

    pd->spin_threshold =
        gtk_spin_button_new_with_range(1, 120, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(pd->spin_threshold),
                              pd->app->renewal_threshold_mins);
    gtk_label_set_mnemonic_widget(GTK_LABEL(lbl1), pd->spin_threshold);

    GtkWidget *lbl1b = gtk_label_new("minutes before expiry");
    gtk_widget_set_halign(lbl1b, GTK_ALIGN_START);

    GtkWidget *hbox1 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_pack_start(GTK_BOX(hbox1),
        gtk_label_new("Renew TGT"), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hbox1), pd->spin_threshold, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hbox1), lbl1b, FALSE, FALSE, 0);
    (void)lbl1;
    gtk_grid_attach(GTK_GRID(grid), hbox1, 0, row, 2, 1);
    row++;

    /* Check interval. */
    GtkWidget *hbox2 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    pd->spin_interval = gtk_spin_button_new_with_range(10, 3600, 10);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(pd->spin_interval),
                              pd->app->check_interval_secs);
    gtk_box_pack_start(GTK_BOX(hbox2),
        gtk_label_new("Check ticket status every"), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hbox2), pd->spin_interval, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hbox2),
        gtk_label_new("seconds"), FALSE, FALSE, 0);
    gtk_grid_attach(GTK_GRID(grid), hbox2, 0, row, 2, 1);
    row++;

    /* Autostart. */
    pd->check_autostart =
        gtk_check_button_new_with_mnemonic("_Start automatically on login");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(pd->check_autostart),
                                 pd->app->autostart);
    gtk_grid_attach(GTK_GRID(grid), pd->check_autostart, 0, row, 2, 1);

    return grid;
}

/* Construct the Principals tab with a list view of managed principals and
 * a toolbar for add, remove, authenticate, and clear-password actions. */
static GtkWidget *build_principals_page(PrefsData *pd)
{
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);

    /* List store + view. */
    pd->store = gtk_list_store_new(N_COLS,
        G_TYPE_STRING,   /* COL_PRINCIPAL   */
        G_TYPE_STRING,   /* COL_STATE_STR   */
        G_TYPE_BOOLEAN,  /* COL_STORE_PW    */
        G_TYPE_BOOLEAN   /* COL_AUTO_KINIT  */
    );

    pd->tree_view = gtk_tree_view_new_with_model(GTK_TREE_MODEL(pd->store));
    g_object_unref(pd->store);

    /* Column: Principal. */
    GtkCellRenderer *r_text = gtk_cell_renderer_text_new();
    GtkTreeViewColumn *col_p =
        gtk_tree_view_column_new_with_attributes(
            "Principal", r_text, "text", COL_PRINCIPAL, NULL);
    gtk_tree_view_column_set_expand(col_p, TRUE);
    gtk_tree_view_append_column(GTK_TREE_VIEW(pd->tree_view), col_p);

    /* Column: State. */
    GtkCellRenderer *r_state = gtk_cell_renderer_text_new();
    gtk_tree_view_append_column(GTK_TREE_VIEW(pd->tree_view),
        gtk_tree_view_column_new_with_attributes(
            "State", r_state, "text", COL_STATE_STR, NULL));

    /* Column: Store password (toggle). */
    GtkCellRenderer *r_pw = gtk_cell_renderer_toggle_new();
    g_signal_connect(r_pw, "toggled",
                     G_CALLBACK(on_store_pw_toggled), pd);
    gtk_tree_view_append_column(GTK_TREE_VIEW(pd->tree_view),
        gtk_tree_view_column_new_with_attributes(
            "Store password", r_pw, "active", COL_STORE_PW, NULL));

    /* Column: Auto kinit (toggle). */
    GtkCellRenderer *r_ak = gtk_cell_renderer_toggle_new();
    g_signal_connect(r_ak, "toggled",
                     G_CALLBACK(on_auto_kinit_toggled), pd);
    gtk_tree_view_append_column(GTK_TREE_VIEW(pd->tree_view),
        gtk_tree_view_column_new_with_attributes(
            "Auto kinit", r_ak, "active", COL_AUTO_KINIT, NULL));

    /* Scrolled window around the tree view. */
    GtkWidget *sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_size_request(sw, -1, 180);
    gtk_container_add(GTK_CONTAINER(sw), pd->tree_view);
    gtk_box_pack_start(GTK_BOX(vbox), sw, TRUE, TRUE, 0);

    /* Toolbar. */
    GtkWidget *toolbar = gtk_toolbar_new();
    gtk_toolbar_set_style(GTK_TOOLBAR(toolbar), GTK_TOOLBAR_TEXT);
    gtk_box_pack_start(GTK_BOX(vbox), toolbar, FALSE, FALSE, 0);

    GtkToolItem *btn_add = gtk_tool_button_new(NULL, "Add Principal…");
    gtk_toolbar_insert(GTK_TOOLBAR(toolbar), btn_add, -1);
    g_signal_connect(btn_add, "clicked",
                     G_CALLBACK(on_add_principal), pd);

    pd->btn_remove = GTK_WIDGET(gtk_tool_button_new(NULL, "Remove"));
    gtk_toolbar_insert(GTK_TOOLBAR(toolbar),
                       GTK_TOOL_ITEM(pd->btn_remove), -1);
    g_signal_connect(pd->btn_remove, "clicked",
                     G_CALLBACK(on_remove_principal), pd);

    pd->btn_auth = GTK_WIDGET(gtk_tool_button_new(NULL, "Authenticate…"));
    gtk_toolbar_insert(GTK_TOOLBAR(toolbar),
                       GTK_TOOL_ITEM(pd->btn_auth), -1);
    g_signal_connect(pd->btn_auth, "clicked",
                     G_CALLBACK(on_authenticate), pd);

    pd->btn_clear_pw = GTK_WIDGET(gtk_tool_button_new(NULL, "Clear Password"));
    gtk_toolbar_insert(GTK_TOOLBAR(toolbar),
                       GTK_TOOL_ITEM(pd->btn_clear_pw), -1);
    g_signal_connect(pd->btn_clear_pw, "clicked",
                     G_CALLBACK(on_clear_password), pd);

    /* Selection changed → button sensitivity. */
    GtkTreeSelection *sel =
        gtk_tree_view_get_selection(GTK_TREE_VIEW(pd->tree_view));
    g_signal_connect(sel, "changed",
                     G_CALLBACK(on_selection_changed), pd);
    on_selection_changed(sel, pd);   /* initial state */

    populate_store(pd);
    return vbox;
}

/* ── Public entry point ──────────────────────────────────────────────────── */

/* Show the modal Preferences dialog and, if the user clicks Apply, persist
 * and activate all changed settings. */
void krbtray_prefs_show(KrbTrayApp *app)
{
    PrefsData pd = { .app = app };

    GtkWidget *dialog = gtk_dialog_new_with_buttons(
        "Preferences",
        NULL,
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Apply",  GTK_RESPONSE_APPLY,
        NULL);
    gtk_window_set_default_size(GTK_WINDOW(dialog), 480, -1);

    GtkWidget *notebook = gtk_notebook_new();
    gtk_container_add(
        GTK_CONTAINER(gtk_dialog_get_content_area(GTK_DIALOG(dialog))),
        notebook);

    gtk_notebook_append_page(GTK_NOTEBOOK(notebook),
        build_general_page(&pd),
        gtk_label_new("General"));
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook),
        build_principals_page(&pd),
        gtk_label_new("Principals"));

    gtk_widget_show_all(dialog);

    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_APPLY) {
        /* Apply general settings. */
        app->renewal_threshold_mins =
            gtk_spin_button_get_value_as_int(
                GTK_SPIN_BUTTON(pd.spin_threshold));
        app->check_interval_secs =
            gtk_spin_button_get_value_as_int(
                GTK_SPIN_BUTTON(pd.spin_interval));

        gboolean new_autostart =
            gtk_toggle_button_get_active(
                GTK_TOGGLE_BUTTON(pd.check_autostart));
        if (new_autostart != app->autostart)
            krbtray_app_set_autostart(app, new_autostart);

        /* Apply per-principal toggle changes (already applied in-place). */
        krbtray_app_save_config(app);
        krbtray_app_restart_timer(app);
        krbtray_app_refresh(app);
    }

    gtk_widget_destroy(dialog);
}
