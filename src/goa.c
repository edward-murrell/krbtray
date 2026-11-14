#include "goa.h"

#include <gio/gio.h>

#define GOA_BUS_NAME      "org.gnome.OnlineAccounts"
#define GOA_OBJECT_PATH   "/org/gnome/OnlineAccounts"
#define GOA_ACCOUNT_IFACE "org.gnome.OnlineAccounts.Account"

/* TRUE if krbtray tracks principal_name, either as a managed principal or
 * because it holds tickets. */
static gboolean app_tracks(KrbTrayApp *app, const gchar *principal_name)
{
    for (GList *l = app->entries; l; l = l->next) {
        KrbPrincipalEntry *e = l->data;
        if (g_strcmp0(e->principal_name, principal_name) == 0)
            return e->managed || e->has_tickets;
    }
    return FALSE;
}

/* Read a string property from a proxy's cache.  Caller frees. */
static gchar *cached_string(GDBusProxy *proxy, const gchar *name)
{
    GVariant *v = g_dbus_proxy_get_cached_property(proxy, name);
    if (!v) return NULL;
    gchar *s = g_variant_dup_string(v, NULL);
    g_variant_unref(v);
    return s;
}

/* Read a boolean property from a proxy's cache.  Missing reads as FALSE. */
static gboolean cached_bool(GDBusProxy *proxy, const gchar *name)
{
    GVariant *v = g_dbus_proxy_get_cached_property(proxy, name);
    if (!v) return FALSE;
    gboolean b = g_variant_get_boolean(v);
    g_variant_unref(v);
    return b;
}

/* Report a failed property write.  GOA may refuse a locked account, which
 * is not worth troubling the user about. */
static void on_set_done(GObject *source, GAsyncResult *res, gpointer data)
{
    (void)data;
    GError   *err = NULL;
    GVariant *ret = g_dbus_proxy_call_finish(G_DBUS_PROXY(source), res, &err);
    if (ret)
        g_variant_unref(ret);
    if (err) {
        g_message("krbtray: could not turn off GNOME Online Accounts "
                  "ticketing: %s", err->message);
        g_error_free(err);
    }
}

/* Turn off GOA ticketing on one account if it is a Kerberos account for a
 * principal krbtray tracks and ticketing is still on. */
static void handle_account(KrbTrayApp *app, GDBusProxy *account)
{
    if (cached_bool(account, "TicketingDisabled"))
        return;

    gchar *provider = cached_string(account, "ProviderType");
    gchar *identity = cached_string(account, "Identity");

    if (g_strcmp0(provider, "kerberos") == 0 && identity &&
        app_tracks(app, identity)) {
        /* The Properties interface is called directly, since a generic
         * proxy's set only updates its local cache. */
        g_dbus_proxy_call(account,
            "org.freedesktop.DBus.Properties.Set",
            g_variant_new("(ssv)", GOA_ACCOUNT_IFACE, "TicketingDisabled",
                          g_variant_new_boolean(TRUE)),
            G_DBUS_CALL_FLAGS_NONE, -1, NULL, on_set_done, NULL);
    }
    g_free(provider);
    g_free(identity);
}

/* Look at every account GOA currently exposes. */
void krbtray_goa_sync(KrbTrayApp *app)
{
    if (!app->goa_manager)
        return;

    GList *objects = g_dbus_object_manager_get_objects(app->goa_manager);
    for (GList *l = objects; l; l = l->next) {
        GDBusInterface *iface =
            g_dbus_object_get_interface(l->data, GOA_ACCOUNT_IFACE);
        if (iface) {
            handle_account(app, G_DBUS_PROXY(iface));
            g_object_unref(iface);
        }
    }
    g_list_free_full(objects, g_object_unref);
}

/* GOA added the account interface to an existing object.  New accounts
 * normally arrive through on_object_added instead. */
static void on_interface_added(GDBusObjectManager *manager,
                               GDBusObject        *object,
                               GDBusInterface     *iface,
                               gpointer            data)
{
    (void)manager; (void)object;
    if (g_strcmp0(g_dbus_proxy_get_interface_name(G_DBUS_PROXY(iface)),
                  GOA_ACCOUNT_IFACE) == 0)
        handle_account(data, G_DBUS_PROXY(iface));
}

/* GOA added a whole account object, which is how a new account arrives. */
static void on_object_added(GDBusObjectManager *manager,
                            GDBusObject        *object,
                            gpointer            data)
{
    (void)manager;
    GDBusInterface *iface = g_dbus_object_get_interface(object,
                                                        GOA_ACCOUNT_IFACE);
    if (iface) {
        handle_account(data, G_DBUS_PROXY(iface));
        g_object_unref(iface);
    }
}

/* The object manager is ready.  Watch for new accounts and handle the ones
 * that already exist. */
static void on_manager_ready(GObject *source, GAsyncResult *res, gpointer data)
{
    (void)source;
    KrbTrayApp *app = data;
    GError     *err = NULL;

    app->goa_manager = g_dbus_object_manager_client_new_for_bus_finish(res, &err);
    if (!app->goa_manager) {
        g_message("krbtray: GNOME Online Accounts not watched: %s",
                  err->message);
        g_error_free(err);
        return;
    }
    g_signal_connect(app->goa_manager, "object-added",
                     G_CALLBACK(on_object_added), app);
    g_signal_connect(app->goa_manager, "interface-added",
                     G_CALLBACK(on_interface_added), app);
    krbtray_goa_sync(app);
}

/* Connect to GOA without starting it.  If GOA starts later, its accounts
 * arrive through interface-added. */
void krbtray_goa_init(KrbTrayApp *app)
{
    g_dbus_object_manager_client_new_for_bus(
        G_BUS_TYPE_SESSION,
        G_DBUS_OBJECT_MANAGER_CLIENT_FLAGS_DO_NOT_AUTO_START,
        GOA_BUS_NAME, GOA_OBJECT_PATH,
        NULL, NULL, NULL, NULL, on_manager_ready, app);
}

/* Drop the connection to GOA. */
void krbtray_goa_uninit(KrbTrayApp *app)
{
    g_clear_object(&app->goa_manager);
}
