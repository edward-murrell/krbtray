#include "notify.h"

#include <libnotify/notify.h>
#include <glib.h>
#include <glib/gi18n.h>

/* Initialise the libnotify library.  Must be called before any notifications
 * are shown. */
void krbtray_notify_init(void)
{
    notify_init("krbtray");
}

/* Clean up libnotify resources on application exit. */
void krbtray_notify_uninit(void)
{
    notify_uninit();
}

/* Send a critical desktop notification to alert the user that automatic
 * ticket renewal failed and manual intervention is required. */
void krbtray_notify_renewal_failed(const gchar *principal_name,
                                   const gchar *error_message)
{
    gchar *body = g_strdup_printf(
        _("Could not renew Kerberos tickets for <b>%s</b>.\n%s"),
        principal_name,
        error_message ? error_message : _("Unknown error."));

    NotifyNotification *n = notify_notification_new(
        _("Kerberos Renewal Failed"), body, "security-low");
    notify_notification_set_urgency(n, NOTIFY_URGENCY_CRITICAL);

    GError *err = NULL;
    if (!notify_notification_show(n, &err)) {
        g_warning("krbtray: notification failed: %s", err->message);
        g_clear_error(&err);
    }
    g_object_unref(n);
    g_free(body);
}
