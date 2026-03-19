#include "keyring.h"

#define SECRET_API_SUBJECT_TO_CHANGE
#include <libsecret/secret.h>

/* ── Schema ──────────────────────────────────────────────────────────────── */

static const SecretSchema krbtray_schema = {
    "org.krbtray.Credentials",
    SECRET_SCHEMA_NONE,
    {
        { "principal", SECRET_SCHEMA_ATTRIBUTE_STRING },
        { NULL, 0 },
    },
    0, NULL, NULL, NULL, NULL, NULL, NULL, NULL  /* reserved fields */
};

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static gchar *label_for(const gchar *principal_name)
{
    return g_strdup_printf("Kerberos password for %s", principal_name);
}

/* ── Public API ──────────────────────────────────────────────────────────── */

gboolean krbtray_keyring_store_password(const gchar *principal_name,
                                        const gchar *password)
{
    gchar  *label = label_for(principal_name);
    GError *err   = NULL;

    gboolean ok = secret_password_store_sync(
        &krbtray_schema,
        SECRET_COLLECTION_DEFAULT,
        label,
        password,
        NULL,  /* cancellable */
        &err,
        "principal", principal_name,
        NULL);

    if (!ok && err) {
        g_warning("krbtray: keyring store failed: %s", err->message);
        g_clear_error(&err);
    }
    g_free(label);
    return ok;
}

gchar *krbtray_keyring_lookup_password(const gchar *principal_name)
{
    GError *err = NULL;
    gchar  *pw  = secret_password_lookup_sync(
        &krbtray_schema,
        NULL,  /* cancellable */
        &err,
        "principal", principal_name,
        NULL);

    if (err) {
        g_warning("krbtray: keyring lookup failed: %s", err->message);
        g_clear_error(&err);
        return NULL;
    }
    return pw;   /* caller must g_free(); libsecret uses g_malloc */
}

gboolean krbtray_keyring_delete_password(const gchar *principal_name)
{
    GError  *err = NULL;
    gboolean ok  = secret_password_clear_sync(
        &krbtray_schema,
        NULL,
        &err,
        "principal", principal_name,
        NULL);

    if (err) {
        g_warning("krbtray: keyring delete failed: %s", err->message);
        g_clear_error(&err);
    }
    return ok;
}
