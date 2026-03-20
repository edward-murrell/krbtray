#include <gtk/gtk.h>
#include <locale.h>
#include <stdlib.h>

#include "app.h"

/* Entry point. Initialises locale and GTK, creates the application, then
 * hands control to the GTK event loop until the user quits. */
int main(int argc, char *argv[])
{
    setlocale(LC_ALL, "");
    gtk_init(&argc, &argv);

    KrbTrayApp *app = krbtray_app_new();
    if (!app) {
        g_printerr("krbtray: failed to initialise – is Kerberos configured?\n");
        return EXIT_FAILURE;
    }

    krbtray_app_run(app);

    gtk_main();

    krbtray_app_free(app);
    return EXIT_SUCCESS;
}
