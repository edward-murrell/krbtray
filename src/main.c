#include <gtk/gtk.h>
#include <locale.h>
#include <stdlib.h>

#include "app.h"

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
