# krbtray — Claude guidance

## Code conventions

### Comments
- All functions must have a doc comment (placed immediately above the function definition, not the declaration).
- Document **intent** ("why / what"), not implementation ("how"). Be concise — one or two sentences is the norm.
- Language: English (UK spelling).
- Update existing comments whenever the function's behaviour changes.

### Internationalisation
- All user-visible strings must be wrapped with `_()` (from `<glib/gi18n.h>`).
- UK English is the built-in default (source strings are UK English; no `.po` file needed for `en_GB`).
- Translation files live in `po/`.  Add a new `msgid`/`msgstr` pair to every `.po` file whenever a new user-visible string is introduced.
- The `.pot` template (`po/krbtray.pot`) must be kept in sync with the source.
- `msgfmt` compiles `.po` → `.mo` at build time via CMake; the `translations` target must remain a dependency of the `krbtray` target.

### Error messages
- Kerberos error codes that produce confusing raw messages should be intercepted and replaced with plain English.  Known mappings:
  - `KRB5KDC_ERR_PREAUTH_FAILED` / `KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN` → "Current password is incorrect."
  - `KRB5KDC_ERR_KEY_EXPIRED` → triggers the Change Password dialog (see below); never shown as raw text.

## Architecture decisions

### Authentication flow (`krbtray_app_authenticate`)
When the user clicks "Authenticate" for a principal that already has a stored keyring password, the application silently attempts kinit with that password first.  The interactive dialog is only shown if:
- no password is stored, or
- the silent kinit fails for any reason other than `KRB5KDC_ERR_KEY_EXPIRED`.

All "Authenticate" entry points (tray menu, Preferences toolbar) must go through `krbtray_app_authenticate()` in `app.c`, not call `krbtray_kinit_dialog_run()` directly.

### Forced password change (`KRB5KDC_ERR_KEY_EXPIRED`)
Wherever kinit is called and `KRB5KDC_ERR_KEY_EXPIRED` is returned, the Change Password dialog must be opened immediately with `must_change = TRUE`.  This applies to:
- Manual authentication via the kinit dialog (`kinit_dialog.c`).
- Startup / power-resume auto-kinit (`app.c`, `krbtray_app_refresh` step 5).

### Power resume
The application subscribes to the systemd-logind `org.freedesktop.login1.Manager.PrepareForSleep` D-Bus signal.  On resume (`going_to_sleep == FALSE`), `auto_kinit` is re-armed for all managed principals that have a stored password, and an immediate refresh is triggered.

### Auto-kinit scope
Step 5 of `krbtray_app_refresh` attempts auto-kinit when `needs_new_creds` is true, defined as:
- the principal has no tickets at all, **or**
- the principal has tickets but they are in `KRB_STATE_EXPIRED` (expired and no longer renewable).

### New source files
| File | Purpose |
|------|---------|
| `src/passwd_dialog.c/h` | Change Password dialog |

`passwd_dialog.c` must be listed in the `SOURCES` set in `CMakeLists.txt`.

## Build system notes
- Requires `gettext` (provides `msgfmt`) in addition to the existing dependencies.  Already listed in `debian/control` Build-Depends.
- `GETTEXT_PACKAGE` is defined as `"krbtray"`; `LOCALEDIR` resolves to `CMAKE_INSTALL_FULL_LOCALEDIR` at compile time.
- GIO (`<gio/gio.h>`) is used for D-Bus (power-resume monitoring); it is a transitive dependency of GTK3 and requires no extra `pkg_check_modules` entry.
