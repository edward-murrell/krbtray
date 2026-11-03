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

logind emits `PrepareForSleep(FALSE)` *before* NetworkManager has reconnected (delay inhibitors only apply to the going-to-sleep direction), so the refresh must never assume the network is up on resume.  See *Offline deferral* below.

### Offline deferral
`krbtray_app_refresh()` always performs the local steps (ccache scan, entry pruning, tray update), but the steps that contact the KDC — renewal (step 4) and auto-kinit (step 5) — are skipped while `g_network_monitor_get_network_available()` is false.  When skipped, `refresh_pending` is set and the refresh re-runs from the `GNetworkMonitor::network-changed` handler as soon as connectivity returns.

A 60-second fallback timer (`OFFLINE_REFRESH_TIMEOUT_SECS`) forces the network steps regardless, so an absent or inaccurate network monitor can never permanently prevent renewals.  `app_refresh_internal(app, force_network)` is the internal entry point; `force_network = TRUE` is used only by that timer.

### Transient vs. credential errors
`krbtray_krb_error_is_transient()` (`kerberos.c`) distinguishes "could not reach the KDC" from "the KDC rejected us".  Transient errors (`KRB5_KDC_UNREACH`, `KRB5_REALM_CANT_RESOLVE`, `KRB5_REALM_UNKNOWN`, `HEIM_ERR_NOHOST`, and the socket/resolver errnos Heimdal passes through) must **never** raise a notification or error dialog — they are retried silently on a later refresh.  Any new call site that reports a Kerberos failure to the user must filter through this helper.

Renewal failures that *are* genuine set `renewal_failure_notified` on the entry so the user is told once rather than on every check interval; a successful renewal or kinit clears it.

### Auto-kinit scope
Step 5 of `krbtray_app_refresh` attempts auto-kinit when `needs_new_creds` is true, defined as:
- the principal has no tickets at all, **or**
- the principal has tickets but they are in `KRB_STATE_EXPIRED` (expired and no longer renewable).

### New source files
| File | Purpose |
|------|---------|
| `src/passwd_dialog.c/h` | Change Password dialog |

`passwd_dialog.c` must be listed in the `SOURCES` set in `CMakeLists.txt`.

### Heimdal and MIT Kerberos
The code builds against both.  CMake defines exactly one of `KRBTRAY_HEIMDAL` (Debian/Ubuntu/Mint) or `KRBTRAY_MIT` (Fedora/RHEL); `kerberos.h` refuses to compile without one.  Keep implementation-specific code inside `kerberos.c` behind those macros, and keep Heimdal behaviour unchanged when adding MIT-only fixes.  Known differences:
- Ticket flags: Heimdal `creds.flags.b.renewable`, MIT `creds.ticket_flags & TKT_FLG_RENEWABLE`.
- `KRB5KDC_ERR_KEY_EXPIRED` is Heimdal's name; `kerberos.h` maps it to MIT's `KRB5KDC_ERR_KEY_EXP`.  Use the Heimdal name in sources.
- `krb5_data_zero` / `krb5_data_free` are Heimdal-only; MIT uses `krb5_free_data_contents`.
- Wrong-password detection goes through `krbtray_krb_error_is_bad_password()`; MIT also reports it as `KRB5KRB_AP_ERR_BAD_INTEGRITY`.
- On MIT, kinit for a principal with no cache creates a new cache in the collection (`krb5_cc_new_unique`) instead of overwriting the primary cache.

## Build system notes
- Requires `gettext` (provides `msgfmt`) in addition to the existing dependencies.  Already listed in `debian/control` Build-Depends.
- `GETTEXT_PACKAGE` is defined as `"krbtray"`; `LOCALEDIR` resolves to `CMAKE_INSTALL_FULL_LOCALEDIR` at compile time.
- `KRBTRAY_VERSION` is defined from `CMAKE_PROJECT_VERSION` at compile time; the About dialog reads this value.  The `project(VERSION ...)` line in `CMakeLists.txt` is the single source of truth for the version number.
- Packages are built natively per target release: `.deb` from `debian/` via `packaging/build-deb.sh`, `.rpm` from `packaging/krbtray.spec` via `packaging/build-rpm.sh`.  There is no CPack configuration — don't reintroduce one (hand-written dependency lists break on the `t64` library renames).  `.github/workflows/release.yml` builds and install-tests every target on amd64 and arm64 and publishes to the central `edward-murrell/packages` repository; the git tag must equal the `project(VERSION ...)` number.
- Version contract with the central repo: `.deb` versions are `<upstream>+<codename>` (added by `build-deb.sh`), `.rpm` uses `Release: 1%{?dist}`.  Never upload `-dbgsym` / `-debuginfo` / source packages.
- GIO (`<gio/gio.h>`) is used for D-Bus (power-resume monitoring); it is a transitive dependency of GTK3 and requires no extra `pkg_check_modules` entry.

## Documentation
- When build instructions, dependencies, or build commands change, update `README.md` to match.
