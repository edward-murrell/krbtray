# Changelog

All notable changes to krbtray are documented here.

## [1.1.1] – 2026-04-01

- Fix spurious "Kerberos Renewal Failed" notification after resuming from sleep
  when tickets have fully expired (renewal window closed).  The renewal step now
  checks `renew_till` before attempting renewal; expired-and-non-renewable
  tickets fall through to auto-kinit silently.

## [1.1.0] – 2026-03-21

- Add function comments throughout (intent-based, English).
- Expired credentials: auto-kinit now triggers on expired tickets (not just
  missing ones) at startup and after power resume.
- Power resume: subscribe to logind PrepareForSleep D-Bus signal; on resume,
  re-arm auto-kinit for all managed principals with stored passwords and trigger
  an immediate refresh.
- Add Change Password feature: new `krbtray_krb_change_password()` using the
  RFC 3244 kadmin/changepw protocol, with a dedicated dialog (current password,
  new password, confirm).  Updates keyring on success and re-authenticates to
  obtain a fresh TGT.  Accessible from both the tray context menu and the
  Preferences > Principals toolbar.
- Forced password change: detect `KRB5KDC_ERR_KEY_EXPIRED` during manual
  authentication and during startup auto-kinit; automatically open the Change
  Password dialog with a prominent must-change notice.
- Authenticate: when a stored keyring password exists, use it silently; only
  fall back to the interactive dialog on failure.
- Fix misleading "Preauthentication failed" error in the Change Password dialog;
  now shown as "Current password is incorrect."
- Add internationalisation (gettext): UK English is the built-in default;
  translations provided for American English (en_US), Spanish (es), French (fr),
  and German (de).
- Add .gitignore.

## [1.0.0] – 2026-03-19

Initial release.

- System tray icon reflecting the worst-case Kerberos ticket state across all
  principals: green (valid), yellow (expiring soon), red (expired or no
  tickets).
- Tooltip listing every tracked principal and its remaining ticket lifetime.
- Multiple-principal support: scans the full credential cache collection
  (KCM / DIR ccache recommended for multi-principal use).
- Per-principal context menu with: Renew Now, Destroy Tickets, Authenticate,
  and Add Principal.
- Manual authentication dialog (kinit): accepts principal name and password,
  obtains a new TGT, and optionally saves the password to the Secret Service.
- Ticket renewal: extends the lifetime of a valid, renewable TGT in-place.
- Ticket destruction: prompts for confirmation then destroys all tickets for
  the selected principal.
- Auto-kinit: at startup, silently obtains a new TGT for managed principals
  that have a stored keyring password and currently have no tickets.
- Password storage via GNOME Keyring (libsecret Secret Service API), scoped
  per-principal under the `org.krbtray.Credentials` schema.
- Preferences dialog with two pages:
  - General: renewal threshold (minutes before expiry to flag as expiring),
    check interval (polling period), and autostart toggle.
  - Principals: add, remove, and configure managed principals; set
    store-password and auto-kinit flags per principal; authenticate or remove
    from here.
- Desktop notifications (libnotify) when automatic ticket renewal fails,
  displayed as critical urgency alerts.
- Autostart: creates or removes `~/.config/autostart/krbtray.desktop` to
  control whether krbtray launches at login.
- Periodic background polling at a configurable interval (default: 60 s).
- Configurable renewal threshold (default: 30 min before expiry).
- Configuration persisted in `~/.config/krbtray/krbtray.ini`.
