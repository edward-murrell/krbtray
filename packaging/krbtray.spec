# Built by packaging/build-rpm.sh, which passes --define "pkg_version <x.y.z>".
Name:           krbtray
Version:        %{pkg_version}
Release:        1%{?dist}
Summary:        Kerberos TGT management system tray icon

License:        MIT
URL:            https://github.com/edward-murrell/krbtray
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cmake
BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  gettext
BuildRequires:  pkgconfig(gtk+-3.0)
BuildRequires:  pkgconfig(libsecret-1)
BuildRequires:  pkgconfig(libnotify)
BuildRequires:  krb5-devel

%description
krbtray sits in the system tray and monitors the state of all Kerberos
Ticket-Granting Tickets (TGTs) in the credential cache collection. It renews
tickets before they expire, notifies on renewal failure, offers a GTK dialog
for obtaining new tickets, and can store the password in the Secret Service
keyring to re-authenticate automatically.

The icon uses GtkStatusIcon (an X11 system tray icon). Cinnamon, MATE and
XFCE show it natively; GNOME needs the AppIndicator and KStatusNotifierItem
Support extension. See README.md for details.

%prep
%autosetup

%build
%cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo
%cmake_build

%install
%cmake_install
%find_lang %{name}

%files -f %{name}.lang
%license LICENSE
%doc README.md CHANGELOG.md
%{_bindir}/krbtray
%{_datadir}/applications/krbtray.desktop

%changelog
* Tue Nov 03 2026 Edward Murrell <edward@murrell.co.nz> - %{version}-%{release}
- Automated build; see CHANGELOG.md for upstream changes.
