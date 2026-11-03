cmake_minimum_required(VERSION 3.16)
project(krbtray VERSION 1.1.3 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)

# Must come before any use of CMAKE_INSTALL_*DIR — in particular the
# LOCALEDIR compile definition and the .mo install rules below, which
# silently resolve to empty paths if these variables are not yet defined.
include(GNUInstallDirs)

pkg_check_modules(GTK3       REQUIRED gtk+-3.0)
pkg_check_modules(LIBSECRET  REQUIRED libsecret-1)
pkg_check_modules(LIBNOTIFY  REQUIRED libnotify)

# Kerberos: Heimdal (Debian/Ubuntu/Mint) or MIT (Fedora/RHEL).
#   Debian/Ubuntu/Mint:  apt install heimdal-dev libnotify-dev libsecret-1-dev
#   Fedora/RHEL:         dnf install krb5-devel libnotify-devel libsecret-devel
#
# Prefer the Heimdal-specific pkg-config name so we don't accidentally pick up
# MIT krb5 when both are installed (heimdal-multidev provides krb5.pc too).
# Exactly one of KRBTRAY_HEIMDAL / KRBTRAY_MIT is defined for the sources.
pkg_check_modules(KRB5 heimdal-krb5)
if(KRB5_FOUND)
    set(KRBTRAY_KRB5_IMPL HEIMDAL)
else()
    # Fall back to the krb5-config helper, which both implementations ship,
    # and ask it which one it belongs to.
    find_program(KRB5_CONFIG NAMES krb5-config heimdal-krb5-config REQUIRED)
    execute_process(
        COMMAND ${KRB5_CONFIG} --vendor
        OUTPUT_VARIABLE KRB5_VENDOR
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(KRB5_VENDOR MATCHES "Heimdal")
        set(KRBTRAY_KRB5_IMPL HEIMDAL)
    else()
        set(KRBTRAY_KRB5_IMPL MIT)
    endif()
    execute_process(
        COMMAND ${KRB5_CONFIG} --libs krb5
        OUTPUT_VARIABLE KRB5_LINK_LIBRARIES
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(
        COMMAND ${KRB5_CONFIG} --cflags krb5
        OUTPUT_VARIABLE KRB5_CFLAGS_OTHER
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    separate_arguments(KRB5_LINK_LIBRARIES UNIX_COMMAND "${KRB5_LINK_LIBRARIES}")
    separate_arguments(KRB5_CFLAGS_OTHER   UNIX_COMMAND "${KRB5_CFLAGS_OTHER}")
endif()
message(STATUS "Kerberos implementation: ${KRBTRAY_KRB5_IMPL}")

set(SOURCES
    src/main.c
    src/app.c
    src/kerberos.c
    src/tray.c
    src/keyring.c
    src/kinit_dialog.c
    src/passwd_dialog.c
    src/prefs.c
    src/notify.c
)

add_executable(krbtray ${SOURCES})

# ── Internationalisation ──────────────────────────────────────────────────────
find_program(MSGFMT_EXECUTABLE msgfmt REQUIRED)

set(GETTEXT_PACKAGE "krbtray")

# During a normal install the .mo files live under the system locale dir.
# When building a Debian package CMAKE_INSTALL_FULL_LOCALEDIR resolves to
# the correct path (/usr/share/locale) automatically.
add_compile_definitions(
    GETTEXT_PACKAGE="${GETTEXT_PACKAGE}"
    LOCALEDIR="${CMAKE_INSTALL_FULL_LOCALEDIR}"
    KRBTRAY_VERSION="${CMAKE_PROJECT_VERSION}"
    KRBTRAY_${KRBTRAY_KRB5_IMPL}
)

set(LANGUAGES en_US es fr de)
set(MO_FILES "")
foreach(LANG IN LISTS LANGUAGES)
    set(PO_FILE  "${CMAKE_CURRENT_SOURCE_DIR}/po/${LANG}.po")
    set(MO_DIR   "${CMAKE_CURRENT_BINARY_DIR}/po/${LANG}/LC_MESSAGES")
    set(MO_FILE  "${MO_DIR}/${GETTEXT_PACKAGE}.mo")
    add_custom_command(
        OUTPUT  "${MO_FILE}"
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${MO_DIR}"
        COMMAND "${MSGFMT_EXECUTABLE}" -o "${MO_FILE}" "${PO_FILE}"
        DEPENDS "${PO_FILE}"
        COMMENT "Compiling ${LANG} translation"
    )
    list(APPEND MO_FILES "${MO_FILE}")
    install(FILES "${MO_FILE}"
        DESTINATION "${CMAKE_INSTALL_LOCALEDIR}/${LANG}/LC_MESSAGES")
endforeach()

add_custom_target(translations ALL DEPENDS ${MO_FILES})
add_dependencies(krbtray translations)

target_include_directories(krbtray PRIVATE
    src
    ${GTK3_INCLUDE_DIRS}
    ${LIBSECRET_INCLUDE_DIRS}
    ${LIBNOTIFY_INCLUDE_DIRS}
    ${KRB5_INCLUDE_DIRS}
)

target_compile_options(krbtray PRIVATE
    ${GTK3_CFLAGS_OTHER}
    ${LIBSECRET_CFLAGS_OTHER}
    ${LIBNOTIFY_CFLAGS_OTHER}
    ${KRB5_CFLAGS_OTHER}
    -Wall -Wextra -Wno-deprecated-declarations
)

target_link_directories(krbtray PRIVATE
    ${GTK3_LIBRARY_DIRS}
    ${LIBSECRET_LIBRARY_DIRS}
    ${LIBNOTIFY_LIBRARY_DIRS}
    ${KRB5_LIBRARY_DIRS}
)

target_link_libraries(krbtray PRIVATE
    ${GTK3_LIBRARIES}
    ${LIBSECRET_LIBRARIES}
    ${LIBNOTIFY_LIBRARIES}
    ${KRB5_LIBRARIES}
    ${KRB5_LINK_LIBRARIES}
)

# ── Install ──────────────────────────────────────────────────────────────────
# GNUInstallDirs is included near the top, before its first use.

install(TARGETS krbtray
    DESTINATION ${CMAKE_INSTALL_BINDIR})

# Application .desktop file (for app menus / launchers)
configure_file(
    data/krbtray.desktop.in
    ${CMAKE_BINARY_DIR}/krbtray.desktop
    @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/krbtray.desktop
    DESTINATION ${CMAKE_INSTALL_DATADIR}/applications)
