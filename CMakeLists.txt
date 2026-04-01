cmake_minimum_required(VERSION 3.16)
project(krbtray VERSION 1.1.1 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)

pkg_check_modules(GTK3       REQUIRED gtk+-3.0)
pkg_check_modules(LIBSECRET  REQUIRED libsecret-1)
pkg_check_modules(LIBNOTIFY  REQUIRED libnotify)

# Heimdal Kerberos.
# On Debian/Ubuntu/Mint:  apt install heimdal-dev libnotify-dev libsecret-1-dev
#
# Prefer the Heimdal-specific pkg-config name so we don't accidentally pick up
# MIT krb5 when both are installed (heimdal-multidev provides mit-krb5 too).
pkg_check_modules(HEIMDAL heimdal-krb5)
if(NOT HEIMDAL_FOUND)
    # Fall back to the generic krb5-config helper.
    find_program(KRB5_CONFIG NAMES krb5-config heimdal-krb5-config REQUIRED)
    execute_process(
        COMMAND ${KRB5_CONFIG} --libs krb5
        OUTPUT_VARIABLE HEIMDAL_LINK_LIBRARIES
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(
        COMMAND ${KRB5_CONFIG} --cflags
        OUTPUT_VARIABLE HEIMDAL_CFLAGS_OTHER
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    separate_arguments(HEIMDAL_LINK_LIBRARIES UNIX_COMMAND "${HEIMDAL_LINK_LIBRARIES}")
    separate_arguments(HEIMDAL_CFLAGS_OTHER   UNIX_COMMAND "${HEIMDAL_CFLAGS_OTHER}")
    set(HEIMDAL_FOUND TRUE)
endif()

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
    ${HEIMDAL_INCLUDE_DIRS}
)

target_compile_options(krbtray PRIVATE
    ${GTK3_CFLAGS_OTHER}
    ${LIBSECRET_CFLAGS_OTHER}
    ${LIBNOTIFY_CFLAGS_OTHER}
    ${HEIMDAL_CFLAGS_OTHER}
    -Wall -Wextra -Wno-deprecated-declarations
)

target_link_directories(krbtray PRIVATE
    ${GTK3_LIBRARY_DIRS}
    ${LIBSECRET_LIBRARY_DIRS}
    ${LIBNOTIFY_LIBRARY_DIRS}
    ${HEIMDAL_LIBRARY_DIRS}
)

target_link_libraries(krbtray PRIVATE
    ${GTK3_LIBRARIES}
    ${LIBSECRET_LIBRARIES}
    ${LIBNOTIFY_LIBRARIES}
    ${HEIMDAL_LIBRARIES}
    ${HEIMDAL_LINK_LIBRARIES}
)

# ── Install ──────────────────────────────────────────────────────────────────
include(GNUInstallDirs)

install(TARGETS krbtray
    DESTINATION ${CMAKE_INSTALL_BINDIR})

# Application .desktop file (for app menus / launchers)
configure_file(
    data/krbtray.desktop.in
    ${CMAKE_BINARY_DIR}/krbtray.desktop
    @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/krbtray.desktop
    DESTINATION ${CMAKE_INSTALL_DATADIR}/applications)
