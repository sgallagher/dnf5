if(NOT WITH_DNF5DAEMON_SERVER)
    return()
endif()

set(DNF5DAEMON_SERVER_BIN dnf5daemon-server)
file(GLOB_RECURSE DNF5DAEMON_SERVER_SOURCES *.cpp)

# set gettext domain for translations
set(GETTEXT_DOMAIN dnf5daemon-server)
add_definitions(-DGETTEXT_DOMAIN=\"${GETTEXT_DOMAIN}\")

include_directories(.)

pkg_check_modules(SDBUS_CPP REQUIRED sdbus-c++)
find_package(Threads)

add_executable(${DNF5DAEMON_SERVER_BIN} ${DNF5DAEMON_SERVER_SOURCES})

target_link_libraries(
    ${DNF5DAEMON_SERVER_BIN}
    PUBLIC
        common
        libdnf5
        libdnf5-cli
        ${SDBUS_CPP_LIBRARIES}
        Threads::Threads
)

install(TARGETS ${DNF5DAEMON_SERVER_BIN} RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})


add_subdirectory(polkit)
add_subdirectory(dbus)
add_subdirectory(po)
