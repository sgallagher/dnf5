# use any sources found under the current directory
file(GLOB_RECURSE LIBDNF5_SOURCES *.cpp *.c)

# create config header file
configure_file("config.h.in" ${CMAKE_CURRENT_SOURCE_DIR}/conf/config.h)

# gather all pkg-config requires and write them to a .pc file later
list(APPEND LIBDNF5_PC_REQUIRES)
list(APPEND LIBDNF5_PC_REQUIRES_PRIVATE)

# set gettext domain for translations
set(GETTEXT_DOMAIN libdnf5)
add_definitions(-DGETTEXT_DOMAIN=\"${GETTEXT_DOMAIN}\")

# If defined, libsolv adds the prefix "dep_" to solvable dependencies.
# As a result, `requires` is renamed to `dep_requires`.
# Needed for C++20. `requires` is a keyword in C++20.
add_definitions(-DLIBSOLV_SOLVABLE_PREPEND_DEP)

include_directories(.)

# build libdnf5.so
add_library(libdnf5 SHARED ${LIBDNF5_SOURCES})
set(DNF_SO_VERSION 1)
set_target_properties(libdnf5 PROPERTIES OUTPUT_NAME "dnf5")
set_target_properties(libdnf5 PROPERTIES SOVERSION ${DNF_SO_VERSION})
# required to have dlopen symbol
target_link_libraries(libdnf5 ${CMAKE_DL_LIBS})

# required by clang
target_link_libraries(libdnf5 stdc++)

# link stdc++fs to make experimental std::filesystem available on gcc 8:
# https://gcc.gnu.org/onlinedocs/libstdc++/manual/using.html
target_link_libraries(libdnf5 stdc++fs)

# install libdnf5.so
install(TARGETS libdnf5 LIBRARY DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR})

target_link_libraries(libdnf5 common)

# link libraries and set pkg-config requires

find_package(toml11 REQUIRED)

pkg_check_modules(LIBFMT REQUIRED fmt)
list(APPEND LIBDNF5_PC_REQUIRES "${LIBFMT_MODULE_NAME}")
target_link_libraries(libdnf5 ${LIBFMT_LIBRARIES})

pkg_check_modules(JSONC REQUIRED json-c)
include_directories(${JSONC_INCLUDE_DIRS})
target_link_libraries(libdnf5 ${JSONC_LIBRARIES})

pkg_check_modules(LIBMODULEMD REQUIRED modulemd-2.0>=2.11.2)
list(APPEND LIBDNF5_PC_REQUIRES "${LIBMODULEMD_MODULE_NAME}")
target_link_libraries(libdnf5 ${LIBMODULEMD_LIBRARIES})

pkg_check_modules(LIBSOLV REQUIRED libsolv>=0.7.21)
list(APPEND LIBDNF5_PC_REQUIRES "${LIBSOLV_MODULE_NAME}")
target_link_libraries(libdnf5 ${LIBSOLV_LIBRARIES})

pkg_check_modules(LIBSOLVEXT REQUIRED libsolvext>=0.7.7)
list(APPEND LIBDNF5_PC_REQUIRES_PRIVATE "${LIBSOLVEXT_MODULE_NAME}")
target_link_libraries(libdnf5 ${LIBSOLVEXT_LIBRARIES})

pkg_check_modules(RPM REQUIRED rpm>=4.17.0)
list(APPEND LIBDNF5_PC_REQUIRES "${RPM_MODULE_NAME}")
target_link_libraries(libdnf5 ${RPM_LIBRARIES})

if(WITH_COMPS)
    pkg_check_modules(LIBXML2 REQUIRED libxml-2.0)
    list(APPEND LIBDNF5_PC_REQUIRES_PRIVATE "${LIBXML2_MODULE_NAME}")
    include_directories(${LIBXML2_INCLUDE_DIRS})
    target_link_libraries(libdnf5 ${LIBXML2_LIBRARIES})
endif()

if (WITH_ZCHUNK)
    pkg_check_modules(ZCHUNKLIB zck>=0.9.11 REQUIRED)
    add_definitions(-DWITH_ZCHUNK)
endif()

# GLIB librepo and libmodulemd uses glib2 in API :(
pkg_check_modules (GLIB2 glib-2.0>=2.46.0)
include_directories(${GLIB2_INCLUDE_DIRS})
target_link_libraries(libdnf5 ${GLIB2_LIBRARIES})

pkg_check_modules(LIBREPO REQUIRED librepo>=1.15.0)
list(APPEND LIBDNF5_PC_REQUIRES "${LIBREPO_MODULE_NAME}")
target_include_directories(libdnf5 PRIVATE ${LIBREPO_INCLUDE_DIRS})
target_link_libraries(libdnf5 ${LIBREPO_LDFLAGS})

# SQLite3
pkg_check_modules(SQLite3 REQUIRED sqlite3>=3.35.0)
list(APPEND LIBDNF5_PC_REQUIRES "${SQLite3_MODULE_NAME}")
target_link_libraries(libdnf5 ${SQLite3_LIBRARIES})


# sort the pkg-config requires and concatenate them into a string
list(SORT LIBDNF5_PC_REQUIRES)
list(JOIN LIBDNF5_PC_REQUIRES ", " LIBDNF5_PC_REQUIRES_STRING)
list(SORT LIBDNF5_PC_REQUIRES_PRIVATE)
list(JOIN LIBDNF5_PC_REQUIRES_PRIVATE ", " LIBDNF5_PC_REQUIRES_PRIVATE_STRING)


# create a .pc file
configure_file("libdnf5.pc.in" ${CMAKE_CURRENT_BINARY_DIR}/libdnf5.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libdnf5.pc DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR}/pkgconfig)

# Makes an empty directory for libdnf5 cache
install(DIRECTORY DESTINATION ${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/cache/libdnf5)


add_subdirectory(po)
