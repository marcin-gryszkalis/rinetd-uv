# CMake build configuration for rinetd-uv
# Alternative to the autotools build system (both can coexist)
#
# Quick start:
#   mkdir build && cd build
#   cmake ..
#   make
#   sudo make install
#
# Requirements:
#   - CMake >= 3.14
#   - libuv >= 1.0 (pkg-config: libuv)
#   - libyaml (pkg-config: yaml-0.1)
#   - Optional: leg (for regenerating parse.c from parse.peg)

cmake_minimum_required(VERSION 3.14)

# Read version from VERSION file
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" PACKAGE_VERSION)
string(STRIP "${PACKAGE_VERSION}" PACKAGE_VERSION)

# Extract numeric version for CMake (remove -dev, -rc, etc. suffixes)
string(REGEX REPLACE "([0-9]+\\.[0-9]+\\.[0-9]+).*" "\\1" NUMERIC_VERSION "${PACKAGE_VERSION}")

project(rinetd-uv VERSION ${NUMERIC_VERSION} LANGUAGES C)

# Require pkg-config for finding dependencies
find_package(PkgConfig REQUIRED)

# Find required libraries
pkg_check_modules(LIBUV REQUIRED libuv>=1.0)
pkg_check_modules(YAML REQUIRED yaml-0.1)

# Include check modules
include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckTypeSize)

# Check for functions
check_function_exists(daemon HAVE_DAEMON)
check_function_exists(fork HAVE_FORK)

# Check for headers
check_include_file(errno.h HAVE_ERRNO_H)

# Check for types
check_type_size(ssize_t SSIZE_T)
if(HAVE_SSIZE_T)
    set(HAVE_SSIZE_T 1)
endif()

check_type_size(socklen_t SOCKLEN_T)
if(HAVE_SOCKLEN_T)
    set(HAVE_SOCKLEN_T 1)
endif()

# Generate config.h
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/src/cmake_config.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/config.h"
    @ONLY
)

# Source files
set(RINETD_SOURCES
    src/rinetd.c
    src/log.c
    src/parse.c
    src/match.c
    src/net.c
    src/buffer_pool.c
    src/loadbalancer.c
    src/affinity.c
    src/yaml_config.c
    src/stats.c
)

# Header files (for IDE support)
set(RINETD_HEADERS
    src/rinetd.h
    src/log.h
    src/parse.h
    src/match.h
    src/net.h
    src/buffer_pool.h
    src/loadbalancer.h
    src/affinity.h
    src/yaml_config.h
    src/stats.h
    src/types.h
)

# Optional: Regenerate parse.c from parse.peg if leg is available
find_program(LEG_EXECUTABLE leg)
if(LEG_EXECUTABLE)
    add_custom_command(
        OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/src/parse.c"
        COMMAND ${LEG_EXECUTABLE} -o "${CMAKE_CURRENT_SOURCE_DIR}/src/parse.c" "${CMAKE_CURRENT_SOURCE_DIR}/src/parse.peg"
        DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/parse.peg"
        COMMENT "Generating parse.c from parse.peg using leg"
        VERBATIM
    )
else()
    message(STATUS "leg not found - will use existing parse.c (regeneration disabled)")
endif()

# Create executable
add_executable(rinetd-uv ${RINETD_SOURCES} ${RINETD_HEADERS})

# Include directories
target_include_directories(rinetd-uv PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR}
    ${LIBUV_INCLUDE_DIRS}
    ${YAML_INCLUDE_DIRS}
)

# Compiler options
target_compile_options(rinetd-uv PRIVATE
    -std=c99
    -Wall
    -Wextra
    -Wwrite-strings
)

# POSIX and platform feature macros
target_compile_definitions(rinetd-uv PRIVATE
    HAVE_CONFIG_H
    _POSIX_C_SOURCE=200809L
    _XOPEN_SOURCE
    _GNU_SOURCE
    _DARWIN_C_SOURCE
    _BSD_SOURCE
    _DEFAULT_SOURCE
    __BSD_VISIBLE
)

# Link libraries
target_link_libraries(rinetd-uv PRIVATE
    ${LIBUV_LIBRARIES}
    ${YAML_LIBRARIES}
)

# Link directories (for older CMake / pkg-config compatibility)
target_link_directories(rinetd-uv PRIVATE
    ${LIBUV_LIBRARY_DIRS}
    ${YAML_LIBRARY_DIRS}
)

# Install targets
include(GNUInstallDirs)

# Install binary to sbin
install(TARGETS rinetd-uv DESTINATION ${CMAKE_INSTALL_SBINDIR})

# Install man page if it exists
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/rinetd-uv.8")
    install(FILES rinetd-uv.8 DESTINATION ${CMAKE_INSTALL_MANDIR}/man8)
endif()

# Install example config to sysconfdir
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/rinetd-uv.conf")
    install(FILES rinetd-uv.conf DESTINATION ${CMAKE_INSTALL_SYSCONFDIR})
endif()

# ============================================================================
# Documentation generation targets (equivalent to autotools 'make docs')
# ============================================================================

find_program(PANDOC_EXECUTABLE pandoc)
find_program(BASH_EXECUTABLE bash)

if(PANDOC_EXECUTABLE AND BASH_EXECUTABLE)
    # docs-man: Generate man page from DOCUMENTATION.md
    add_custom_target(docs-man
        COMMAND ${BASH_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/generate-manpage.sh"
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        COMMENT "Generating man page from DOCUMENTATION.md"
        VERBATIM
    )

    # docs-html: Generate HTML from DOCUMENTATION.md
    add_custom_target(docs-html
        COMMAND ${BASH_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/generate-html.sh"
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        COMMENT "Generating HTML documentation from DOCUMENTATION.md"
        VERBATIM
    )

    # docs-conf: Extract example configs from DOCUMENTATION.md
    add_custom_target(docs-conf
        COMMAND ${BASH_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/generate-conf.sh"
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        COMMENT "Extracting example configurations from DOCUMENTATION.md"
        VERBATIM
    )

    # docs: Generate all documentation
    add_custom_target(docs
        DEPENDS docs-man docs-html docs-conf
        COMMENT "Generating all documentation"
    )

    message(STATUS "Documentation targets enabled: docs, docs-man, docs-html, docs-conf")
else()
    if(NOT PANDOC_EXECUTABLE)
        message(STATUS "pandoc not found - documentation generation targets disabled")
    endif()
    if(NOT BASH_EXECUTABLE)
        message(STATUS "bash not found - documentation generation targets disabled")
    endif()
endif()

# ============================================================================
# Source distribution (equivalent to autotools 'make dist')
# ============================================================================

include(CPack)

set(CPACK_PACKAGE_NAME "rinetd-uv")
set(CPACK_PACKAGE_VERSION ${PACKAGE_VERSION})
set(CPACK_PACKAGE_VENDOR "Marcin Gryszkalis")
set(CPACK_PACKAGE_CONTACT "mg@fork.pl")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "rinetd-uv - internet redirection server with libuv")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")

# Source tarball configuration (TGZ only for speed - can add TXZ, ZIP if needed)
set(CPACK_SOURCE_GENERATOR "TGZ" "TZ")
set(CPACK_SOURCE_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}")

# generated from .gitignore (no auto sync)
set(CPACK_SOURCE_IGNORE_FILES
    "\\\\.git/"
    "build/"
    "build\\\\..*/"
    "\\\\.gitignore"
    "Makefile$"
    "config\\\\.h$"
    "config\\\\.log"
    "config\\\\.status"
    "stamp-h1"
    "\\\\.deps/"
    "\\\\.dirstamp"
    "autom4te\\\\.cache/"
    "\\\\.o$"
    "\\\\.so$"
    "\\\\.a$"
    "rinetd-uv$"
    "\\\\.tar\\\\."
    "\\\\.zip$"
    "~$"
    "\\\\.swp$"
    "\\\\.log$"
    "venv/"
    "__pycache__/"
    "\\\\.pytest_cache/"
    "CMakeFiles/"
    "CMakeCache\\\\.txt"
    "cmake_install\\\\.cmake"
    "CPackConfig\\\\.cmake"
    "CPackSourceConfig\\\\.cmake"
    "_CPack_Packages/"
    "install_manifest\\\\.txt"
)

# Custom dist target (like autotools 'make dist')
# Use git archive (CPack too messy)
find_program(GIT_EXECUTABLE git)
if(GIT_EXECUTABLE)
    add_custom_target(dist
        COMMAND ${GIT_EXECUTABLE} archive
            --format=tar.gz
            --prefix=${CPACK_SOURCE_PACKAGE_FILE_NAME}/
            -o "${CMAKE_BINARY_DIR}/${CPACK_SOURCE_PACKAGE_FILE_NAME}.tar.gz"
            HEAD
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        COMMENT "Creating source distribution tarball using git archive"
        VERBATIM
    )
    message(STATUS "dist target enabled")
else()
    message(STATUS "git not found - dist target disabled")
endif()

# ============================================================================
# Distribution verification (equivalent to autotools 'make distcheck')
# ============================================================================

# distcheck: Build tarball, extract, configure, build, test, install, uninstall
if(GIT_EXECUTABLE AND BASH_EXECUTABLE)
    add_custom_target(distcheck
        COMMAND ${BASH_EXECUTABLE} "${CMAKE_SOURCE_DIR}/distcheck.sh" "${CPACK_SOURCE_PACKAGE_FILE_NAME}" "${CMAKE_BINARY_DIR}"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        COMMENT "Verifying source distribution"
        VERBATIM
    )
    message(STATUS "distcheck target enabled")
else()
    if(NOT GIT_EXECUTABLE)
        message(STATUS "git not found - distcheck target disabled")
    endif()
    if(NOT BASH_EXECUTABLE)
        message(STATUS "bash not found - distcheck target disabled")
    endif()
endif()
