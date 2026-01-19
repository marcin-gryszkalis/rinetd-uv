# Process this file with autoconf to produce a configure script.
m4_include([VERSION]) #Force reconf on VERSION change
AC_PREREQ(2.52)
AC_INIT(rinetd-uv, m4_esyscmd_s(cat VERSION), mg@fork.pl, rinetd-uv, https://github.com/marcin-gryszkalis/rinetd-uv)
AC_CONFIG_AUX_DIR(.auto)
AC_CONFIG_SRCDIR([src/rinetd.c])
AC_CONFIG_HEADERS([src/config.h])
AM_INIT_AUTOMAKE([no-define tar-ustar silent-rules])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Checks for libraries.
AC_CHECK_LIB(ws2_32, main, [LIBS="${LIBS} -lws2_32"])

# Check for libuv (required for event loop)
PKG_CHECK_MODULES([LIBUV], [libuv >= 1.0], [], [
    AC_MSG_ERROR([libuv >= 1.0 not found. Install with: apt-get install libuv1-dev (Debian/Ubuntu) or brew install libuv (macOS)])
])
AC_SUBST([LIBUV_CFLAGS])
AC_SUBST([LIBUV_LIBS])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h errno.h fcntl.h netdb.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_STRUCT_TM
AC_CHECK_TYPES(ssize_t, [], [],
  [#include <sys/types.h>])
AC_CHECK_TYPES(socklen_t, [], [],
  [#include <sys/types.h>
   #include <sys/socket.h>])

# Checks for library functions.
AC_FUNC_FORK
#XXX: disabled because of cross-compilation issues
#AC_FUNC_MALLOC
AC_FUNC_STRFTIME
AC_CHECK_FUNCS([gethostbyname memset select socket strstr daemon fork sigaction])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([src/Makefile])
AC_OUTPUT
