
EXTRA_DIST = parse.peg getopt.c getopt.h

sbin_PROGRAMS = rinetd-uv
rinetd_uv_SOURCES = rinetd.c rinetd.h \
                    log.c log.h \
                    parse.c parse.h \
                    match.c match.h \
                    net.c net.h \
                    buffer_pool.c buffer_pool.h \
                    loadbalancer.c loadbalancer.h \
                    affinity.c affinity.h \
                    yaml_config.c yaml_config.h \
                    types.h

BUILT_SOURCES = parse.c

# If peg/leg is available, regenerate parse.h
parse.c: parse.peg
	if which leg >/dev/null 2>&1; then leg -o $@ $^; else echo "parse.peg is newer than parse.c but leg/peg is not found"; exit 1; fi

# _POSIX_C_SOURCE is for SA_RESTART and others
# _DARWIN_C_SOURCE is for NI_MAXHOST on OS X
# _XOPEN_SOURCE is for struct sigaction
# _GNU_SOURCE is for h_errno and gethostbyname-related macros
# _BSD_SOURCE, __BSD_VISIBLE and _DEFAULT_SOURCE are for daemon() and vsyslog() on BSD systems
rinetd_uv_CFLAGS = -std=c99 -D_POSIX_C_SOURCE=200809L \
                   -D_XOPEN_SOURCE -D_GNU_SOURCE -D_DARWIN_C_SOURCE \
                   -D_BSD_SOURCE -D_DEFAULT_SOURCE -D__BSD_VISIBLE \
                   -Wall -Wextra -Wwrite-strings $(LIBUV_CFLAGS) $(YAML_CFLAGS)

rinetd_uv_LDADD = $(LIBUV_LIBS) $(YAML_LIBS)

