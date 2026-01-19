/* Copyright © 1997—1999 Thomas Boutell <boutell@boutell.com>
                         and Boutell.Com, Inc.
             © 2003—2021 Sam Hocevar <sam@hocevar.net>
             © 2026 Marcin Gryszkalis <mg@fork.pl>

   This software is released for free use under the terms of
   the GNU Public License, version 2 or higher. NO WARRANTY
   IS EXPRESSED OR IMPLIED. USE THIS SOFTWARE AT YOUR OWN RISK. */

#pragma once

#include "types.h"

/* Log event codes */
enum {
    logUnknownError = 0,
    logLocalClosedFirst,
    logRemoteClosedFirst,
    logAcceptFailed,
    logLocalSocketFailed,
    logLocalBindFailed,
    logLocalConnectFailed,
    logOpened,
    logAllowed,
    logNotAllowed,
    logDenied,
};

/* Log message strings (indexed by log event codes) */
extern char const *logMessages[];

/* Basic logging (no connection context) */
void logError(char const *fmt, ...);
void logWarning(char const *fmt, ...);
void logInfo(char const *fmt, ...);
void logDebug(char const *fmt, ...);

/* Connection-aware logging (includes source/dest discriminators) */
void logErrorConn(ConnectionInfo const *cnx, char const *fmt, ...);
void logWarningConn(ConnectionInfo const *cnx, char const *fmt, ...);
void logInfoConn(ConnectionInfo const *cnx, char const *fmt, ...);
void logDebugConn(ConnectionInfo const *cnx, char const *fmt, ...);

/* Connection event logging (to log file) */
void logEvent(ConnectionInfo const *cnx, ServerInfo const *srv, int result);

/* Initialize/shutdown logging subsystem */
void log_init(void);
void log_shutdown(void);

/* Configuration setters for internal state */
void log_set_forked(int forked);
void log_set_debug(int debug);
