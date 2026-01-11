# rinetd-uv(8) - internet redirection server

## NAME

rinetd-uv - internet redirection server

## SYNOPSIS

```
rinetd-uv [-f] [-c configuration]
rinetd-uv -h
rinetd-uv -v
```

## DESCRIPTION

**rinetd-uv** redirects TCP or UDP connections from one IP address and port to another. **rinetd-uv** is a single-process server which handles any number of connections to the address/port pairs specified in the file `/etc/rinetd-uv.conf`. Since **rinetd-uv** runs as a single process using nonblocking I/O (via libuv event loop), it is able to redirect a large number of connections without a severe impact on the machine. This makes it practical to run services on machines inside an IP masquerading firewall.

### Libuv

**rinetd-uv** is a modernized implementation of the original rinetd daemon, rewritten to use the libuv event loop library. While maintaining backward compatibility with the original rinetd configuration format, rinetd-uv features a completely rewritten internal architecture.

## RUN

**rinetd-uv** is typically launched at boot time, using the following syntax:

```
/usr/sbin/rinetd-uv
```

The configuration file is found in the file `/etc/rinetd-uv.conf`, unless another file is specified using the `-c` command line option.

## OPTIONS

**-f**
:   Run **rinetd-uv** in the foreground, without forking to the background.

**-c** *configuration*
:   Specify an alternate configuration file.

**-d**
:   Enable debug logging. Shows detailed information about DNS refresh operations, connection failures triggering re-resolution, and other internal operations.

**-v**
:   Display the version number and exit.

**-h**
:   Produce a short help message and exit.

## FORWARDING RULES

Most entries in the configuration file are forwarding rules. The format of a forwarding rule is as follows:

```
bindaddress bindport connectaddress connectport [options...]
```

For example:

```
206.125.69.81 80  10.1.1.2 80
```

Would redirect all connections to port 80 of the "real" IP address 206.125.69.81, which could be a virtual interface, through **rinetd-uv** to port 80 of the address 10.1.1.2, which would typically be a machine on the inside of a firewall which has no direct routing to the outside world.

Although responding on individual interfaces rather than on all interfaces is one of **rinetd-uv**'s primary features, sometimes it is preferable to respond on all IP addresses that belong to the server. In this situation, the special IP address `0.0.0.0` can be used. For example:

```
0.0.0.0 23  10.1.1.2 23
```

Would redirect all connections to port 23, for all IP addresses assigned to the server. This is the default behavior for most other programs.

### Protocol Specification

Ports default to TCP. To specify the protocol, append `/udp` or `/tcp` to the port number:

```
206.125.69.81 80/tcp  10.1.1.2 8000/tcp
0.0.0.0 53/udp  8.8.8.8 53/udp
```

**Note:** Mixed-mode forwarding (TCP to UDP or UDP to TCP) is not currently supported.

### Service Names

Service names can be specified instead of port numbers. On most systems, service names are defined in the file `/etc/services`.

### IP Addresses and Hostnames

Both IP addresses and hostnames are accepted for *bindaddress* and *connectaddress*, including IPv6.

## FORWARDING OPTIONS

### UDP Timeout Option

Since UDP is a connectionless protocol, a timeout is necessary or forwarding connections may accumulate with time and exhaust resources. By default, if no data is sent or received on a UDP connection for 10 seconds, the other connection is closed. This value can be changed using the *timeout* option:

```
0.0.0.0 8000/udp  10.1.1.2 53/udp  [timeout=3600]
```

This rule will forward all data received on UDP port 8000 to host 10.1.1.2 on UDP port 53, and will close the connection after no data is received on the UDP port for 3600 seconds.

**Note:** rinetd-uv limits UDP connections to 1000 concurrent outgoing connections per forwarding rule to prevent file descriptor exhaustion. When this limit is reached, the oldest (least recently used) connection is automatically closed to make room for new connections. This is particularly important for high-volume UDP proxies (e.g., DNS).

### Source Address Option

A forwarding rule option allows binding to a specific local address when sending data to the other end. This is done using the *src* option:

```
192.168.1.1 80  10.1.1.127 80  [src=10.1.1.2]
```

Assuming the local host has two IP addresses, 10.1.1.1 and 10.1.1.2, this rule ensures that forwarded packets are sent using source address 10.1.1.2.

### TCP Keepalive Option

TCP keepalive is enabled by default for all TCP connections to detect dead connections. To disable it for a specific forwarding rule, use the *keepalive* option:

```
192.168.1.1 80/tcp  10.1.1.127 80/tcp  [keepalive=off]
```

When enabled, keepalive probes are sent after 60 seconds of inactivity.

### DNS Refresh Option

For forwarding rules with backend hostnames (not IP addresses), **rinetd-uv** can automatically re-resolve DNS hostnames at configurable intervals. This ensures that if a backend's IP address changes, new connections will use the updated address.

**Global configuration:**

```
dns-refresh 600
```

This sets the default DNS refresh interval to 600 seconds (10 minutes) for all forwarding rules with hostnames.

**Per-rule configuration:**

```
0.0.0.0 8080/tcp backend.example.com 80 [dns-refresh=300]
```

This overrides the global setting, refreshing this specific backend every 300 seconds (5 minutes).

**Disable for specific rule:**

```
0.0.0.0 8081/tcp backend2.example.com 80 [dns-refresh=0]
```

Setting `dns-refresh=0` disables periodic DNS refresh for this rule.

**Behavior:**

- **Hostname detection:** DNS refresh is only enabled for backend (target) hostnames. Rules with IP addresses (IPv4 or IPv6) automatically skip DNS refresh.
- **Existing connections:** Continue using the old IP address until they close naturally.
- **New connections:** Immediately use the newly resolved IP address.
- **Failure-triggered refresh:** After 3 consecutive connection failures to a backend, DNS is re-resolved immediately (regardless of the timer interval).
- **SIGHUP compatibility:** Sending SIGHUP still forces immediate re-resolution of all hostnames (existing behavior preserved).

**Default:** 600 seconds (10 minutes)

**Example configuration:**

```
# Global default: refresh every 10 minutes
dns-refresh 600

# Critical service: refresh more frequently
0.0.0.0 443/tcp api.example.com 443 [dns-refresh=60]

# Static IP backend: no DNS refresh needed
0.0.0.0 8080/tcp 192.168.1.100 8080

# Long-lived connections: refresh less frequently
0.0.0.0 8000/tcp cache.example.com 6379 [dns-refresh=1800]

# Disable for this specific rule
0.0.0.0 9000/tcp static.example.com 9000 [dns-refresh=0]
```

## UNIX DOMAIN SOCKETS

rinetd-uv supports Unix domain sockets (also known as Unix sockets or local sockets),
allowing forwarding between TCP and Unix sockets in any combination:

- **TCP to Unix socket** - Expose a Unix socket service over TCP (e.g. Docker socket proxy)
- **Unix socket to TCP** - Accept connections on a Unix socket and forward to TCP backend
- **Unix to Unix** - Forward between Unix sockets

### Syntax

Unix socket addresses use the `unix:` prefix followed by the socket path:

```
unix:/path/to/socket    # Filesystem socket (absolute path required)
unix:@name              # Abstract namespace socket (Linux only)
```

**Note:** No port number is required for Unix socket addresses.

### Examples

```
# TCP to Unix - Docker socket proxy
# Clients connect to TCP port 2375, forwarded to Docker Unix socket
0.0.0.0 2375/tcp unix:/var/run/docker.sock

# Unix to TCP - Accept on Unix socket, forward to HTTP server
unix:/var/run/frontend.sock 192.168.1.100 8080/tcp

# Unix to Unix - Forward between Unix sockets
unix:/tmp/proxy.sock unix:/var/run/backend.sock

# Abstract namespace socket (Linux only)
# Abstract sockets don't create filesystem entries
0.0.0.0 9999/tcp unix:@myservice
```

### Access Control

- For **filesystem sockets**, access is controlled by filesystem permissions on the socket file
- For **TCP endpoints**, the standard `allow` and `deny` rules apply
- IP-based access control does not apply to incoming Unix socket connections (access rules in such case will be ignored)
- For **abstract sockets** (Linux), any process in the same network namespace can connect

### Security Considerations

1. **Filesystem permissions**: The socket file inherits permissions from the directory where it's created
2. **Abstract sockets**: Accessible by any process in the same network namespace - use with caution
3. **Socket cleanup**: Filesystem sockets are automatically removed on shutdown and before bind

### Limitations

- Maximum socket path length varies by system (Linux: 107, BSD: 103, some other systems: 91)
- Unix sockets only support stream mode (SOCK_STREAM); datagram mode (SOCK_DGRAM) or SCTP (SOCK_SEQPACKET) is not supported
- UDP forwarding cannot use Unix sockets
- Abstract namespace sockets are Linux-specific and not portable
- Windows named pipes support is not tested although underlying libuv declares they are covered, report a bug in case you need it.

## GLOBAL CONFIGURATION OPTIONS

### Buffer Size

The buffer size used for I/O operations can be configured globally. This affects memory usage and performance characteristics.

```
buffersize 32768
```

**Range:** 1024 to 1048576 bytes (1 KB to 1 MB)
**Default:** 65536 bytes (64 KB)

**Recommendations:**
- **DNS proxy (small packets):** `buffersize 2048` - Reduces memory usage
- **HTTP proxy (medium packets):** `buffersize 32768` - Balanced performance
- **High throughput:** `buffersize 131072` - Maximum performance (if memory allows)
- **Memory-constrained systems:** `buffersize 4096` - Minimum practical size

The buffer size multiplied by the number of concurrent connections determines total memory usage. For example, with 1000 concurrent connections:
- `buffersize 4096`: ~4 MB memory
- `buffersize 65536`: ~64 MB memory

### DNS Refresh

The global DNS refresh interval can be configured to set the default for all forwarding rules with backend hostnames:

```
dns-refresh 600
```

**Range:** 0 to unlimited seconds
**Default:** 600 seconds (10 minutes)

This global setting applies to all forwarding rules unless overridden by a per-rule `[dns-refresh=N]` option. See the **DNS Refresh Option** section under **FORWARDING OPTIONS** for detailed documentation and examples.

### Logging

**rinetd-uv** is able to produce a log file in either of two formats: tab-delimited and web server-style "common log format".

By default, **rinetd-uv** does not produce a log file. To activate logging, add the following line to the configuration file:

```
logfile /var/log/rinetd-uv.log
```

By default, **rinetd-uv** logs in a simple tab-delimited format containing the following information:

- Date and time
- Client address
- Listening host
- Listening port
- Forwarded-to host
- Forwarded-to port
- Bytes received from client
- Bytes sent to client
- Result message

To activate web server-style "common log format" logging, add the following line to the configuration file:

```
logcommon
```

### PID File

Under Linux the process ID is saved in the file `/var/run/rinetd-uv.pid` by default. An alternate filename can be provided:

```
pidfile /var/run/myrinetd-uv.pid
```

## INCLUDE DIRECTIVE

Configuration files can include other configuration files using the `include` directive. This allows splitting large configurations into multiple files for better organization and maintainability.

### Syntax

```
include pattern
```

The `pattern` can be:
- **Single file**: `include servers.conf`
- **Wildcard pattern**: `include conf.d/*.conf`
- **Absolute path**: `include /etc/rinetd-uv/servers.conf`
- **Relative path**: Resolved relative to the current config file's directory

### Features

- **Wildcard Support**: Use glob patterns like `*.conf` or `server-*.conf` to include multiple files
- **Nested Includes**: Included files can include other files (up to 10 levels deep)
- **Circular Detection**: Automatically prevents circular includes
- **Depth Limit**: Maximum include depth is 10 levels to prevent infinite recursion
- **Optional Includes**: If a pattern matches no files, a warning is logged but parsing continues
- **Sorted Loading**: When using wildcards, files are loaded in alphabetical order

### Examples

**Basic include:**
```
# Include a single file
include /etc/rinetd-uv.d/database-servers.conf
```

**Wildcard pattern:**
```
# Include all .conf files from a directory
include /etc/rinetd-uv.d/*.conf
```

**Relative paths:**
```
# In /etc/rinetd-uv.conf:
include conf.d/*.conf

# This resolves to /etc/conf.d/*.conf
```

**Organized configuration structure:**
```
# Main config: /etc/rinetd-uv.conf
logfile /var/log/rinetd-uv.log
pidfile /var/run/rinetd-uv.pid

# Global access control
allow 10.0.0.*
deny 192.168.1.100

# Include server-specific configs
include conf.d/web-servers.conf
include conf.d/database-servers.conf
include conf.d/dns-servers.conf
```

### Error Handling

- **No matches**: If a pattern matches no files, a warning is logged and parsing continues
- **Circular includes**: Detected and causes immediate error
- **Maximum depth exceeded**: More than 10 levels of nesting causes an error
- **File not found**: Individual file errors cause immediate failure
- **Permission denied**: Causes immediate error

## ALLOW AND DENY RULES

Configuration files can also contain allow and deny rules.

Allow rules which appear **before the first forwarding rule** are applied globally: if at least one global allow rule exists, and the address of a new connection does not satisfy at least one of the global allow rules, that connection is immediately rejected, regardless of any other rules.

Allow rules which appear **after a specific forwarding rule** apply to that forwarding rule only. If at least one allow rule exists for a particular forwarding rule, and the address of a new connection does not satisfy at least one of the allow rules for that forwarding rule, that connection is immediately rejected, regardless of any other rules.

Deny rules which appear **before the first forwarding rule** are applied globally: if the address of a new connection satisfies any of the global deny rules, that connection is immediately rejected, regardless of any other rules.

Deny rules which appear **after a specific forwarding rule** apply to that forwarding rule only. If the address of a new connection satisfies any of the deny rules for that forwarding rule, that connection is immediately rejected, regardless of any other rules.

### Rule Format

The format of an allow or deny rule is as follows:

```
allow pattern
deny pattern
```

Patterns can contain the following characters: `0`, `1`, `2`, `3`, `4`, `5`, `6`, `7`, `8`, `9`, `.` (period), `?`, and `*`. The `?` wildcard matches any one character. The `*` wildcard matches any number of characters, including zero.

For example:

```
allow 206.125.69.*
```

This allow rule matches all IP addresses in the 206.125.69 class C domain.

**Important:** Host names are **NOT** permitted in allow and deny rules. The performance cost of looking up IP addresses to find their corresponding names is prohibitive. Since **rinetd-uv** is a single process server, all other connections would be forced to pause during the address lookup.

## EXAMPLE CONFIGURATION

```
# rinetd-uv.conf - example configuration

# Global options
logfile /var/log/rinetd-uv.log
# logcommon  # Use Apache-style logging

# PID file
pidfile /var/run/rinetd-uv.pid

# Buffer size configuration (1KB - 1MB, default: 65536)
# Smaller values reduce memory usage and latency, larger values improve throughput
buffersize 65536  # 64KB is the default

# DNS refresh interval (default: 600 seconds = 10 minutes)
# Automatically re-resolves backend hostnames at specified intervals
# Set to 0 to disable, or override per-rule with [dns-refresh=N]
dns-refresh 600

# Global Access Control:
# You may specify global allow and deny rules here.
# Only ip addresses are matched, hostnames cannot be specified here.
# The wildcards you may use are * and ?
#
allow 192.168.2.*
deny 192.168.2.1?
allow fe80:*
deny 2001:618:*:e43f

# You can split your configuration across multiple files
include /etc/rinetd-uv.d/*.conf
# include conf.d/servers.conf

# Forwarding options:
# Format: bindaddress bindport connectaddress connectport [options]
# Options: [timeout=seconds,src=sourceaddress,keepalive=on/off,dns-refresh=seconds]
# Note: TCP keepalive is enabled by default

# TCP forwarding examples
0.0.0.0 80/tcp 192.168.1.10 8080/tcp
192.168.0.1 https server.example.com 8443 [src=192.168.1.1]
0.0.0.0 444 api.example.com 444 [dns-refresh=60]
:: http ipv6.google.com http

# UDP forwarding example
0.0.0.0 53/udp 8.8.8.8 53/udp [timeout=30]

# Unix domain socket forwarding examples
# TCP to Unix socket - Docker socket proxy
0.0.0.0 2375/tcp unix:/var/run/docker.sock
# Unix to TCP forwarding
unix:/var/run/myapp.sock 192.168.1.100 8080/tcp

# Per-rule Access Control (applies to previous forwarding rule)
0.0.0.0 22 192.168.1.20 22
allow 10.0.0.*

```

## REINITIALIZING RINETD-UV

The SIGHUP signal can be used to cause **rinetd-uv** to reload its configuration file without interrupting existing connections.

```bash
kill -HUP $(cat /var/run/rinetd-uv.pid)
```

Or simply:

```bash
killall -HUP rinetd-uv
```

## RUN WITH DOCKER

There's simple `Dockerfile` provided to create working docker image with **rinetd-uv** built from sources (HEAD). Image is based on Debian Linux. Thanks to using `-slim` base image and 2-stage build final image size shouldn't exceed 100MB.

Build the image:

```bash
docker build -t rinetd-uv .
```

Example run:

```bash
docker run -d --name rinetd-uv --user nobody --ulimit nofile=65000 --publish 8080:8080 --publish 5353:5353/udp --volume ./rinetd-uv.conf:/etc/rinetd-uv.conf:ro rinetd-uv
```

## BUGS AND LIMITATIONS

**rinetd-uv** only redirects protocols which use a single TCP or UDP socket. This rules out FTP (which uses multiple connections for data transfer).

The server redirected to is not able to identify the host the client really came from. This cannot be corrected; however, the log produced by **rinetd-uv** provides a way to obtain this information.

Two rules with the same source ip/port and different destination ip/port are not allowed (you'll get "Address already in use" or similar error). Note that `0.0.0.0` (IPv4) and `::` (IPv6) effectively mean the same (both would bind to "any" address).

**rinetd-uv** does not implement backpressure (flow control) between the client and backend connections. If one endpoint sends data faster than the other endpoint can receive it, the data waiting to be forwarded will queue up in memory. In extreme cases (e.g., a fast sender paired with a very slow or stalled receiver), this can lead to unbounded memory growth. This is generally not a problem for well-behaved clients and backends, but could be exploited in adversarial scenarios where an attacker deliberately sends data rapidly while receiving slowly.

### Incompatibilities

**rinetd-uv** was meant as drop-in replacement for **rinetd**, although there are some differences

- logging format and behavior changed slightly: date is in the iso format (yyyy-mm-dd hh:mm:ss), for every connection 2 lines are logged - one with 'open' result and one with 'done-' result (which contain valid values for transferred data sizes)
- `pidlogfile` option was renamed to `pidfile`
- original rinetd mentioned possibility to proxy traffic between differen protocols (UDP <-> TCP), in **rinetd-uv** it's not possible due to fundamental protocol incompatibilities. See `TCP-UDP_MIXED_MODE.md` for technical details.

## PERFORMANCE NOTES

**rinetd-uv** uses libuv for event-driven I/O, providing excellent performance characteristics:

- Single-process, event-driven architecture
- Dynamic buffer allocation with zero-copy forwarding
- Efficient handling of thousands of concurrent connections
- Low CPU overhead per connection

Memory usage can be tuned via the `buffersize` option. Typical memory usage:
```
Total Memory = buffersize × concurrent_connections
```

For high-performance deployments, consider:
- Using larger buffer sizes (64 KB - 128 KB) for better throughput
- Using smaller buffer sizes (2 KB - 8 KB) when memory is constrained
- Monitoring active connections and adjusting buffer size accordingly

## LICENSE

Copyright (c) 1997, 1998, 1999, Thomas Boutell and Boutell.Com, Inc.

Copyright (c) 2003-2025 Sam Hocevar

Copyright (c) 2026 Marcin Gryszkalis

This software is released for free use under the terms of the GNU General Public License, version 2 or higher. NO WARRANTY IS EXPRESSED OR IMPLIED. USE THIS SOFTWARE AT YOUR OWN RISK.

## CONTACT INFORMATION

See https://github.com/marcin-gryszkalis/rinetd for the latest release.

**Marcin Gryszkalis** can be reached by email: mg@fork.pl

**Sam Hocevar** can be reached by email: sam@hocevar.net

**Thomas Boutell** can be reached by email: boutell@boutell.com

## THANKS

Thanks are due to Bill Davidsen, Libor Pechachek, Sascha Ziemann, the Apache Group, and many others who have contributed advice and/or source code to this and other free software projects.

## LLM

This implementation was created with support of assorted LLM agents (Claude Opus, Claude Sonnet, Gemini, GPT). The architecure and code was reviewed by human.

## SEE ALSO

### Links

- rinetd-uv: https://github.com/marcin-gryszkalis/rinetd
- original rinetd: https://github.com/samhocevar/rinetd

### Additional Documentation

- [[BUILD.md]] - Build requirements and instructions
- [[TCP-UDP_MIXED_MODE.md]] - Technical analysis of mixed-mode limitations
