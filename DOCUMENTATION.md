# rinetd(8) - internet redirection server

## NAME

rinetd - internet redirection server

## SYNOPSIS

```
rinetd [-f] [-c configuration]
rinetd -h
rinetd -v
```

## DESCRIPTION

**rinetd** redirects TCP or UDP connections from one IP address and port to another. **rinetd** is a single-process server which handles any number of connections to the address/port pairs specified in the file `/etc/rinetd.conf`. Since **rinetd** runs as a single process using nonblocking I/O (via libuv event loop), it is able to redirect a large number of connections without a severe impact on the machine. This makes it practical to run services on machines inside an IP masquerading firewall.

**rinetd** is typically launched at boot time, using the following syntax:

```
/usr/sbin/rinetd
```

The configuration file is found in the file `/etc/rinetd.conf`, unless another file is specified using the `-c` command line option.

## OPTIONS

**-f**
:   Run **rinetd** in the foreground, without forking to the background.

**-c** *configuration*
:   Specify an alternate configuration file.

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

Would redirect all connections to port 80 of the "real" IP address 206.125.69.81, which could be a virtual interface, through **rinetd** to port 80 of the address 10.1.1.2, which would typically be a machine on the inside of a firewall which has no direct routing to the outside world.

Although responding on individual interfaces rather than on all interfaces is one of **rinetd**'s primary features, sometimes it is preferable to respond on all IP addresses that belong to the server. In this situation, the special IP address `0.0.0.0` can be used. For example:

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

Since UDP is a connectionless protocol, a timeout is necessary or forwarding connections may accumulate with time and exhaust resources. By default, if no data is sent or received on a UDP connection for 72 seconds, the other connection is closed. This value can be changed using the *timeout* option:

```
0.0.0.0 8000/udp  10.1.1.2 53/udp  [timeout=3600]
```

This rule will forward all data received on UDP port 8000 to host 10.1.1.2 on UDP port 53, and will close the connection after no data is received on the UDP port for 3600 seconds.

### Source Address Option

A forwarding rule option allows binding to a specific local address when sending data to the other end. This is done using the *src* option:

```
192.168.1.1 80  10.1.1.127 80  [src=10.1.1.2]
```

Assuming the local host has two IP addresses, 10.1.1.1 and 10.1.1.2, this rule ensures that forwarded packets are sent using source address 10.1.1.2.

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

### Logging

**rinetd** is able to produce a log file in either of two formats: tab-delimited and web server-style "common log format".

By default, **rinetd** does not produce a log file. To activate logging, add the following line to the configuration file:

```
logfile /var/log/rinetd.log
```

By default, **rinetd** logs in a simple tab-delimited format containing the following information:

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

Under Linux the process ID is saved in the file `/var/run/rinetd.pid` by default. An alternate filename can be provided:

```
pidlogfile /var/run/myrinetd.pid
```

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

**Important:** Host names are **NOT** permitted in allow and deny rules. The performance cost of looking up IP addresses to find their corresponding names is prohibitive. Since **rinetd** is a single process server, all other connections would be forced to pause during the address lookup.

## EXAMPLE CONFIGURATION

```
# Global settings
logfile /var/log/rinetd.log
buffersize 32768

# Global access control
allow 192.168.*
deny *

# TCP forwarding
0.0.0.0 80 192.168.1.10 8080
0.0.0.0 443 192.168.1.10 8443

# UDP forwarding (DNS)
0.0.0.0 53/udp 8.8.8.8 53/udp [timeout=30]

# Forwarding with source address binding
192.168.1.1 3306 10.1.1.50 3306 [src=192.168.1.100]

# Per-rule access control
0.0.0.0 22 192.168.1.20 22
allow 10.0.0.*
```

## REINITIALIZING RINETD

The `kill -1` signal (SIGHUP) can be used to cause **rinetd** to reload its configuration file without interrupting existing connections.

```bash
kill -HUP $(cat /var/run/rinetd.pid)
```

Or simply:

```bash
killall -HUP rinetd
```

## BUGS AND LIMITATIONS

**rinetd** only redirects protocols which use a single TCP or UDP socket. This rules out FTP (which uses multiple connections for data transfer).

The server redirected to is not able to identify the host the client really came from. This cannot be corrected; however, the log produced by **rinetd** provides a way to obtain this information.

Mixed-mode forwarding (TCP client to UDP backend, or UDP client to TCP backend) is not supported due to fundamental protocol incompatibilities. See `TCP-UDP_MIXED_MODE.md` for technical details.

## PERFORMANCE NOTES

**rinetd** uses libuv for event-driven I/O, providing excellent performance characteristics:

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

Copyright (c) 2003-2021 Sam Hocevar

This software is released for free use under the terms of the GNU General Public License, version 2 or higher. NO WARRANTY IS EXPRESSED OR IMPLIED. USE THIS SOFTWARE AT YOUR OWN RISK.

## CONTACT INFORMATION

See https://github.com/samhocevar/rinetd/releases for the latest release.

**Thomas Boutell** can be reached by email: boutell@boutell.com

**Sam Hocevar** can be reached by email: sam@hocevar.net

## THANKS

Thanks are due to Bill Davidsen, Libor Pechachek, Sascha Ziemann, the Apache Group, and many others who have contributed advice and/or source code to this and other free software projects.

## SEE ALSO

Additional documentation:
- `BUILD.md` - Build requirements and instructions
- `BUFFER_OPTIMIZATION.md` - Buffer management and optimization details
- `TCP-UDP_MIXED_MODE.md` - Technical analysis of mixed-mode limitations
- `CLEANUP_SUMMARY.md` - Code cleanup and maintenance notes
