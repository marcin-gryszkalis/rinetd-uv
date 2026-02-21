# rinetd-uv(8) - internet redirection server

## NAME

rinetd-uv - internet redirection server

## SYNOPSIS

```
rinetd-uv [-f] [-d] [-c configuration]
rinetd-uv -h
rinetd-uv -v
```

## DESCRIPTION

**rinetd-uv** redirects TCP or UDP connections from one IP address and port to another. **rinetd-uv** is a single-process server which handles any number of connections to the address/port pairs specified in the file `/etc/rinetd-uv.conf` (legacy format) or `/etc/rinetd-uv.yaml` (YAML format with load balancing support). Since **rinetd-uv** runs as a single process using nonblocking I/O (via libuv event loop), it is able to redirect a large number of connections without a severe impact on the machine. This makes it practical to run services on machines inside an IP masquerading firewall.

The YAML configuration format (version 2.1.0+) adds support for **load balancing** with multiple backend servers, health checking, and client affinity. See the **Configuration** section for details.

### Libuv

**rinetd-uv** is a modernized implementation of the original rinetd daemon, rewritten to use the libuv event loop library. While maintaining backward compatibility with the original rinetd configuration format, rinetd-uv features a completely rewritten internal architecture.

## RUN

**rinetd-uv** is typically launched at boot time, using the following syntax:

```
/usr/sbin/rinetd-uv
```

When no `-c` option is provided, **rinetd-uv** searches for configuration files in the following order:

1. `/etc/rinetd-uv.yaml` (YAML format with load balancing support)
2. `/etc/rinetd-uv.yml` (YAML format)
3. `/etc/rinetd-uv.conf` (legacy format)

The first file found is used. YAML configuration files enable load balancing features. Use the `-c` option to specify an alternate configuration file.

### Run with Docker

#### From public registry

 * https://hub.docker.com/r/marcingryszkalis/rinetd-uv

```bash
docker pull marcingryszkalis/rinetd-uv

docker run --rm marcingryszkalis/rinetd-uv:latest --version

docker run \
   --rm \
   --name rinetd-uv \
   --ulimit nofile=65000 \
   --publish 127.0.0.1:8080:8080 \
   --publish 127.0.0.1:53535:53535/udp \
   --volume ./rinetd-uv.conf:/etc/rinetd-uv.conf:ro \
   marcingryszkalis/rinetd-uv
```

#### Local build

```bash
docker build --build-arg VERSION=$(cat VERSION) -t rinetd-uv .

docker run --rm rinetd-uv --version

docker run \
    --rm \
    --name rinetd-uv \
    --ulimit nofile=65000 \
    --publish 127.0.0.1:8080:8080 \
    --publish 127.0.0.1:53535:53535/udp \
    --volume ./rinetd-uv.conf:/etc/rinetd-uv.conf:ro \
    rinetd-uv
```

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

## CONFIGURATION

**rinetd-uv** supports two configuration formats:

- **Legacy format** (`.conf`) - the original space-delimited format, compatible with the original rinetd. Simple and easy to use for basic forwarding rules.
- **YAML format** (`.yaml` / `.yml`, version 2.1.0+) - a structured format that adds support for load balancing with multiple backends, health checking, weighted distribution, and client affinity.

The format is detected automatically by file extension. Both formats support the same core features (forwarding rules, access control, global options). Load balancing is available only in YAML format, while the `include` directive is available only in the legacy format.

A Python conversion script is provided to migrate legacy configurations to YAML:

```bash
python3 tools/conf2yaml.py /etc/rinetd-uv.conf > /etc/rinetd-uv.yaml
```

### Forwarding Rules

Forwarding rules define how **rinetd-uv** redirects connections from one address/port to another. Each rule specifies a listening (bind) address and a destination (connect) address.

Both IP addresses and hostnames are accepted, including IPv6. Service names (as defined in `/etc/services`) can be used instead of port numbers.

#### Legacy Format

```
bindaddress bindport connectaddress connectport [options...]
```

For example:

```
206.125.69.81 80  10.1.1.2 80
```

Would redirect all connections to port 80 of the "real" IP address 206.125.69.81, which could be a virtual interface, through **rinetd-uv** to port 80 of the address 10.1.1.2, which would typically be a machine on the inside of a firewall which has no direct routing to the outside world.

Although responding on individual interfaces rather than on all interfaces is one of **rinetd-uv**'s primary features, sometimes it is preferable to respond on all IP addresses that belong to the server. In this situation, the special IP address `0.0.0.0` can be used:

```
0.0.0.0 23  10.1.1.2 23
```

#### YAML Format

In YAML, each forwarding rule is an entry in the `rules` list with a unique `name`, a `bind` address, and a `connect` destination:

```yaml
rules:
  - name: web-forward
    bind: "0.0.0.0:80/tcp"
    connect: "10.1.1.2:80"
```

The `bind` field can be a single address or a list (for fan-in from multiple listeners):

```yaml
rules:
  - name: web-multi
    bind:
      - "0.0.0.0:80/tcp"
      - "0.0.0.0:443/tcp"
      - "[::]:80/tcp"
    connect: "10.1.1.2:80"
```

The `connect` field can be a single destination string or a list of backends (for load balancing):

```yaml
rules:
  - name: web-cluster
    connect:
      - dest: "web1.example.com:8080"
        weight: 2
      - dest: "web2.example.com:8080"
        weight: 1
```

See the **Load Balancing** section for details on multi-backend configuration.

#### Protocol Specification

Ports default to TCP. To specify the protocol, append `/udp` or `/tcp` to the port number:

**Legacy format:**
```
206.125.69.81 80/tcp  10.1.1.2 8000/tcp
0.0.0.0 53/udp  8.8.8.8 53/udp
```

**YAML format:**
```yaml
rules:
  - name: dns-forward
    bind: "0.0.0.0:53/udp"
    connect: "8.8.8.8:53/udp"
```

**Note:** Mixed-mode forwarding (TCP to UDP or UDP to TCP) is not supported.

#### Unix Domain Sockets

**rinetd-uv** supports Unix domain sockets (also known as Unix sockets or local sockets), allowing forwarding between TCP and Unix sockets in any combination:

- **TCP to Unix socket** - Expose a Unix socket service over TCP (e.g. Docker socket proxy)
- **Unix socket to TCP** - Accept connections on a Unix socket and forward to TCP backend
- **Unix to Unix** - Forward between Unix sockets

Unix socket addresses use the `unix:` prefix followed by the socket path:

```
unix:/path/to/socket    # Filesystem socket (absolute path required)
unix:@name              # Abstract namespace socket (Linux only)
```

No port number is required for Unix socket addresses.

**Legacy format examples:**
```
# TCP to Unix - Docker socket proxy
0.0.0.0 2375/tcp unix:/var/run/docker.sock

# Unix to TCP forwarding with restricted permissions
unix:/var/run/myapp.sock 192.168.1.100 8080/tcp [mode=0660]

# Abstract namespace socket (Linux only)
0.0.0.0 9999/tcp unix:@myservice
```

**YAML format examples:**
```yaml
rules:
  - name: docker-proxy
    bind: "0.0.0.0:2375/tcp"
    connect: "unix:/var/run/docker.sock"

  - name: unix-to-tcp
    bind: "unix:/var/run/myapp.sock"
    connect: "192.168.1.100:8080/tcp"
    mode: "0660"
```

**Access control for Unix sockets:**

- For **filesystem sockets**, access is controlled by filesystem permissions on the socket file
- For **TCP endpoints**, the standard allow and deny rules apply
- IP-based access control does not apply to incoming Unix socket connections (access rules in such case will be ignored)
- For **abstract sockets** (Linux), any process in the same network namespace can connect

**Security considerations:**

1. **Filesystem permissions**: By default, the socket file permissions are determined by the process umask. Use `[mode=0660]` (legacy) or `mode: "0660"` (YAML) to set explicit permissions.
2. **Abstract sockets**: Accessible by any process in the same network namespace - use with caution. The `mode` option has no effect on abstract sockets.
3. **Socket cleanup**: Filesystem sockets are automatically removed on shutdown and before bind.

**Limitations:**

- Maximum socket path length varies by system (Linux: 107, BSD: 103, some other systems: 91)
- Unix sockets only support stream mode (SOCK_STREAM); datagram mode (SOCK_DGRAM) or SCTP (SOCK_SEQPACKET) is not supported
- UDP forwarding cannot use Unix sockets
- Abstract namespace sockets are Linux-specific and not portable
- Windows named pipes support is not tested although underlying libuv declares they are covered, report a bug in case you need it.

#### Per-Rule Options

Per-rule options modify the behavior of individual forwarding rules.

**Legacy format** uses square brackets after the rule: `[option=value,option2=value2]`

**YAML format** uses rule-level keys or per-backend keys.

##### UDP Timeout

Since UDP is a connectionless protocol, a timeout is necessary or forwarding connections may accumulate with time and exhaust resources. By default, if no data is sent or received on a UDP connection for 10 seconds, the other connection is closed.

**Legacy format:**
```
0.0.0.0 8000/udp  10.1.1.2 53/udp  [timeout=3600]
```

**YAML format:**
```yaml
rules:
  - name: dns-forward
    bind: "0.0.0.0:8000/udp"
    connect: "10.1.1.2:53/udp"
    timeout: 3600
```

**Note:** rinetd-uv limits UDP connections to 5000 concurrent outgoing connections per forwarding rule (configurable via `max-udp-connections`) to prevent file descriptor exhaustion. When this limit is reached, the oldest (least recently used) connection is automatically closed to make room for new connections.

##### Source Address

A forwarding rule option allows binding to a specific local address when sending data to the other end.

**Legacy format:**
```
192.168.1.1 80  10.1.1.127 80  [src=10.1.1.2]
```

**YAML format:**
```yaml
rules:
  - name: web-forward
    bind: "192.168.1.1:80/tcp"
    connect:
      - dest: "10.1.1.127:80"
        src: 10.1.1.2
```

Assuming the local host has two IP addresses, 10.1.1.1 and 10.1.1.2, this rule ensures that forwarded packets are sent using source address 10.1.1.2.

##### TCP Keepalive

TCP keepalive is enabled by default for all TCP connections to detect dead connections. To disable it for a specific forwarding rule:

**Legacy format:**
```
192.168.1.1 80/tcp  10.1.1.127 80/tcp  [keepalive=off]
```

**YAML format:**
```yaml
rules:
  - name: web-forward
    bind: "192.168.1.1:80/tcp"
    connect: "10.1.1.127:80/tcp"
    keepalive: false
```

When enabled, keepalive probes are sent after 60 seconds of inactivity.

##### Backend Connect Timeout

By default, TCP backend connections rely on the OS timeout (typically 75-127 seconds on Linux). The `connect-timeout` option sets an application-level timeout for backend TCP connect attempts, allowing faster failure detection.

This applies to TCP backend connections only. Unix domain socket connections are instantaneous and do not use the timer.

A value of 0 (the default) means no application timeout — the OS default is used. Recommended values: 5-30 seconds for most deployments.

The timeout can be set globally and overridden per-rule:

**Legacy format:**
```
connect-timeout 10

0.0.0.0 8080/tcp  10.1.1.127 80/tcp
0.0.0.0 8081/tcp  10.1.1.128 80/tcp  [connect-timeout=5]
```

**YAML format:**
```yaml
global:
  connect_timeout: 10

rules:
  - name: web-forward
    bind: "0.0.0.0:8080/tcp"
    connect: "10.1.1.127:80/tcp"
    connect_timeout: 5
```

##### DNS Refresh

For forwarding rules with backend hostnames (not IP addresses), **rinetd-uv** can automatically re-resolve DNS hostnames at configurable intervals. This ensures that if a backend's IP address changes, new connections will use the updated address.

The global default is set via `dns-refresh` / `dns_refresh` (see **Global Options**). Per-rule overrides:

**Legacy format:**
```
0.0.0.0 8080/tcp backend.example.com 80 [dns-refresh=300]
0.0.0.0 8081/tcp backend2.example.com 80 [dns-refresh=0]
```

**YAML format:**
```yaml
rules:
  - name: web-forward
    bind: "0.0.0.0:8080/tcp"
    connect:
      - dest: "backend.example.com:80"
        dns_refresh: 300
```

Setting `dns-refresh=0` / `dns_refresh: 0` disables periodic DNS refresh for that rule/backend.

**Behavior:**

- **Hostname detection:** DNS refresh is only enabled for backend (target) hostnames. Rules with IP addresses (IPv4 or IPv6) automatically skip DNS refresh.
- **Existing connections:** Continue using the old IP address until they close naturally.
- **New connections:** Immediately use the newly resolved IP address.
- **Failure-triggered refresh:** After 3 consecutive connection failures to a backend, DNS is re-resolved immediately (regardless of the timer interval).
- **SIGHUP compatibility:** Sending SIGHUP still forces immediate re-resolution of all hostnames (existing behavior preserved).
- **Multiple IPs:** In case DNS returns multiple addresses for given hostname - the first one will be used; with random order in returned set you may get frequent changes of IP assigned to given rule. See also: **DNS Multi-IP Automatic Load Balancing** in the **Global Options** section.

##### Unix Socket Mode

Set explicit file permissions for Unix domain socket files:

**Legacy format:**
```
unix:/var/run/restricted.sock 192.168.1.100 8080/tcp [mode=0660]
```

**YAML format:**
```yaml
rules:
  - name: restricted-proxy
    bind: "unix:/var/run/restricted.sock"
    connect: "192.168.1.100:8080/tcp"
    mode: "0660"
```

### Access Rules

Configuration files can contain allow and deny rules to control which clients can connect. Patterns can contain the characters: `0`-`9`, `.` (period), `?`, and `*`. The `?` wildcard matches any one character. The `*` wildcard matches any number of characters, including zero.

**Important:** Host names are **NOT** permitted in allow and deny rules. The performance cost of looking up IP addresses to find their corresponding names is prohibitive. Since **rinetd-uv** is a single process server, all other connections would be forced to pause during the address lookup.

#### Legacy Format

In the legacy format, allow and deny rules can be **global** or **per-rule** depending on their position in the configuration file.

**Global rules** appear before the first forwarding rule:

```
# Global access control (before any forwarding rules)
allow 192.168.2.*
deny 192.168.2.1?

# Forwarding rules follow
0.0.0.0 80/tcp 192.168.1.10 8080/tcp
```

- If at least one global allow rule exists, connections not matching any global allow rule are rejected.
- If a connection matches any global deny rule, it is rejected.

**Per-rule access control** appears after a specific forwarding rule:

```
0.0.0.0 22 192.168.1.20 22
allow 10.0.0.*
deny 10.0.0.100
```

- Per-rule allow/deny rules apply only to the preceding forwarding rule.
- The same logic applies: if allow rules exist for a rule, connections must match at least one.

#### YAML Format

In YAML, access control can be **global** (under `global.access`) or **per-rule** (under `rules[].access`).

**Global access rules** apply to all forwarding rules:

```yaml
global:
  access:
    allow:
      - "192.168.*"
      - "10.0.0.*"
    deny:
      - "192.168.1.100"
```

**Per-rule access control** applies only to a specific rule:

```yaml
rules:
  - name: web-forward
    bind: "0.0.0.0:80/tcp"
    connect: "192.168.1.10:8080/tcp"
    access:
      allow:
        - "192.168.*"
        - "10.0.0.*"
      deny:
        - "192.168.1.100"
        - "*"
```

Rules are evaluated in order: global allow rules first, then global deny, then per-rule allow, then per-rule deny. The semantics are identical to the legacy format.

### Global Options

Global options configure server-wide behavior. All settings are optional and have sensible defaults.

| Legacy name | YAML name | Default | Description |
|-------------|-----------|---------|-------------|
| `logfile` | `log_file` | (none) | Path to log file |
| `logcommon` | `log_common` | false | Use Apache-style common log format |
| `pidfile` | `pid_file` | /var/run/rinetd-uv.pid | Path to PID file |
| `buffersize` | `buffer_size` | 65536 | I/O buffer size in bytes (1024-1048576) |
| `dns-refresh` | `dns_refresh` | 600 | Default DNS refresh interval in seconds (0 = disabled) |
| `dns-multi-ip-expand` | `dns_multi_ip_expand` | true (YAML) / false (.conf) | Expand backends when DNS returns multiple IPs |
| `dns-multi-ip-proto` | `dns_multi_ip_proto` | ipv4 | Protocol filter for DNS expansion: `ipv4`, `ipv6`, or `any` |
| `connect-timeout` | `connect_timeout` | 0 | Backend TCP connect timeout in seconds (0 = OS default, max 86400) |
| `pool-min-free` | `pool_min_free` | 64 | Minimum pooled buffers (0-10000) |
| `pool-max-free` | `pool_max_free` | 1024 | Maximum pooled buffers (1-100000) |
| `pool-trim-delay` | `pool_trim_delay` | 60000 | Pool trim delay in milliseconds (100-300000) |
| `listen-backlog` | `listen_backlog` | 128 | TCP listen backlog (1-65535) |
| `max-udp-connections` | `max_udp_connections` | 5000 | Max UDP connections per rule (1-1000000) |
| (N/A) | `status.enabled` | false | Enable status file writing (YAML only) |
| `statusfile` | `status.file` | (none) | Path to status file |
| `statusinterval` | `status.interval` | 30 | Status file write interval in seconds |
| `statusformat` | `status.format` | json | Status file format: `json` or `text` |
| `statsloginterval` | `stats_log_interval` | 60 | Log summary interval in seconds (0 = disabled) |

#### Buffer Size

The buffer size used for I/O operations can be configured globally. This affects memory usage and performance characteristics.

If it's expected that large UDP datagrams are to be processed make sure that `buffersize` is large enough to fit whole datagram (theoretical maximum datagram size is 64KB). Note that on FreeBSD it is required to set sysctl `net.inet.udp.maxdgram=65535` because default value is 9216 on modern versions.

**Recommendations:**
- **DNS proxy (small packets):** `buffersize 4096` - Reduces memory usage (standard DNS packets are limited to 512 bytes but EDNS0 extension allows up to 4KB)
- **HTTP proxy (medium packets):** `buffersize 32768` - Balanced performance
- **High throughput:** `buffersize 131072` - Maximum performance (if memory allows)
- **Memory-constrained systems:** `buffersize 4096` - Minimum practical size

The buffer size multiplied by the number of concurrent connections determines total memory usage. For example, with 1000 concurrent connections:
- `buffersize 4096`: ~4 MB memory
- `buffersize 65536`: ~64 MB memory

#### Buffer Pool

**rinetd-uv** uses a dynamic buffer pool to reduce memory allocation overhead. The pool maintains pre-allocated buffers and lazily trims excess memory after burst traffic subsides.

**Memory behavior:**
- When traffic starts, buffers are allocated from the pool (or via `malloc()` if the pool is empty)
- When traffic ends, buffers are returned to the pool up to `pool-max-free`
- If the pool remains oversized for `pool-trim-delay` milliseconds, excess buffers are freed
- Pool warming pre-allocates `pool-min-free` buffers at startup for consistent initial performance

**Recommendations:**
- **Low traffic servers:** `pool-min-free 16` `pool-max-free 128` - Reduces idle memory usage
- **Burst traffic servers:** `pool-min-free 64` `pool-max-free 2048` - Handles bursts without thrashing
- **High traffic servers:** `pool-min-free 256` `pool-max-free 4096` - Pre-allocated capacity for sustained load
- **Memory-constrained:** `pool-max-free 64` `pool-trim-delay 10000` - Aggressive memory reclamation

#### DNS Configuration

The global DNS refresh interval sets the default for all forwarding rules with backend hostnames. It can be overridden per-rule (see **Per-Rule Options > DNS Refresh**).

##### DNS Multi-IP Automatic Load Balancing

The `dns-multi-ip-expand` / `dns_multi_ip_expand` option enables automatic backend creation when a DNS name resolves to multiple IP addresses. When enabled, rinetd creates separate backend entries for each IP address, allowing automatic load balancing without explicit configuration.

**Format-specific defaults:**
- **YAML format:** Enabled by default (`true`) - modern opt-out behavior
- **Legacy .conf format:** Disabled by default (`false`) - backward compatibility, opt-in

**Legacy format:**
```
dns-multi-ip-expand on
dns-refresh 300

0.0.0.0 8080/tcp web.example.com 80
```

**YAML format:**
```yaml
global:
  dns_multi_ip_expand: true
  dns_refresh: 300

rules:
  - name: web-cluster
    bind: "0.0.0.0:8080/tcp"
    connect:
      - dest: "web.example.com:80"
    load_balancing:
      algorithm: roundrobin
```

**Protocol filtering** (`dns-multi-ip-proto` / `dns_multi_ip_proto`) controls which IP address types are used for expansion:
- **`ipv4`** (default): Only use IPv4 addresses, skip IPv6
- **`ipv6`**: Only use IPv6 addresses, skip IPv4
- **`any`**: Use all addresses (both IPv4 and IPv6)

This is useful when your network doesn't support IPv6 routing or you want to explicitly control the protocol used.

**Behavior:**

When a backend's DNS name resolves to multiple IPs:
- If `dns_multi_ip_expand` is enabled: rinetd creates separate backends named `hostname[0]`, `hostname[1]`, etc., each pointing to one IP address (filtered by protocol)
- If disabled: only the first resolved IP is used (legacy behavior)

**Dynamic updates:** When DNS refresh occurs and the resolved IPs change:
- New IPs are automatically added as new backends
- IPs no longer in DNS are gracefully removed (backends marked unhealthy, connections drained)
- Changes are logged with `[INFO]` messages

**Example log output:**
```
[INFO] DNS for web.example.com resolved to 4 IPs (2 after IPv4 filter), expanding to separate backends
[INFO]   Created implicit backend web.example.com[0] -> 10.0.0.1
[INFO]   Created implicit backend web.example.com[1] -> 10.0.0.2
[INFO] DNS refresh: adding implicit backend for new IP 10.0.0.3
[INFO] DNS refresh: removing implicit backend web.example.com[1] - IP 10.0.0.2 no longer in DNS
```

#### Listen Backlog

The TCP/Unix socket listen backlog determines how many pending connections can queue before the OS starts rejecting new ones. Higher values are useful for servers that handle connection bursts. Lower values are appropriate for low-traffic or resource-constrained environments.

#### Maximum UDP Connections

The maximum number of concurrent UDP connections (backend sockets) per forwarding rule. When this limit is reached, the oldest (least recently used) connection is automatically evicted. Each UDP connection uses a file descriptor, so ensure your system's `ulimit -n` is set high enough to accommodate the configured limit multiplied by the number of UDP forwarding rules.

#### Logging

**rinetd-uv** is able to produce a log file in either of two formats: tab-delimited and web server-style "common log format".

By default, **rinetd-uv** does not produce a log file. To activate logging, set the `logfile` / `log_file` option. By default, **rinetd-uv** logs in a simple tab-delimited format containing the following information:

- Date and time
- Client address
- Listening host
- Listening port
- Forwarded-to host
- Forwarded-to port
- Bytes received from client
- Bytes sent to client
- Result message

To activate web server-style "common log format" logging, enable `logcommon` / `log_common`.

#### Status Reporting

**rinetd-uv** can periodically write a status file containing runtime statistics, useful for monitoring and debugging.

**Legacy format configuration:**

```
statusfile /var/log/rinetd-uv_status.json
statusinterval 30
statusformat json
statsloginterval 60
```

**YAML format configuration:**

```yaml
global:
  status:
    enabled: true
    file: /var/log/rinetd-uv_status.json
    interval: 30
    format: json
  stats_log_interval: 60
```

##### JSON Output Format

The JSON status file includes:

```json
{
  "timestamp": "2026-02-02T12:00:00Z",
  "version": "2.1.0",
  "uptime_seconds": 3600,
  "config_reloads": 2,
  "stats_since_reload": "2026-02-02T11:30:00Z",
  "connections": {
    "active": 150,
    "active_tcp": 120,
    "active_udp": 25,
    "active_unix": 5,
    "total": 50000,
    "total_tcp": 45000,
    "total_udp": 4500,
    "total_unix": 500
  },
  "traffic": {
    "bytes_in": 1073741824,
    "bytes_out": 2147483648
  },
  "errors": {
    "accept": 0,
    "connect": 15,
    "denied": 100
  },
  "buffer_pool": {
    "buffer_size": 65536,
    "free": 128,
    "allocs_from_pool": 50000,
    "allocs_from_malloc": 100
  },
  "servers": 5,
  "rules": [
    {
      "name": "web-cluster",
      "algorithm": "roundrobin",
      "connections_active": 50,
      "connections_total": 10000,
      "bytes_in": 536870912,
      "bytes_out": 1073741824,
      "backends": [
        {
          "name": "web-cluster-backend-1",
          "healthy": true,
          "connections_active": 25,
          "connections_total": 5000,
          "bytes_in": 268435456,
          "bytes_out": 536870912
        }
      ]
    }
  ]
}
```

##### Text Output Format

The text format provides a human-readable summary:

```
rinetd-uv Status Report
Updated: 2026-02-02 12:00:00
Version: 2.1.0
Uptime: 1:00:00
Config reloads: 2

CONNECTIONS
Active: 150 (TCP: 120, UDP: 25, Unix: 5)
Total: 50000 (TCP: 45000, UDP: 4500, Unix: 500)

TRAFFIC
Bytes in: 1.0G
Bytes out: 2.0G

ERRORS
Accept: 0
Connect: 15
Denied: 100

BUFFER POOL
Buffer size: 65536
Free buffers: 128

SERVERS
Count: 5

RULES
  web-cluster (roundrobin):
    Active: 50, Total: 10000, Traffic: 512.0M/1.0G
    Backends:
      web-cluster-backend-1: healthy, active=25, total=5000
```

##### Log Summary Format

The periodic log summary outputs a single line with key metrics:

```
STATS: uptime=3600s conns=150/50000 tcp=120/45000 udp=25/4500 unix=5/500 traffic=1.0G/2.0G errors=0/15/100
```

Format: `conns=active/total`, `traffic=in/out`, `errors=accept/connect/denied`

##### Security Considerations

The status output intentionally omits sensitive information:
- **No IP addresses or hostnames** are exposed in the status file
- Backend servers are identified by their **name** field only
- For YAML rules, backend names are auto-generated as `{rule-name}-backend-{N}` if not explicitly set

### Load Balancing (YAML only)

When a YAML rule has multiple backends, load balancing is automatically enabled. Configure the algorithm and behavior with the `load_balancing` section:

```yaml
rules:
  - name: web-cluster
    bind: "0.0.0.0:80/tcp"
    connect:
      - dest: "web1.internal:8080"
        weight: 2
      - dest: "web2.internal:8080"
        weight: 1
    load_balancing:
      algorithm: roundrobin
      health_threshold: 3
      recovery_timeout: 30
      affinity_ttl: 300
      affinity_max_entries: 10000
```

#### Algorithms

| Algorithm | Description |
|-----------|-------------|
| `roundrobin` | Distributes connections evenly in circular order. With weights, uses smooth weighted round-robin for proportional distribution. |
| `leastconn` | Sends to backend with fewest active connections. Good for varying request durations. |
| `random` | Random selection. Simple and effective for uniform loads. |
| `iphash` | Consistent routing based on client IP hash. Same client always goes to same backend (unless unhealthy). |

**Default:** `roundrobin`

#### Weighted Distribution

Weights control the proportion of traffic each backend receives:

```yaml
connect:
  - dest: "web1.example.com:8080"
    weight: 3    # Receives 3/6 = 50% of traffic

  - dest: "web2.example.com:8080"
    weight: 2    # Receives 2/6 = 33% of traffic

  - dest: "web3.example.com:8080"
    weight: 1    # Receives 1/6 = 17% of traffic
```

Weights are respected by `roundrobin` and `random` algorithms. The `leastconn` algorithm considers weights as a tiebreaker.

#### Health Checking

**rinetd-uv** performs passive health checking based on connection success/failure:

1. **Connection succeeds:** Backend marked healthy, failure counter reset
2. **Connection fails:** Failure counter incremented
3. **Threshold reached:** Backend marked unhealthy after `health_threshold` consecutive failures (default: 3, range: 1-100)
4. **Recovery:** After `recovery_timeout` seconds (default: 30, range: 1-86400), unhealthy backend becomes eligible for retry
5. **All unhealthy:** If all backends are unhealthy, traffic is distributed anyway (fail-open)

**Note:** DNS is automatically re-resolved when a backend reaches the failure threshold.

#### Client Affinity (Session Persistence)

Client affinity ensures the same client IP is routed to the same backend within a time window:

```yaml
load_balancing:
  affinity_ttl: 300            # 5 minutes
  affinity_max_entries: 10000  # Maximum tracked clients
```

- **TTL:** Time-to-live in seconds. Each connection refreshes the timer. (Default: 0 = disabled, max: 2592000)
- **Max entries:** When full, least-recently-used entries are evicted. (Default: 10000, range: 100-10000000)
- **Health-aware:** If the affinity target is unhealthy, a new backend is selected.

#### Per-Backend Options

Each backend in a YAML `connect` list supports these options:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `dest` | string | (required) | Destination address in `host:port/proto` or `unix:path` format |
| `name` | string | auto-generated | Backend name for status/logs |
| `weight` | integer | 1 | Weight for weighted algorithms (1-100) |
| `dns_refresh` | integer | global default | DNS refresh interval override |
| `src` | string | (none) | Source address for outgoing connections |

### Include Directive (legacy format only)

Configuration files can include other configuration files using the `include` directive. This allows splitting large configurations into multiple files for better organization and maintainability.

```
include pattern
```

The `pattern` can be:
- **Single file**: `include servers.conf`
- **Wildcard pattern**: `include conf.d/*.conf`
- **Absolute path**: `include /etc/rinetd-uv/servers.conf`
- **Relative path**: Resolved relative to the current config file's directory

**Features:**

- **Wildcard Support**: Use glob patterns like `*.conf` or `server-*.conf` to include multiple files
- **Nested Includes**: Included files can include other files (up to 10 levels deep)
- **Circular Detection**: Automatically prevents circular includes
- **Depth Limit**: Maximum include depth is 10 levels to prevent infinite recursion
- **Optional Includes**: If a pattern matches no files, a warning is logged but parsing continues
- **Sorted Loading**: When using wildcards, files are loaded in alphabetical order

**Examples:**

```
# Include a single file
include /etc/rinetd-uv.d/database-servers.conf

# Include all .conf files from a directory
include /etc/rinetd-uv.d/*.conf

# Organized configuration structure
logfile /var/log/rinetd-uv.log
pidfile /var/run/rinetd-uv.pid

allow 10.0.0.*
deny 192.168.1.100

include conf.d/web-servers.conf
include conf.d/database-servers.conf
include conf.d/dns-servers.conf
```

**Error handling:**

- **No matches**: If a pattern matches no files, a warning is logged and parsing continues
- **Circular includes**: Detected and causes immediate error
- **Maximum depth exceeded**: More than 10 levels of nesting causes an error
- **File not found**: Individual file errors cause immediate failure
- **Permission denied**: Causes immediate error

## EXAMPLE CONFIGURATION

### Legacy Format

```
# rinetd-uv.conf - example configuration

# Logging
logfile /var/log/rinetd-uv.log
# logcommon  # Use Apache-style logging (default: off)

# PID file (default: /var/run/rinetd-uv.pid)
pidfile /var/run/rinetd-uv.pid

# Buffer size (1024-1048576, default: 65536)
buffersize 65536

# Buffer pool configuration
pool-min-free 64          # Min buffers to keep (0-10000, default: 64)
pool-max-free 1024        # Max buffers before trimming (1-100000, default: 1024)
pool-trim-delay 60000     # Trim delay in milliseconds (100-300000, default: 60000)

# DNS refresh interval (default: 600 seconds = 10 minutes)
dns-refresh 600

# DNS multi-IP expansion (default: off for .conf files)
# dns-multi-ip-expand on
# dns-multi-ip-proto ipv4  # ipv4, ipv6, or any (default: ipv4)

# Listen backlog (1-65535, default: 128)
listen-backlog 128

# Maximum UDP connections per forwarding rule (1-1000000, default: 5000)
max-udp-connections 5000

# Status reporting
statusfile /var/log/rinetd-uv_status.json
statusinterval 30         # Write interval in seconds (default: 30)
statusformat json         # json or text (default: json)
statsloginterval 60       # Log summary interval, 0 to disable (default: 60)

# Global access control (before any forwarding rules)
allow 192.168.2.*
deny 192.168.2.1?
allow fe80:*
deny 2001:618:*:e43f

# Include other configuration files
include /etc/rinetd-uv.d/*.conf
# include conf.d/servers.conf

# TCP forwarding examples
# Format: bindaddress bindport connectaddress connectport [options]
# Options: [timeout=N,src=address,keepalive=on/off,dns-refresh=N,mode=octal]
0.0.0.0 80/tcp 192.168.1.10 8080/tcp
192.168.0.1 https server.example.com 8443 [src=192.168.1.1]
0.0.0.0 444 api.example.com 444 [dns-refresh=60]
:: http ipv6.google.com http

# UDP forwarding example
0.0.0.0 53/udp 8.8.8.8 53/udp [timeout=30]

# Unix domain socket forwarding examples
0.0.0.0 2375/tcp unix:/var/run/docker.sock
unix:/var/run/myapp.sock 192.168.1.100 8080/tcp [mode=0660]

# Per-rule access control (applies to preceding forwarding rule)
0.0.0.0 22 192.168.1.20 22
allow 10.0.0.*

```

### YAML Format

```yaml
# rinetd-uv.yaml - example configuration with load balancing

global:
  # Logging
  log_file: /var/log/rinetd-uv.log
  # log_common: false       # Apache-style logging (default: false)

  # PID file (default: /var/run/rinetd-uv.pid)
  pid_file: /var/run/rinetd-uv.pid

  # Buffer size (1024-1048576, default: 65536)
  buffer_size: 65536

  # Buffer pool configuration
  pool_min_free: 64         # Min buffers to keep (0-10000, default: 64)
  pool_max_free: 1024       # Max buffers before trimming (1-100000, default: 1024)
  pool_trim_delay: 60000    # Trim delay in milliseconds (100-300000, default: 60000)

  # DNS configuration
  dns_refresh: 600          # DNS refresh interval in seconds (default: 600)
  dns_multi_ip_expand: true # Expand multi-IP DNS to backends (default: true for YAML)
  dns_multi_ip_proto: ipv4  # ipv4, ipv6, or any (default: ipv4)

  # Network settings
  listen_backlog: 128       # TCP listen backlog (1-65535, default: 128)
  max_udp_connections: 5000 # Max UDP connections per rule (1-1000000, default: 5000)

  # Status reporting
  status:
    enabled: true
    file: /var/log/rinetd-uv_status.json
    interval: 30            # Write interval in seconds (default: 30)
    format: json            # json or text (default: json)
  stats_log_interval: 60    # Log summary interval, 0 to disable (default: 60)

  # Global access control (applied to all rules before per-rule rules)
  access:
    allow:
      - "10.*"
      - "192.168.*"
    deny:
      - "192.168.1.100"

rules:
  # Simple 1:1 forwarding (equivalent to legacy format)
  - name: simple-forward
    bind: "0.0.0.0:80/tcp"
    connect: "192.168.1.10:8080"

  # Load balanced web servers with weighted round-robin
  - name: web-cluster
    bind:
      - "0.0.0.0:443/tcp"
      - "[::]:443/tcp"
    connect:
      - dest: "web1.internal:8443"
        weight: 3
      - dest: "web2.internal:8443"
        weight: 2
      - dest: "web3.internal:8443"
        weight: 1
    load_balancing:
      algorithm: roundrobin
      health_threshold: 3
      recovery_timeout: 30
    access:
      allow: ["10.*", "192.168.*"]
      deny: ["*"]

  # DNS servers with least-connections algorithm
  - name: dns-lb
    bind: "0.0.0.0:53/udp"
    connect:
      - dest: "8.8.8.8:53/udp"
      - dest: "8.8.4.4:53/udp"
      - dest: "1.1.1.1:53/udp"
    load_balancing:
      algorithm: leastconn
    timeout: 10

  # Application servers with sticky sessions
  - name: app-cluster
    bind: "0.0.0.0:8080/tcp"
    connect:
      - dest: "app1.internal:3000"
        dns_refresh: 60
      - dest: "app2.internal:3000"
        dns_refresh: 60
    load_balancing:
      algorithm: iphash
      affinity_ttl: 3600
      affinity_max_entries: 50000
    keepalive: true

  # Docker socket proxy
  - name: docker-proxy
    bind: "0.0.0.0:2375/tcp"
    connect: "unix:/var/run/docker.sock"
    access:
      allow: ["10.0.0.*"]
      deny: ["*"]
```

## REINITIALIZING RINETD-UV

The SIGHUP signal can be used to cause **rinetd-uv** to reload its configuration file.

**TCP connections** are not interrupted — existing connections continue using cached routing information until they close naturally.

**UDP sessions** are closed on reload. Because UDP is stateless at the transport level, the next packet from a client automatically creates a new session using the updated configuration. This also means that load balancing affinity is reset on reload.

```bash
kill -HUP $(cat /var/run/rinetd-uv.pid)
```

Or simply:

```bash
killall -HUP rinetd-uv
```

## BUGS AND LIMITATIONS

**rinetd-uv** only redirects protocols which use a single TCP or UDP channel. This rules out ancient protocols like FTP or IRC CTCP/DCC.

The server redirected to is not able to identify the host the client really came from. This cannot be corrected; however, the log produced by **rinetd-uv** provides a way to obtain this information.

Two rules with the same effective source ip/port and different destination ip/port are not allowed. With YAML config file problem will be recognized on parsing stage, with legacy config you'll get "Address already in use" or similar error. Note that `0.0.0.0` (IPv4) and `::` (IPv6) effectively mean the same (both would bind to "any" address). Checking may also fail on edge cases like unix: sockets accessed via symlink.

**rinetd-uv** does not implement backpressure (flow control) between the client and backend connections. If one endpoint sends data faster than the other endpoint can receive it, the data waiting to be forwarded will queue up in memory. In extreme cases (e.g., a fast sender paired with a very slow or stalled receiver), this can lead to unbounded memory growth. This is generally not a problem for well-behaved clients and backends, but could be exploited in adversarial scenarios where an attacker deliberately sends data rapidly while receiving slowly.

### Incompatibilities

**rinetd-uv** was meant as drop-in replacement for **rinetd**, although there are some differences

- logging format and behavior changed slightly: date is in the iso8601 format (yyyy-mm-ddThh:mm:ss+tz:tz), for every connection 2 lines are logged - one with 'open' result and one with 'done-' result (this entry contains valid values for transferred data sizes)
- `pidlogfile` option was renamed to `pidfile`
- original rinetd mentioned possibility to proxy traffic between differen protocols (UDP <-> TCP), in **rinetd-uv** it's not possible due to fundamental protocol incompatibilities. See `TCP-UDP_MIXED_MODE.md` for technical details.

## PERFORMANCE NOTES

**rinetd-uv** uses libuv for event-driven I/O, providing excellent performance characteristics:

- Single-process, event-driven architecture
- Dynamic buffer pool with lazy trimming reduces allocation overhead
- Efficient handling of thousands of concurrent connections
- Low CPU overhead per connection

Memory usage can be tuned via the `buffersize` and `pool-*` options. Typical memory usage:
```
Total Memory = bufferSize × pool-max-free  (maximum pooled buffers)
             + bufferSize × active_connections  (in-flight data)
```

For high-performance deployments, consider:
- Using larger buffer sizes (64 KB - 128 KB) for better throughput
- Using smaller buffer sizes (2 KB - 8 KB) when memory is constrained
- Tuning `pool-min-free` to match typical concurrent connection count
- Setting `pool-trim-delay` lower (10-30 seconds) for memory-constrained systems

### Operating system optimization

There are assorted system-level settings that may affect rinetd-uv behavior, especially for higher loads (thousands connections per second or high bandwidth).

#### Open files

Many of UDP-related scenarios require increasing limit of open files:
* local limit (`ulimit -n`)
* global/kernel limit
    - Linux: `fs.file-max` and `fs.nr_open`
    - FreeBSD: `kern.maxfiles` and `kern.maxfilesperproc`

#### Max network buffer size

Rinetd-uv sets both buffer sizes (send and receive, known as SO_SNDBUF and SO_RCVBUF) to twice the value of `buffersize` configuration variable (2 x 64KB by default).
You may try to increase this value if required but operating system limits and behavior may affect possibility to manipulate that.

* FreeBSD - refer to **tuning(7)** man page for details
    - `kern.ipc.maxsockbuf`
    - `net.inet.udp.maxdgram`
    - `net.inet.tcp.sendbuf_max`
    - `net.inet.tcp.recvbuf_max`
    - `net.inet.tcp.sendbuf_auto` -- Send buffer autotuning
    - `net.inet.tcp.recvbuf_auto` -- Receive buffer autotuning
    - `net.inet.tcp.sendspace`
    - `net.inet.tcp.recvspace`
    - `net.local.stream.recvspace` -- unix sockets
    - `net.local.stream.sendspace`
    - `net.local.dgram.maxdgram` -- unix datagram sockets, not supported yet
    - `net.local.dgram.recvspace`

#### Backlog

While it's possible to configure baclog queue length with `backlog` configuration option - there are system level limits as well:

* Linux
    - `net.core.somaxconn`
    - `net.core.netdev_max_backlog`
    - `net.ipv4.tcp_max_syn_backlog`
* FreeBSD
    - `kern.ipc.soacceptqueue`
    - `kern.ipc.somaxconn` -- legacy name

#### Other tuning

There are many parameters that needs to be adjusted in case of demanding environment and specific use cases. Check applicable documentation. Below you can find some tunables that should be checked:

* Linux
    - `net.ipv4.tcp_keepalive_*`
    - `net.ipv4.tcp_mtu_probing`
    - `net.ipv4.tcp_tw_reuse`
    - `net.ipv4.tcp_max_tw_buckets`
    - `net.core.rmem_*`
    - `net.core.wmem_*`
    - `net.ipv4.tcp_rmem`
    - `net.ipv4.tcp_wmem`
    - `net.ipv4.udp_rmem_min`
    - `net.ipv4.udp_wmem_min`
    - `net.ipv4.tcp_mtu_probing`
    - `net.ipv4.ip_local_port_range`
* FreeBSD
    - `kern.ipc.maxpipekva` -- for unix sockets
    - `kern.ipc.nmbclusters`
    - `kern.ipc.nmbjumbop`
    - `net.inet.ip.portrange.*`
    - `net.inet.tcp.always_keepalive`
    - `net.inet.tcp.cc.*`
    - `net.inet.tcp.fast_finwait2_recycle`
    - `net.inet.tcp.minmss`
    - `net.inet.tcp.mssdflt`
    - `net.inet.tcp.rfc1323`
    - `net.inet.tcp.syncache.*`
    - `net.link.ifqmaxlen`

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

This implementation (rinetd-uv since version 2.0.0) was created with support of assorted LLM models and agents (Claude Opus, Claude Sonnet, Gemini, GPT). The architecure and code was always reviewed by human.

## SEE ALSO

### Links

- rinetd-uv: https://github.com/marcin-gryszkalis/rinetd
- original rinetd: https://github.com/samhocevar/rinetd

### Additional Documentation

- [BUILD.md](BUILD.md) - Build requirements and instructions
- [SECURITY.md](SECURITY.md) - Security policy
- [CHANGES.md](CHANGES.md) - Changelog
- [TCP-UDP_MIXED_MODE.md](TCP-UDP_MIXED_MODE.md) - Technical analysis of mixed-mode limitations
