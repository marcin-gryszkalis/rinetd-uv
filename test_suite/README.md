# Rinetd-uv Test Suite

## Prerequisites

- Python 3.13+
- Valgrind (optional, for memory leak detection)
- `rinetd-uv` binary (built from source or available in PATH)

## Operating system limits

Running full test suite may require tuning OS-level parameters. Check **Operating system optimization** section in `DOCUMENTATION.md`.

**FreeBSD-specific requirement:**

On FreeBSD, configure loopback IPs for testing:
```bash
# Add test IPs (as root, needed once per boot)
sudo ifconfig lo0 alias 127.0.0.2
sudo ifconfig lo0 alias 127.0.0.3
```

On Linux, these IPs work automatically (127.0.0.0/8 is loopback).

## Setup

1. Create a virtual environment:
   ```bash
   python3 -m venv venv
   ```

2. Install dependencies:
   ```bash
   ./venv/bin/pip install -r requirements.txt
   ```

## Running Tests

### Basic Usage

Run all tests:
```bash
./venv/bin/pytest -v
```

Run only quick tests (recommended for development):
```bash
./venv/bin/pytest -v -m quick
```

Run excluding slow tests:
```bash
./venv/bin/pytest -v -m "not slow"
```

### Advanced Options

Specify custom path to `rinetd-uv`:
```bash
./venv/bin/pytest -v --rinetd-path /path/to/rinetd-uv
```

Run with Valgrind leak detection:
```bash
./venv/bin/pytest -v --valgrind
```

Run specific test file:
```bash
./venv/bin/pytest -v test_suite/test_transfer.py
```

Run specific test:
```bash
./venv/bin/pytest -v test_suite/test_transfer.py::test_zero_byte_transfer
```

Run tests in parallel (requires pytest-xdist):
```bash
./venv/bin/pytest -v -n auto
```

## Test Markers

| Marker | Description |
|--------|-------------|
| `@pytest.mark.quick` | Fast tests suitable for rapid feedback during development |
| `@pytest.mark.slow` | Long-running tests (large transfers, high concurrency) |
| `@pytest.mark.valgrind` | Tests specifically for Valgrind memory leak detection |
| `@pytest.mark.reload` | Tests for SIGHUP configuration reload functionality |
| `@pytest.mark.ipv6` | Tests requiring IPv6 support |
| `@pytest.mark.big` | Very large transfer tests (1GB+), requires significant time/resources |
| `@pytest.mark.expect_rinetd_errors` | Tests that intentionally trigger rinetd errors (stderr check disabled) |

### Marker Examples

```bash
# Run only quick tests
./venv/bin/pytest -m quick

# Run everything except slow and big tests
./venv/bin/pytest -m "not slow and not big"

# Run valgrind-specific tests
./venv/bin/pytest -m valgrind --valgrind

# Run reload tests only
./venv/bin/pytest -m reload

# Run IPv6 tests only
./venv/bin/pytest -m ipv6

# Run big transfer tests (may take hours)
./venv/bin/pytest -m big --timeout=86400
```

## Command-Line Options

| Option | Description |
|--------|-------------|
| `--rinetd-path PATH` | Path to rinetd-uv executable (auto-detected if not specified) |
| `--valgrind` | Run rinetd-uv under Valgrind for leak detection |

## Test Modules

### test_transfer.py - IPv6 and Edge Case Tests

Focused tests for IPv6 support and edge cases not covered by comprehensive matrix tests.

| Test | Description |
|------|-------------|
| `test_zero_byte_transfer` | Zero-byte transfer edge case (connection handling) |
| `test_tcp_transfer_ipv6[size]` | IPv6-to-IPv6 forwarding with sizes: 1, 1KB, 64KB (marked `@ipv6`) |
| `test_ipv4_to_ipv6_forwarding` | IPv4 client to IPv6 backend (marked `@ipv6`) |
| `test_ipv6_to_ipv4_forwarding` | IPv6 client to IPv4 backend (marked `@ipv6`) |

**Note:** For comprehensive protocol/size testing, see test_matrix.py.

### test_matrix.py - Comprehensive Matrix Tests

**Architecture:** 1:1 client-server pairs - each parallel client gets its own dedicated backend server, eliminating server contention and testing pure rinetd multiplexing performance.

Multidimensional parametrized tests covering all combinations of protocols, server modes, sizes, chunk sizes, and parallelism.

**Dimensions:**

| Dimension | Values |
|-----------|--------|
| Protocols | tcp→tcp, tcp→unix, udp→udp, unix→tcp, unix→unix |
| Server Modes | echo, upload, download, upload_sha256, download_sha256 |
| Sizes | 1KB, 64KB, 1MB (`@slow`), 10MB (`@slow`) |
| Chunk Sizes | 1 byte, 1KB, 16KB, 64KB (`@slow`) |
| Parallelism | 1, 2, 5, 10 concurrent clients |

**Total combinations:** 5 protocols × 5 modes × 4 sizes × 4 chunks × 4 parallelism = **1,600 test cases**

Each test runs transfers for 10 seconds with the specified parameters, verifying data integrity using seeded random streams.

**Example:**
- With parallelism=5: Creates 5 dedicated backend servers, 5 rinetd rules, 5 clients
- All 5 pairs run simultaneously for 10 seconds
- 100% success expected (no server contention)

### test_stress.py - Randomized Stress Tests

**Architecture:** 1:1 client-server pairs with randomized parameters per pair.

Multimodal stress testing with fully randomized protocol combinations, transfer modes, sizes, and chunk sizes.

| Test | Description |
|------|-------------|
| `test_simple` | Sanity check (always passes) |
| `test_randomized_stress[N]` | N concurrent pairs with random parameters each |
| `test_randomization_sanity` | Verifies randomization produces sensible values |

**Pair counts:** 10 (`@quick`), 50, 100, 500 (`@slow`), 1000 (`@slow`)

**Randomization per pair:**
- **Protocol:** Random from tcp→tcp, tcp→unix, udp→udp, unix→tcp, unix→unix
- **Mode:** Random from echo, upload, download, upload_sha256, download_sha256 (filtered by protocol compatibility)
- **Size:** Log-scale distribution from 1 byte to 10MB
- **Chunk size:** Intelligent calculation based on size and protocol limits

**Example with 100 pairs:**
```
Pair 0: tcp→unix, 45KB, 8KB chunks, download_sha256 mode
Pair 1: udp→udp, 2KB, 512B chunks, echo mode
Pair 2: unix→tcp, 1MB, 64KB chunks, upload mode
...
```

All 100 pairs run simultaneously for the stress duration (60s default, configurable via `STRESS_DURATION` env var).

### test_big.py - Large Transfer Tests

**Architecture:** 1:1 client-server pairs - each test creates its own dedicated backend server.

Tests for very large data transfers (1GB, 8GB, 16GB).

| Test | Description |
|------|-------------|
| `test_big_tcp_upload[size]` | Large upload to dedicated server (sizes: 1GB, 8GB, 16GB) |
| `test_big_tcp_download[size]` | Large download from dedicated server |
| `test_big_tcp_echo[size]` | Large bidirectional echo transfer with dedicated server |
| `test_big_multiple_concurrent` | 4 parallel 1GB transfers with 4 dedicated servers (2 upload, 2 download) |

**Marker:** `@pytest.mark.big`

**Usage:**
```bash
# Run all big tests (may take several hours)
./venv/bin/pytest -v -m big --timeout=86400

# Run only 1GB tests
./venv/bin/pytest -v -m big -k "1GB"
```

**Features:**
- Optimal 64KB chunk size for maximum throughput
- Progress reporting every 100MB
- Bandwidth measurement (MB/s)
- Memory-efficient streaming (never loads full data in memory)
- SHA256 verification for echo mode data integrity
- Each test creates fresh dedicated backend server (no contention)

### test_config.py - Configuration Tests

Tests for rinetd configuration directives and options.

| Test | Description |
|------|-------------|
| `test_allow_rule` | Global `allow` access control |
| `test_deny_rule` | Global `deny` access control |
| `test_allow_wildcard_star` | Wildcard `*` pattern matching (e.g., `127.0.0.*`) |
| `test_deny_wildcard_star` | Deny with wildcard patterns |
| `test_allow_wildcard_question` | Single-char `?` wildcard matching |
| `test_allow_all_wildcard` | Allow all with `*` |
| `test_logfile` | Log file creation and content |
| `test_logcommon` | Apache common log format |
| `test_pidfile` | PID file creation |
| `test_buffersize` | Buffer size configuration |
| `test_keepalive` | TCP keepalive option |
| `test_include_basic` | Basic configuration file includes |
| `test_include_wildcard` | Include with wildcard patterns (`*.conf`) |
| `test_include_nested` | Nested includes (3 levels) |
| `test_include_circular_detection` | Circular include detection |
| `test_include_max_depth` | Maximum include depth limit (10 levels) |
| `test_include_relative_path` | Relative path resolution |
| `test_include_no_match_warning` | Warning when include pattern matches no files |
| `test_dns_refresh` | DNS refresh interval |
| `test_source_address` | Source address binding (`src=`) |
| `test_unix_socket_mode` | Unix socket permissions (`mode=`) |
| `test_bind_options` | Per-rule options parsing |
| `test_multiple_tcp_rules` | Multiple forwarding rules in one config |
| `test_mixed_protocol_rules` | TCP, UDP, and Unix rules together |
| `test_per_rule_allow_deny` | Per-rule access control (after forwarding rule) |

### test_leaks.py - Memory Leak Tests

Valgrind-based memory and file descriptor leak detection.

| Test | Description |
|------|-------------|
| `test_memory_leaks_tcp` | TCP transfer leak detection |
| `test_memory_leaks_udp` | UDP transfer leak detection |
| `test_memory_leaks_rapid_connections` | Rapid connect/disconnect cycles |

**Requirements:** Valgrind must be installed. Tests are skipped if unavailable.

### test_reload.py - SIGHUP Reload Tests

Tests for configuration reload via SIGHUP signal.

| Test | Description |
|------|-------------|
| `test_sighup_adds_new_rule` | New forwarding rules after SIGHUP |
| `test_sighup_preserves_existing_connections` | Active connections survive reload |
| `test_sighup_multiple_reloads` | Multiple consecutive reloads |
| `test_sighup_under_load` | Config reload while handling active traffic |

**Marker:** `@pytest.mark.reload`

### test_error_handling.py - Error Recovery Tests

Tests for error conditions and recovery scenarios.

| Test | Description |
|------|-------------|
| `test_backend_unavailable_at_start` | Behavior when backend is down |
| `test_backend_becomes_available` | Recovery when backend comes up |
| `test_backend_goes_down_and_recovers` | Backend failure and recovery cycle |
| `test_client_disconnect_mid_transfer` | Graceful handling of client disconnect |
| `test_rapid_connect_disconnect` | Resource exhaustion prevention |
| `test_half_close_handling` | TCP half-close (shutdown) support |
| `test_connection_timeout_backend_slow` | Slow backend connection handling |

## Test Architecture

### Directory Structure

```
test_suite/
├── conftest.py           # Pytest configuration and fixtures
├── servers.py            # Server implementations (Echo, Upload, Download, SHA256)
├── utils.py              # Helper functions, utilities, and 1:1 pair orchestration
├── test_transfer.py      # IPv6 and edge case tests
├── test_config.py        # Configuration directive tests
├── test_matrix.py        # Comprehensive matrix tests (1:1 architecture)
├── test_stress.py        # Randomized stress tests (1:1 architecture)
├── test_leaks.py         # Valgrind leak detection tests
├── test_reload.py        # SIGHUP reload tests
├── test_error_handling.py # Error recovery tests
├── test_big.py           # Very large transfer tests (1:1 architecture)
├── requirements.txt      # Python dependencies
└── README.md             # This file
```

### 1:1 Client-Server Pair Architecture

**Modern test architecture** (test_matrix.py, test_stress.py, test_big.py):

Instead of N clients sharing 1 server, each client gets its own dedicated backend server:

```
Traditional (N:1):                 Modern (1:1):
Client1 ─┐                         Client1 → rinetd → Server1
Client2 ─┼→ rinetd → Server        Client2 → rinetd → Server2
Client3 ─┘                         Client3 → rinetd → Server3
```

**Benefits:**
- **Eliminates server contention** - Tests rinetd's multiplexing, not server limits
- **100% success rate** - No timeouts from server overload
- **Scales to 1000+ pairs** - Each pair is independent
- **Realistic** - Production rinetd forwards to many different backends

**Fixed IPs with Port Range Allocation:**

To avoid port conflicts with 500-1000 concurrent pairs, we use fixed loopback IPs with allocated port ranges:

- **Rinetd listen addresses:** `127.0.0.2:20000+pair_id`
- **Backend server addresses:** `127.0.0.3:20000+pair_id`
- **Port range:** 20000-65535 (supports up to 45,535 concurrent pairs)

**Example:**
- Pair 0: Client connects to `127.0.0.2:20000` (rinetd) → rinetd forwards to `127.0.0.3:20000` (backend)
- Pair 1: Client connects to `127.0.0.2:20001` (rinetd) → rinetd forwards to `127.0.0.3:20001` (backend)
- Pair 100: Client connects to `127.0.0.2:20100` (rinetd) → rinetd forwards to `127.0.0.3:20100` (backend)

**FreeBSD Setup:**

On FreeBSD, loopback IPs must be explicitly configured:
```bash
# Add test IPs to loopback interface (as root)
sudo ifconfig lo0 alias 127.0.0.2
sudo ifconfig lo0 alias 127.0.0.3

# Verify
ifconfig lo0 | grep 127.0.0
```

On Linux, 127.0.0.2 and 127.0.0.3 work automatically (entire 127.0.0.0/8 is loopback).

**Two-Phase Barrier Synchronization:**

```python
# Phase 1: Workers create backend servers and build rinetd rules
servers_ready_barrier.wait()  # All servers ready
→ Main thread starts rinetd with all rules
→ Main thread verifies rinetd is listening

# Phase 2: Main thread signals rinetd is ready
rinetd_ready_barrier.wait()   # All clients start transfers
→ Workers run transfers for specified duration
```

This ensures:
1. All backend servers are ready before rinetd starts
2. rinetd is fully initialized before clients connect
3. All clients start simultaneously (fair testing)

### Fixtures

**Shared Fixtures** (used by test_config.py, test_error_handling.py, etc.):

| Fixture | Scope | Description |
|---------|-------|-------------|
| `rinetd_path` | session | Path to rinetd-uv executable |
| `rinetd` | function | Starts rinetd-uv with given rules, checks stderr for errors |
| `tcp_echo_server` | function | TCP echo backend server |
| `tcp_echo_server_ipv6` | function | IPv6 TCP echo backend server |
| `udp_echo_server` | function | UDP echo backend server |
| `unix_echo_server` | function | Unix socket echo backend server |
| `tcp_upload_server` | function | Server that accepts uploads, returns byte count |
| `tcp_download_server` | function | Server that generates seeded random data |
| `tcp_upload_sha256_server` | function | Server that returns rolling SHA256 of uploads |
| `tcp_download_sha256_server` | function | Server that verifies client's rolling SHA256 |
| `udp_upload_sha256_server` | function | UDP version of SHA256 upload server |
| `udp_download_sha256_server` | function | UDP version of SHA256 download server |
| `unix_upload_server` | function | Unix socket upload server |
| `unix_download_server` | function | Unix socket download server |
| `unix_upload_sha256_server` | function | Unix socket SHA256 upload server |
| `unix_download_sha256_server` | function | Unix socket SHA256 download server |

**1:1 Architecture** (test_matrix.py, test_stress.py, test_big.py):

Tests using 1:1 architecture create servers dynamically using:
- `create_backend_server(protocol, mode, socket_path=None, host='127.0.0.1')` - Factory function
- `run_parallel_pairs(pairs_config, rinetd_starter, duration, tmp_path)` - Orchestrates N pairs

### Test Servers

The test suite includes built-in servers for various transfer patterns. These run in background threads and are automatically started/stopped.

**Echo Servers** - Reflect all received data back:
- **TcpEchoServer**: Threaded TCP server, handles multiple concurrent clients
- **TcpEchoServerIPv6**: IPv6 version of TCP echo server
- **UdpEchoServer**: Datagram-based UDP server with 2MB buffers
- **UnixEchoServer**: Unix domain socket server

**Upload/Download Servers** - For asymmetric data flows:
- **TcpUploadServer**: Accepts uploads, discards data, returns byte count
- **TcpDownloadServer**: Generates seeded random data stream for client to receive
- **TcpUploadSha256Server**: Returns rolling SHA256 hash after each received chunk
- **TcpDownloadSha256Server**: Sends data and verifies client's rolling SHA256
- **UdpUploadSha256Server**: UDP version with datagram-based SHA256
- **UdpDownloadSha256Server**: UDP version, sends data + SHA256 per packet
- **UnixUploadServer**, **UnixDownloadServer**: Unix socket versions
- **UnixUploadSha256Server**, **UnixDownloadSha256Server**: Unix socket SHA256 versions

**Server Modes:**
- **echo** - Bidirectional: client sends data, receives it back
- **upload** - Unidirectional: client sends data, server returns byte count
- **download** - Unidirectional: client receives seeded random data
- **upload_sha256** - Upload with chunk-level SHA256 verification
- **download_sha256** - Download with chunk-level SHA256 verification

### Data Verification

Tests use `SeededRandomStream` for reproducible random data generation. Both sender and receiver use the same seed to generate/verify data, ensuring integrity without storing large amounts in memory.

**SHA256 Modes:**
- Generate rolling hash: `hasher.update(chunk)` after each chunk
- Compare hashes at end to verify all data was transferred correctly
- Catches corruption, truncation, or data loss

### Error Detection

**Automatic stderr checking:** The rinetd fixture automatically checks rinetd's stderr output after each test:
- Fails test if rinetd logged errors or warnings (unless test is marked `@pytest.mark.expect_rinetd_errors`)
- Filters benign errors: "connection reset by peer", "broken pipe"
- Ensures rinetd runs cleanly without unexpected errors

## IPv6 Testing

IPv6 tests require `::1` loopback to be available. Tests automatically skip if IPv6 is unavailable.

To verify IPv6 is working:
```bash
ping6 -c 1 ::1
```

If IPv6 loopback is disabled, enable it (requires root):
```bash
# Linux - temporary
sudo sysctl -w net.ipv6.conf.lo.disable_ipv6=0

# Linux - permanent (add to /etc/sysctl.conf)
net.ipv6.conf.lo.disable_ipv6=0
```

## Troubleshooting

### Tests timeout or hang

- Check if rinetd-uv binary exists and is executable
- Verify no other process is using the test ports
- Try running with `-v` for verbose output
- Check system resource limits (`ulimit -n` for file descriptors)
- For stress tests with 500-1000 pairs, increase file descriptor limit (see DOCUMENTATION.md)

### Valgrind tests fail

- Ensure Valgrind is installed: `valgrind --version`
- Valgrind adds significant overhead; tests may timeout
- Check Valgrind output in test stderr for details

### Port binding errors ("Address already in use")

- Modern 1:1 architecture uses fixed IPs (127.0.0.2, 127.0.0.3) with port range 20000-65535
- Conflicts should be rare (port range starts at 20000, avoiding common services)
- On **FreeBSD**, ensure test IPs are configured: `sudo ifconfig lo0 alias 127.0.0.2` and `sudo ifconfig lo0 alias 127.0.0.3`
- On **Linux**, 127.0.0.2 and 127.0.0.3 work automatically
- If you see errors, check for zombie rinetd processes: `pkill -9 rinetd-uv`
- Ensure nothing else is using ports 20000+ on 127.0.0.2 or 127.0.0.3

### Barrier timeouts with large stress tests

- Default barrier timeout is 60 seconds (configurable via `BARRIER_TIMEOUT` in utils.py)
- With 1000 pairs, initialization can take time - timeout may need increase
- Check for system resource exhaustion (file descriptors, memory)

### Log file issues

- Test log files are created in pytest's `tmp_path` (auto-cleaned)
- Check `/tmp/pytest-*` for debug logs if tests fail

## Contributing

When adding new tests:

1. Use appropriate markers (`@pytest.mark.quick`, `@pytest.mark.slow`, `@pytest.mark.expect_rinetd_errors`)
2. For concurrent/parallel tests, use 1:1 architecture via `run_parallel_pairs()`
3. For simple tests, use shared server fixtures from conftest.py
4. Clean up resources in finally blocks
5. Use `SeededRandomStream` for large data verification
6. Add test documentation to this README
7. Ensure tests check rinetd stderr (or mark with `@pytest.mark.expect_rinetd_errors` if errors are expected)
