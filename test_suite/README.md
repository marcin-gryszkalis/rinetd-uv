# Rinetd-uv Test Suite

## Prerequisites

- Python 3.13+
- Valgrind (optional, for memory leak detection)
- `rinetd-uv` binary (built from source or available in PATH)

## Operating system limits

Running full test suite may require tuning OS-level parameters. Check **Operating system optimization** section in `DOCUMENTATION.md`.

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
./venv/bin/pytest -v test_suite/test_transfer.py::test_tcp_transfer
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

### test_transfer.py - Data Transfer Tests

Functional tests for basic data forwarding across protocols.

| Test | Description |
|------|-------------|
| `test_tcp_transfer[size]` | TCP-to-TCP forwarding with sizes: 0, 1, 1KB, 64KB, 1MB |
| `test_udp_transfer[size]` | UDP-to-UDP forwarding with sizes: 1, 1KB, 60KB |
| `test_unix_to_tcp` | Unix socket to TCP forwarding |
| `test_tcp_to_unix` | TCP to Unix socket forwarding |
| `test_large_transfer` | 100MB streaming transfer (marked `@slow`) |
| `test_tcp_transfer_ipv6[size]` | IPv6-to-IPv6 forwarding (marked `@ipv6`) |
| `test_ipv4_to_ipv6_forwarding` | IPv4 client to IPv6 backend (marked `@ipv6`) |
| `test_ipv6_to_ipv4_forwarding` | IPv6 client to IPv4 backend (marked `@ipv6`) |

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
| `test_include_directive` | Configuration file includes |
| `test_dns_refresh` | DNS refresh interval |
| `test_source_address` | Source address binding (`src=`) |
| `test_unix_socket_mode` | Unix socket permissions (`mode=`) |
| `test_bind_options` | Per-rule options parsing |
| `test_multiple_tcp_rules` | Multiple forwarding rules in one config |
| `test_mixed_protocol_rules` | TCP, UDP, and Unix rules together |
| `test_per_rule_allow_deny` | Per-rule access control (after forwarding rule) |

### test_matrix.py - Matrix Tests

Multidimensional parametrized tests covering combinations of protocols, sizes, chunk sizes, and parallelism.

**Dimensions:**

| Dimension | Values |
|-----------|--------|
| Protocols | TCP->TCP, TCP->Unix, UDP->UDP, Unix->TCP, Unix->Unix |
| Sizes | 1KB, 64KB, 1MB (`@slow`), 10MB (`@slow`) |
| Chunk Sizes | 1 byte, 1KB, 16KB, 64KB (`@slow`) |
| Parallelism | 1, 2, 5, 10 concurrent clients |

**Total combinations:** 5 x 4 x 4 x 4 = **320 test cases**

Each test runs transfers for 10 seconds with the specified parameters, verifying data integrity using seeded random streams.

### test_stress.py - Stress Tests

Concurrency and load testing with randomized parameters.

| Test | Description |
|------|-------------|
| `test_simple` | Sanity check (always passes) |
| `test_randomized_stress[N]` | N concurrent clients with random parameters |
| `test_randomization_sanity` | Verifies randomization produces sensible values |

**Client counts:** 10 (`@quick`), 50, 100, 500 (`@slow`), 1000 (`@slow`)

**Features:**
- Log-scale randomization for SIZE (1 byte to 10MB) and CHUNK_SIZE
- Intelligent CHUNK_SIZE calculation based on SIZE and protocol
- Graceful stopping at deadline (finishes current chunk, not whole transfer)
- Each thread uses independent RNG for reproducibility

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

### test_big.py - Large Transfer Tests

Tests for very large data transfers (1GB, 8GB, 16GB).

| Test | Description |
|------|-------------|
| `test_big_tcp_upload[size]` | Large upload to server (sizes: 1GB, 8GB, 16GB) |
| `test_big_tcp_download[size]` | Large download from server |
| `test_big_tcp_echo[size]` | Large bidirectional echo transfer |
| `test_big_multiple_concurrent` | 4x1GB parallel transfers |

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
- Progress reporting during transfers
- Bandwidth measurement (MB/s)
- Memory-efficient streaming (never loads full data in memory)
- SHA256 verification for data integrity

## Test Architecture

### Directory Structure

```
test_suite/
├── conftest.py           # Pytest configuration and fixtures
├── servers.py            # Server implementations (Echo, Upload, Download, SHA256)
├── utils.py              # Helper functions and utilities
├── test_transfer.py      # Basic transfer tests (TCP, UDP, Unix, IPv6)
├── test_config.py        # Configuration directive tests
├── test_matrix.py        # Matrix parametrized tests
├── test_stress.py        # Stress and concurrency tests
├── test_leaks.py         # Valgrind leak detection tests
├── test_reload.py        # SIGHUP reload tests
├── test_error_handling.py # Error recovery tests
├── test_big.py           # Very large transfer tests (1GB+)
├── requirements.txt      # Python dependencies
└── README.md             # This file
```

### Fixtures

| Fixture | Scope | Description |
|---------|-------|-------------|
| `rinetd_path` | session | Path to rinetd-uv executable |
| `rinetd` | function | Starts rinetd-uv with given rules |
| `tcp_echo_server` | function | TCP echo backend server |
| `tcp_echo_server_ipv6` | function | IPv6 TCP echo backend server |
| `udp_echo_server` | function | UDP echo backend server |
| `unix_echo_server` | function | Unix socket echo backend server |
| `tcp_upload_server` | function | Server that accepts uploads, returns byte count |
| `tcp_download_server` | function | Server that generates seeded random data |
| `tcp_upload_sha256_server` | function | Server that returns rolling SHA256 of uploads |
| `tcp_download_sha256_server` | function | Server that verifies client's rolling SHA256 |

### Test Servers

The test suite includes built-in servers for various transfer patterns. These run in background threads and are automatically started/stopped by fixtures.

**Echo Servers** - Reflect all received data back:
- **TcpEchoServer**: Threaded TCP server, handles multiple concurrent clients
- **TcpEchoServerIPv6**: IPv6 version of TCP echo server
- **UdpEchoServer**: Datagram-based UDP server
- **UnixEchoServer**: Unix domain socket server

**Alternative Transfer Mode Servers** - For asymmetric data flows:
- **TcpUploadServer**: Accepts uploads, discards data, returns byte count
- **TcpDownloadServer**: Generates seeded random data stream for client to receive
- **TcpUploadSha256Server**: Returns rolling SHA256 hash after each received chunk
- **TcpDownloadSha256Server**: Sends data and verifies client's rolling SHA256

The alternative modes enable testing of:
- Upload-only scenarios (backpressure handling)
- Download-only scenarios (flow control)
- Chunk-level data integrity verification via SHA256

### Data Verification

Tests use `SeededRandomStream` for reproducible random data generation. Both sender and receiver use the same seed to generate/verify data, ensuring integrity without storing large amounts in memory.

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

### Valgrind tests fail

- Ensure Valgrind is installed: `valgrind --version`
- Valgrind adds significant overhead; tests may timeout
- Check Valgrind output in test stderr for details

### Port binding errors

- The test suite uses random available ports
- If you see "Address already in use", wait and retry
- Check for zombie rinetd processes: `pkill -9 rinetd`

### Log file issues

- Test log files are created in pytest's `tmp_path` (auto-cleaned)
- Check `/tmp/pytest-*` for debug logs if tests fail

## Contributing

When adding new tests:

1. Use appropriate markers (`@pytest.mark.quick`, `@pytest.mark.slow`)
2. Use fixtures for rinetd and echo servers
3. Clean up resources in finally blocks
4. Use `SeededRandomStream` for large data verification
5. Add test documentation to this README
