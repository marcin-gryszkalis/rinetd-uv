# rinetd Test Suite

This directory contains test scripts for rinetd.

## Test Scripts

### test_parallel_connections.py

Tests rinetd TCP forwarding under high concurrent load.

**Usage:**
```bash
# Run with defaults (127.0.0.1:8080, 100 parallel connections, single batch)
python3 test_parallel_connections.py

# Custom host and port
python3 test_parallel_connections.py --host 192.168.1.1 --port 9000

# Test with 200 parallel connections
python3 test_parallel_connections.py --connections 200

# Continuous stress test: 50 workers connecting repeatedly for 60 seconds
python3 test_parallel_connections.py --connections 50 --duration 60

# Quiet mode (less output)
python3 test_parallel_connections.py --quiet

# Show all options
python3 test_parallel_connections.py --help
```

**Example Test Setup:**

1. Configure rinetd to forward local port 8080 to a remote HTTP server:
   ```
   # /tmp/rinetd-test.conf
   127.0.0.1 8080 example.com 80
   ```

2. Start rinetd:
   ```bash
   ./rinetd -f -c /tmp/rinetd-test.conf
   ```

3. Run the test:
   ```bash
   python3 test/test_parallel_connections.py
   ```

**What it tests:**
- Concurrent TCP connection handling
- HTTP request/response forwarding
- Connection stability under load
- Throughput measurement

**Test Modes:**
- **Single batch mode** (default): Makes N parallel connections once and reports results
- **Continuous mode** (`--duration N`): Runs N worker threads that continuously make connections for the specified duration, providing sustained load testing
