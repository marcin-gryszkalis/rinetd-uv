"""
Load balancing tests for rinetd-uv YAML configuration.

Tests cover:
- Many:1 mode (multiple listeners to single backend)
- Many:many mode (multiple listeners to multiple backends)
- Mixed backends (unix/tcp)
- All LB algorithms with 2-5 backends
- Health monitoring (backend failure and recovery)
"""
import pytest
import socket
import os
import time
import tempfile
import threading
import subprocess
from collections import Counter
from .utils import get_free_port, wait_for_port
from .servers import TcpEchoServer, UdpEchoServer, UnixEchoServer


def create_yaml_config(yaml_content, filename=None):
    """Create a YAML configuration file and return its path."""
    if filename is None:
        fd, filename = tempfile.mkstemp(suffix='.yaml', prefix='rinetd_test_')
        os.close(fd)
    with open(filename, 'w') as f:
        f.write(yaml_content)
    return filename


def run_rinetd_yaml(rinetd_path, yaml_content, tmp_path):
    """Start rinetd with a YAML config and return the process."""
    config_file = str(tmp_path / "test.yaml")
    with open(config_file, 'w') as f:
        f.write(yaml_content)

    process = subprocess.Popen(
        [rinetd_path, "-f", "-c", config_file],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True
    )
    time.sleep(0.3)

    if process.poll() is not None:
        stdout, stderr = process.communicate()
        pytest.fail(f"rinetd failed to start:\nStdout: {stdout}\nStderr: {stderr}")

    return process


def stop_rinetd(process):
    """Stop a rinetd process cleanly."""
    if process and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


class IdentifyingTcpServer(threading.Thread):
    """TCP server that responds with its ID to identify which backend handled request."""

    def __init__(self, server_id, host='127.0.0.1', port=0):
        super().__init__()
        self.server_id = server_id
        self.host = host
        self.port = port
        self.actual_port = 0
        self.running = True
        self.ready = threading.Event()
        self.connection_count = 0
        self.daemon = True

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))
            self.actual_port = sock.getsockname()[1]
            sock.listen(128)
            sock.settimeout(0.5)
            self.ready.set()

            while self.running:
                try:
                    conn, _ = sock.accept()
                    self.connection_count += 1
                    threading.Thread(target=self._handle, args=(conn,), daemon=True).start()
                except socket.timeout:
                    continue
                except OSError:
                    break

    def _handle(self, conn):
        try:
            data = conn.recv(1024)
            if data:
                response = f"SERVER_{self.server_id}".encode()
                conn.sendall(response)
        except (OSError, BrokenPipeError):
            pass
        finally:
            conn.close()

    def stop(self):
        self.running = False
        self.join(timeout=2)

    def wait_ready(self, timeout=5):
        return self.ready.wait(timeout)


class IdentifyingUnixServer(threading.Thread):
    """Unix socket server that responds with its ID."""

    def __init__(self, server_id, path):
        super().__init__()
        self.server_id = server_id
        self.path = path
        self.running = True
        self.ready = threading.Event()
        self.connection_count = 0
        self.daemon = True

    def run(self):
        if os.path.exists(self.path):
            os.unlink(self.path)

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.bind(self.path)
            sock.listen(128)
            sock.settimeout(0.5)
            self.ready.set()

            while self.running:
                try:
                    conn, _ = sock.accept()
                    self.connection_count += 1
                    threading.Thread(target=self._handle, args=(conn,), daemon=True).start()
                except socket.timeout:
                    continue
                except OSError:
                    break

        if os.path.exists(self.path):
            try:
                os.unlink(self.path)
            except OSError:
                pass

    def _handle(self, conn):
        try:
            data = conn.recv(1024)
            if data:
                response = f"SERVER_{self.server_id}".encode()
                conn.sendall(response)
        except (OSError, BrokenPipeError):
            pass
        finally:
            conn.close()

    def stop(self):
        self.running = False
        self.join(timeout=2)

    def wait_ready(self, timeout=5):
        return self.ready.wait(timeout)


def send_request_tcp(host, port, data=b"PING"):
    """Send a request to TCP server and return response."""
    with socket.create_connection((host, port), timeout=5) as s:
        s.sendall(data)
        return s.recv(1024).decode()


def send_request_unix(path, data=b"PING"):
    """Send a request to Unix socket server and return response."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect(path)
        s.sendall(data)
        return s.recv(1024).decode()


# =============================================================================
# Many:1 Mode Tests
# =============================================================================

class TestManyToOne:
    """Tests for many:1 mode (multiple listeners to single backend)."""

    def test_two_listeners_one_backend_tcp(self, rinetd_path, tmp_path):
        """Two TCP listeners forwarding to one TCP backend."""
        server = IdentifyingTcpServer(1)
        server.start()
        server.wait_ready()

        listen_port1 = get_free_port()
        listen_port2 = get_free_port()

        yaml_config = f"""
global:
  buffer_size: 65536

rules:
  - name: two-to-one
    bind:
      - "127.0.0.1:{listen_port1}/tcp"
      - "127.0.0.1:{listen_port2}/tcp"
    connect: "127.0.0.1:{server.actual_port}"
"""
        process = run_rinetd_yaml(rinetd_path, yaml_config, tmp_path)
        try:
            assert wait_for_port(listen_port1)
            assert wait_for_port(listen_port2)

            # Both listeners should forward to the same backend
            resp1 = send_request_tcp('127.0.0.1', listen_port1)
            resp2 = send_request_tcp('127.0.0.1', listen_port2)

            assert resp1 == "SERVER_1"
            assert resp2 == "SERVER_1"
            assert server.connection_count >= 2
        finally:
            stop_rinetd(process)
            server.stop()

    def test_three_listeners_one_backend_mixed(self, rinetd_path, tmp_path):
        """Three listeners (2 TCP, 1 Unix) to one TCP backend."""
        server = IdentifyingTcpServer(1)
        server.start()
        server.wait_ready()

        listen_port1 = get_free_port()
        listen_port2 = get_free_port()
        unix_path = str(tmp_path / "listen.sock")

        yaml_config = f"""
global:
  buffer_size: 65536

rules:
  - name: three-to-one
    bind:
      - "127.0.0.1:{listen_port1}/tcp"
      - "127.0.0.1:{listen_port2}/tcp"
      - "unix:{unix_path}"
    connect: "127.0.0.1:{server.actual_port}"
"""
        process = run_rinetd_yaml(rinetd_path, yaml_config, tmp_path)
        try:
            assert wait_for_port(listen_port1)
            assert wait_for_port(listen_port2)
            time.sleep(0.2)
            assert os.path.exists(unix_path)

            resp1 = send_request_tcp('127.0.0.1', listen_port1)
            resp2 = send_request_tcp('127.0.0.1', listen_port2)
            resp3 = send_request_unix(unix_path)

            assert resp1 == "SERVER_1"
            assert resp2 == "SERVER_1"
            assert resp3 == "SERVER_1"
        finally:
            stop_rinetd(process)
            server.stop()


# =============================================================================
# Many:Many Mode Tests
# =============================================================================

class TestManyToMany:
    """Tests for many:many mode (multiple listeners to multiple backends)."""

    def test_two_listeners_two_backends_roundrobin(self, rinetd_path, tmp_path):
        """Two listeners to two backends with round-robin."""
        servers = [IdentifyingTcpServer(i) for i in range(2)]
        for s in servers:
            s.start()
            s.wait_ready()

        listen_port1 = get_free_port()
        listen_port2 = get_free_port()

        yaml_config = f"""
rules:
  - name: two-to-two
    bind:
      - "127.0.0.1:{listen_port1}/tcp"
      - "127.0.0.1:{listen_port2}/tcp"
    connect:
      - dest: "127.0.0.1:{servers[0].actual_port}"
      - dest: "127.0.0.1:{servers[1].actual_port}"
    load_balancing:
      algorithm: roundrobin
"""
        process = run_rinetd_yaml(rinetd_path, yaml_config, tmp_path)
        try:
            assert wait_for_port(listen_port1)
            assert wait_for_port(listen_port2)

            # Send multiple requests and collect responses
            responses = []
            for _ in range(10):
                responses.append(send_request_tcp('127.0.0.1', listen_port1))
                responses.append(send_request_tcp('127.0.0.1', listen_port2))

            # Both backends should have received connections
            counts = Counter(responses)
            assert "SERVER_0" in counts
            assert "SERVER_1" in counts
            # Round-robin should be fairly even
            assert counts["SERVER_0"] >= 5
            assert counts["SERVER_1"] >= 5
        finally:
            stop_rinetd(process)
            for s in servers:
                s.stop()


# =============================================================================
# Mixed Backend Types Tests
# =============================================================================

class TestMixedBackends:
    """Tests for mixed backend types (TCP and Unix sockets)."""

    def test_tcp_listener_to_mixed_backends(self, rinetd_path, tmp_path):
        """TCP listener with both TCP and Unix socket backends."""
        tcp_server = IdentifyingTcpServer(0)
        tcp_server.start()
        tcp_server.wait_ready()

        unix_path = str(tmp_path / "backend.sock")
        unix_server = IdentifyingUnixServer(1, unix_path)
        unix_server.start()
        unix_server.wait_ready()

        listen_port = get_free_port()

        yaml_config = f"""
rules:
  - name: mixed-backends
    bind: "127.0.0.1:{listen_port}/tcp"
    connect:
      - dest: "127.0.0.1:{tcp_server.actual_port}"
      - dest: "unix:{unix_path}"
    load_balancing:
      algorithm: roundrobin
"""
        process = run_rinetd_yaml(rinetd_path, yaml_config, tmp_path)
        try:
            assert wait_for_port(listen_port)

            responses = []
            for _ in range(10):
                responses.append(send_request_tcp('127.0.0.1', listen_port))

            counts = Counter(responses)
            # Both backends should receive connections
            assert "SERVER_0" in counts, "TCP backend should receive connections"
            assert "SERVER_1" in counts, "Unix backend should receive connections"
        finally:
            stop_rinetd(process)
            tcp_server.stop()
            unix_server.stop()

    def test_unix_listener_to_tcp_backend(self, rinetd_path, tmp_path):
        """Unix socket listener forwarding to TCP backend with LB."""
        servers = [IdentifyingTcpServer(i) for i in range(2)]
        for s in servers:
            s.start()
            s.wait_ready()

        unix_path = str(tmp_path / "listen.sock")

        yaml_config = f"""
rules:
  - name: unix-to-tcp-lb
    bind: "unix:{unix_path}"
    connect:
      - dest: "127.0.0.1:{servers[0].actual_port}"
      - dest: "127.0.0.1:{servers[1].actual_port}"
    load_balancing:
      algorithm: roundrobin
"""
        process = run_rinetd_yaml(rinetd_path, yaml_config, tmp_path)
        try:
            time.sleep(0.3)
            assert os.path.exists(unix_path)

            responses = []
            for _ in range(10):
                responses.append(send_request_unix(unix_path))

            counts = Counter(responses)
            assert "SERVER_0" in counts
            assert "SERVER_1" in counts
        finally:
            stop_rinetd(process)
            for s in servers:
                s.stop()


# =============================================================================
# Load Balancing Algorithm Tests
# =============================================================================

class TestLBAlgorithms:
    """Tests for all load balancing algorithms."""

    @pytest.mark.parametrize("backend_count", [2, 3, 4, 5])
    def test_roundrobin_distribution(self, rinetd_path, tmp_path, backend_count):
        """Round-robin should distribute evenly across all backends."""
        servers = [IdentifyingTcpServer(i) for i in range(backend_count)]
        for s in servers:
            s.start()
            s.wait_ready()

        listen_port = get_free_port()
        backends_yaml = "\n".join([
            f"      - dest: \"127.0.0.1:{s.actual_port}\""
            for s in servers
        ])

        yaml_config = f"""
rules:
  - name: roundrobin-test
    bind: "127.0.0.1:{listen_port}/tcp"
    connect:
{backends_yaml}
    load_balancing:
      algorithm: roundrobin
"""
        process = run_rinetd_yaml(rinetd_path, yaml_config, tmp_path)
        try:
            assert wait_for_port(listen_port)

            # Send many requests
            num_requests = backend_count * 20
            responses = [send_request_tcp('127.0.0.1', listen_port) for _ in range(num_requests)]

            counts = Counter(responses)

            # All backends should have received connections
            for i in range(backend_count):
                assert f"SERVER_{i}" in counts, f"Backend {i} should receive connections"
                # With round-robin, distribution should be fairly even
                expected = num_requests // backend_count
                actual = counts[f"SERVER_{i}"]
                assert actual >= expected - 5, f"Backend {i}: got {actual}, expected ~{expected}"
        finally:
            stop_rinetd(process)
            for s in servers:
                s.stop()

    @pytest.mark.parametrize("backend_count", [2, 3, 4, 5])
    def test_leastconn_distribution(self, rinetd_path, tmp_path, backend_count):
        """Least-connections should send to backend with fewest active connections."""
        servers = [IdentifyingTcpServer(i) for i in range(backend_count)]
        for s in servers:
            s.start()
            s.wait_ready()

        listen_port = get_free_port()
        backends_yaml = "\n".join([
            f"      - dest: \"127.0.0.1:{s.actual_port}\""
            for s in servers
        ])

        yaml_config = f"""
rules:
  - name: leastconn-test
    bind: "127.0.0.1:{listen_port}/tcp"
    connect:
{backends_yaml}
    load_balancing:
      algorithm: leastconn
"""
        process = run_rinetd_yaml(rinetd_path, yaml_config, tmp_path)
        try:
            assert wait_for_port(listen_port)

            num_requests = backend_count * 10
            responses = [send_request_tcp('127.0.0.1', listen_port) for _ in range(num_requests)]

            counts = Counter(responses)

            # All backends should receive some connections
            for i in range(backend_count):
                assert f"SERVER_{i}" in counts, f"Backend {i} should receive connections"
        finally:
            stop_rinetd(process)
            for s in servers:
                s.stop()

    @pytest.mark.parametrize("backend_count", [2, 3, 4, 5])
    def test_random_distribution(self, rinetd_path, tmp_path, backend_count):
        """Random should distribute to all backends (probabilistically)."""
        servers = [IdentifyingTcpServer(i) for i in range(backend_count)]
        for s in servers:
            s.start()
            s.wait_ready()

        listen_port = get_free_port()
        backends_yaml = "\n".join([
            f"      - dest: \"127.0.0.1:{s.actual_port}\""
            for s in servers
        ])

        yaml_config = f"""
rules:
  - name: random-test
    bind: "127.0.0.1:{listen_port}/tcp"
    connect:
{backends_yaml}
    load_balancing:
      algorithm: random
"""
        process = run_rinetd_yaml(rinetd_path, yaml_config, tmp_path)
        try:
            assert wait_for_port(listen_port)

            # Need more requests to ensure randomness covers all backends
            num_requests = backend_count * 50
            responses = [send_request_tcp('127.0.0.1', listen_port) for _ in range(num_requests)]

            counts = Counter(responses)

            # With enough requests, all backends should receive some
            for i in range(backend_count):
                assert f"SERVER_{i}" in counts, f"Backend {i} should receive connections with random"
        finally:
            stop_rinetd(process)
            for s in servers:
                s.stop()

    @pytest.mark.parametrize("backend_count", [2, 3, 4, 5])
    def test_iphash_consistency(self, rinetd_path, tmp_path, backend_count):
        """IP-hash should consistently route same client to same backend."""
        servers = [IdentifyingTcpServer(i) for i in range(backend_count)]
        for s in servers:
            s.start()
            s.wait_ready()

        listen_port = get_free_port()
        backends_yaml = "\n".join([
            f"      - dest: \"127.0.0.1:{s.actual_port}\""
            for s in servers
        ])

        yaml_config = f"""
rules:
  - name: iphash-test
    bind: "127.0.0.1:{listen_port}/tcp"
    connect:
{backends_yaml}
    load_balancing:
      algorithm: iphash
"""
        process = run_rinetd_yaml(rinetd_path, yaml_config, tmp_path)
        try:
            assert wait_for_port(listen_port)

            # Same client IP should consistently go to same backend
            responses = [send_request_tcp('127.0.0.1', listen_port) for _ in range(20)]

            # All responses should be from the same server (consistent hashing)
            unique_responses = set(responses)
            assert len(unique_responses) == 1, \
                f"IP-hash should route consistently, got: {unique_responses}"
        finally:
            stop_rinetd(process)
            for s in servers:
                s.stop()


# =============================================================================
# Weighted Distribution Tests
# =============================================================================

class TestWeightedDistribution:
    """Tests for weighted load balancing."""

    def test_weighted_roundrobin_2_1(self, rinetd_path, tmp_path):
        """Weighted round-robin with 2:1 ratio."""
        servers = [IdentifyingTcpServer(i) for i in range(2)]
        for s in servers:
            s.start()
            s.wait_ready()

        listen_port = get_free_port()

        yaml_config = f"""
rules:
  - name: weighted-test
    bind: "127.0.0.1:{listen_port}/tcp"
    connect:
      - dest: "127.0.0.1:{servers[0].actual_port}"
        weight: 2
      - dest: "127.0.0.1:{servers[1].actual_port}"
        weight: 1
    load_balancing:
      algorithm: roundrobin
"""
        process = run_rinetd_yaml(rinetd_path, yaml_config, tmp_path)
        try:
            assert wait_for_port(listen_port)

            num_requests = 60
            responses = [send_request_tcp('127.0.0.1', listen_port) for _ in range(num_requests)]

            counts = Counter(responses)

            # With 2:1 weight, server 0 should get ~2x the connections
            assert counts["SERVER_0"] > counts["SERVER_1"], \
                f"Weight 2 backend should get more: {counts}"
            # Allow some variance but ratio should be roughly 2:1
            ratio = counts["SERVER_0"] / max(counts["SERVER_1"], 1)
            assert 1.5 <= ratio <= 2.5, f"Expected ~2:1 ratio, got {ratio:.2f}"
        finally:
            stop_rinetd(process)
            for s in servers:
                s.stop()

    def test_weighted_roundrobin_3_2_1(self, rinetd_path, tmp_path):
        """Weighted round-robin with 3:2:1 ratio."""
        servers = [IdentifyingTcpServer(i) for i in range(3)]
        for s in servers:
            s.start()
            s.wait_ready()

        listen_port = get_free_port()

        yaml_config = f"""
rules:
  - name: weighted-321
    bind: "127.0.0.1:{listen_port}/tcp"
    connect:
      - dest: "127.0.0.1:{servers[0].actual_port}"
        weight: 3
      - dest: "127.0.0.1:{servers[1].actual_port}"
        weight: 2
      - dest: "127.0.0.1:{servers[2].actual_port}"
        weight: 1
    load_balancing:
      algorithm: roundrobin
"""
        process = run_rinetd_yaml(rinetd_path, yaml_config, tmp_path)
        try:
            assert wait_for_port(listen_port)

            num_requests = 120  # Multiple of 6 for clean ratios
            responses = [send_request_tcp('127.0.0.1', listen_port) for _ in range(num_requests)]

            counts = Counter(responses)

            # Verify ordering matches weights
            assert counts["SERVER_0"] > counts["SERVER_1"], \
                f"Server 0 (weight 3) should beat Server 1 (weight 2): {counts}"
            assert counts["SERVER_1"] > counts["SERVER_2"], \
                f"Server 1 (weight 2) should beat Server 2 (weight 1): {counts}"
        finally:
            stop_rinetd(process)
            for s in servers:
                s.stop()


# =============================================================================
# Health Monitoring Tests
# =============================================================================

class TestHealthMonitoring:
    """Tests for passive health checking."""

    def test_backend_failure_failover(self, rinetd_path, tmp_path):
        """When a backend fails, traffic should failover to healthy backends."""
        servers = [IdentifyingTcpServer(i) for i in range(3)]
        for s in servers:
            s.start()
            s.wait_ready()

        listen_port = get_free_port()

        yaml_config = f"""
rules:
  - name: health-test
    bind: "127.0.0.1:{listen_port}/tcp"
    connect:
      - dest: "127.0.0.1:{servers[0].actual_port}"
      - dest: "127.0.0.1:{servers[1].actual_port}"
      - dest: "127.0.0.1:{servers[2].actual_port}"
    load_balancing:
      algorithm: roundrobin
      health_threshold: 2
      recovery_timeout: 5
"""
        process = run_rinetd_yaml(rinetd_path, yaml_config, tmp_path)
        try:
            assert wait_for_port(listen_port)

            # Verify all backends receive traffic initially
            initial_responses = [send_request_tcp('127.0.0.1', listen_port) for _ in range(9)]
            initial_counts = Counter(initial_responses)
            assert len(initial_counts) == 3, "All 3 backends should receive traffic initially"

            # Stop one backend
            servers[1].stop()
            time.sleep(0.5)

            # Send requests - should fail over to remaining backends
            # Need to send enough to trigger health check failures
            failover_responses = []
            for _ in range(20):
                try:
                    resp = send_request_tcp('127.0.0.1', listen_port)
                    failover_responses.append(resp)
                except (ConnectionRefusedError, socket.timeout, OSError):
                    pass  # Expected during failover

            # Remaining backends should handle traffic
            failover_counts = Counter(failover_responses)
            assert "SERVER_0" in failover_counts or "SERVER_2" in failover_counts, \
                f"Healthy backends should receive traffic after failover: {failover_counts}"
        finally:
            stop_rinetd(process)
            for s in servers:
                try:
                    s.stop()
                except:
                    pass

    def test_backend_recovery(self, rinetd_path, tmp_path):
        """Backend should recover after recovery_timeout and receive traffic again."""
        listen_port = get_free_port()
        backend_port = get_free_port()

        # Start with one backend that will be stopped and restarted
        server = IdentifyingTcpServer(0, port=backend_port)
        server.start()
        server.wait_ready()

        yaml_config = f"""
rules:
  - name: recovery-test
    bind: "127.0.0.1:{listen_port}/tcp"
    connect: "127.0.0.1:{backend_port}"
    load_balancing:
      algorithm: roundrobin
      health_threshold: 2
      recovery_timeout: 2
"""
        process = run_rinetd_yaml(rinetd_path, yaml_config, tmp_path)
        try:
            assert wait_for_port(listen_port)

            # Verify backend works
            resp = send_request_tcp('127.0.0.1', listen_port)
            assert resp == "SERVER_0"

            # Stop and restart backend
            server.stop()
            time.sleep(0.5)

            # Restart on same port
            server = IdentifyingTcpServer(0, port=backend_port)
            server.start()
            server.wait_ready()

            # Wait for recovery timeout
            time.sleep(3)

            # Backend should work again
            resp = send_request_tcp('127.0.0.1', listen_port)
            assert resp == "SERVER_0", "Backend should recover after timeout"
        finally:
            stop_rinetd(process)
            server.stop()

    def test_all_backends_unhealthy_failopen(self, rinetd_path, tmp_path):
        """When all backends are unhealthy, should still try to connect (fail-open)."""
        listen_port = get_free_port()
        dead_port1 = get_free_port()
        dead_port2 = get_free_port()

        yaml_config = f"""
rules:
  - name: failopen-test
    bind: "127.0.0.1:{listen_port}/tcp"
    connect:
      - dest: "127.0.0.1:{dead_port1}"
      - dest: "127.0.0.1:{dead_port2}"
    load_balancing:
      algorithm: roundrobin
      health_threshold: 1
      recovery_timeout: 1
"""
        process = run_rinetd_yaml(rinetd_path, yaml_config, tmp_path)
        try:
            assert wait_for_port(listen_port)

            # Connections should be attempted (fail-open behavior)
            # They will fail since no backends are running, but rinetd should accept
            for _ in range(5):
                try:
                    with socket.create_connection(('127.0.0.1', listen_port), timeout=2) as s:
                        s.sendall(b"PING")
                        # Expect connection reset or timeout (backend is down)
                        s.recv(1024)
                except (ConnectionRefusedError, ConnectionResetError, socket.timeout, OSError):
                    pass  # Expected - no backends available
        finally:
            stop_rinetd(process)


# =============================================================================
# Client Affinity Tests
# =============================================================================

class TestClientAffinity:
    """Tests for client IP affinity (session persistence)."""

    def test_affinity_same_backend(self, rinetd_path, tmp_path):
        """With affinity enabled, same client should go to same backend."""
        servers = [IdentifyingTcpServer(i) for i in range(3)]
        for s in servers:
            s.start()
            s.wait_ready()

        listen_port = get_free_port()

        yaml_config = f"""
rules:
  - name: affinity-test
    bind: "127.0.0.1:{listen_port}/tcp"
    connect:
      - dest: "127.0.0.1:{servers[0].actual_port}"
      - dest: "127.0.0.1:{servers[1].actual_port}"
      - dest: "127.0.0.1:{servers[2].actual_port}"
    load_balancing:
      algorithm: roundrobin
      affinity_ttl: 300
"""
        process = run_rinetd_yaml(rinetd_path, yaml_config, tmp_path)
        try:
            assert wait_for_port(listen_port)

            # Multiple requests from same client should go to same backend
            responses = [send_request_tcp('127.0.0.1', listen_port) for _ in range(10)]

            unique = set(responses)
            assert len(unique) == 1, \
                f"With affinity, all requests should go to same backend: {unique}"
        finally:
            stop_rinetd(process)
            for s in servers:
                s.stop()


# =============================================================================
# UDP Load Balancing Tests
# =============================================================================

class TestUDPLoadBalancing:
    """Tests for UDP load balancing."""

    def test_udp_roundrobin(self, rinetd_path, tmp_path):
        """UDP load balancing with round-robin."""
        servers = [UdpEchoServer(port=0) for _ in range(2)]
        for s in servers:
            s.start()
            s.wait_ready()

        listen_port = get_free_port()

        yaml_config = f"""
rules:
  - name: udp-lb
    bind: "127.0.0.1:{listen_port}/udp"
    connect:
      - dest: "127.0.0.1:{servers[0].actual_port}/udp"
      - dest: "127.0.0.1:{servers[1].actual_port}/udp"
    load_balancing:
      algorithm: roundrobin
    timeout: 5
"""
        process = run_rinetd_yaml(rinetd_path, yaml_config, tmp_path)
        try:
            time.sleep(0.3)

            # UDP load balancing test
            # Note: UDP is connectionless, each packet can go to different backend
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(5)
                sock.sendto(b"test1", ('127.0.0.1', listen_port))
                data, _ = sock.recvfrom(1024)
                assert data == b"test1"

            # Just verify it works - distribution testing is complex for UDP
        finally:
            stop_rinetd(process)
            for s in servers:
                s.stop()


# =============================================================================
# Skip marker for YAML tests if libyaml not available
# =============================================================================

def pytest_configure(config):
    """Check if YAML config is supported."""
    pass  # Will be detected at runtime


@pytest.fixture(scope="module")
def yaml_supported(rinetd_path, tmp_path_factory):
    """Check if rinetd was built with YAML support."""
    tmp_path = tmp_path_factory.mktemp("yaml_check")
    yaml_file = tmp_path / "test.yaml"
    yaml_file.write_text("rules: []\n")

    proc = subprocess.Popen(
        [rinetd_path, "-f", "-c", str(yaml_file)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    time.sleep(0.5)
    if proc.poll() is None:
        proc.terminate()
        proc.wait()
        return True

    _, stderr = proc.communicate()
    if "YAML" in stderr and "not supported" in stderr.lower():
        return False
    return True


@pytest.fixture(autouse=True)
def skip_if_no_yaml(request, yaml_supported):
    """Skip load balancing tests if YAML is not supported."""
    if not yaml_supported:
        pytest.skip("rinetd was built without YAML support (libyaml not available)")
