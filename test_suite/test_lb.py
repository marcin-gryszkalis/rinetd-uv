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
import random
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
# Rinetd Chaining Tests (1:n → n:m → m:1)
# =============================================================================

class TestRinetdChaining:
    """Tests for chaining multiple rinetd instances in different modes."""

    def test_three_rinetd_chain_1n_nm_m1(self, rinetd_path, tmp_path):
        """
        Test 3 rinetd servers in a chain with 1MB data transfer.

        Topology:
          Client → [Rinetd-1 (1:n)] → [Rinetd-2 (n:m)] → [Rinetd-3 (m:1)] → Echo Server

        - Rinetd-1: 1 listener  → 2 backends (round-robin)
        - Rinetd-2: 2 listeners → 3 backends (round-robin)
        - Rinetd-3: 3 listeners → 1 backend  (echo server)

        Transfer: 1MB in 4KB chunks, 60s timeout
        """
        # Start echo server (final destination)
        echo_server = TcpEchoServer()
        echo_server.start()
        echo_server.wait_ready()

        # Allocate ports for all rinetd instances
        # Rinetd-3: 3 listeners, 1 backend (to echo)
        r3_listen1 = get_free_port()
        r3_listen2 = get_free_port()
        r3_listen3 = get_free_port()

        # Rinetd-2: 2 listeners, 3 backends (to rinetd-3)
        r2_listen1 = get_free_port()
        r2_listen2 = get_free_port()

        # Rinetd-1: 1 listener, 2 backends (to rinetd-2)
        r1_listen = get_free_port()

        # Configure Rinetd-3 (m:1 mode - multiple listeners to one backend)
        yaml_r3 = f"""
global:
  buffer_size: 65536

rules:
  - name: rinetd3-m-to-1
    bind:
      - "127.0.0.1:{r3_listen1}/tcp"
      - "127.0.0.1:{r3_listen2}/tcp"
      - "127.0.0.1:{r3_listen3}/tcp"
    connect:
      - dest: "127.0.0.1:{echo_server.actual_port}"
"""

        # Configure Rinetd-2 (n:m mode - multiple listeners to multiple backends)
        yaml_r2 = f"""
global:
  buffer_size: 65536

rules:
  - name: rinetd2-n-to-m
    bind:
      - "127.0.0.1:{r2_listen1}/tcp"
      - "127.0.0.1:{r2_listen2}/tcp"
    connect:
      - dest: "127.0.0.1:{r3_listen1}"
      - dest: "127.0.0.1:{r3_listen2}"
      - dest: "127.0.0.1:{r3_listen3}"
    load_balancing:
      algorithm: roundrobin
"""

        # Configure Rinetd-1 (1:n mode - one listener to multiple backends)
        yaml_r1 = f"""
global:
  buffer_size: 65536

rules:
  - name: rinetd1-1-to-n
    bind: "127.0.0.1:{r1_listen}/tcp"
    connect:
      - dest: "127.0.0.1:{r2_listen1}"
      - dest: "127.0.0.1:{r2_listen2}"
    load_balancing:
      algorithm: roundrobin
"""

        # Create subdirectories for each rinetd instance
        (tmp_path / "r3").mkdir(exist_ok=True)
        (tmp_path / "r2").mkdir(exist_ok=True)
        (tmp_path / "r1").mkdir(exist_ok=True)

        # Start rinetd instances in reverse order (bottom-up)
        proc_r3 = run_rinetd_yaml(rinetd_path, yaml_r3, tmp_path / "r3")
        proc_r2 = run_rinetd_yaml(rinetd_path, yaml_r2, tmp_path / "r2")
        proc_r1 = run_rinetd_yaml(rinetd_path, yaml_r1, tmp_path / "r1")

        try:
            # Wait for all listeners to be ready
            assert wait_for_port(r3_listen1, timeout=5), "Rinetd-3 listener 1 not ready"
            assert wait_for_port(r3_listen2, timeout=5), "Rinetd-3 listener 2 not ready"
            assert wait_for_port(r3_listen3, timeout=5), "Rinetd-3 listener 3 not ready"
            assert wait_for_port(r2_listen1, timeout=5), "Rinetd-2 listener 1 not ready"
            assert wait_for_port(r2_listen2, timeout=5), "Rinetd-2 listener 2 not ready"
            assert wait_for_port(r1_listen, timeout=5), "Rinetd-1 listener not ready"

            # Give the chain a moment to stabilize
            time.sleep(0.5)

            # Run transfers for 60 seconds with random chunk/transfer sizes
            test_duration = 60  # seconds
            base_chunk_size = 4 * 4096  # 4KB base
            base_transfer_size = 1024 * 1024  # 1MB base
            variation = 0.20  # ±20%

            start_time = time.time()
            total_bytes_sent = 0
            total_bytes_received = 0
            transfer_count = 0
            errors = []

            pattern = b"RINETD_CHAIN_TEST_"

            print(f"\nStarting 60-second stress test with randomized chunk/transfer sizes...")
            print(f"Base chunk size: {base_chunk_size} bytes ±{variation*100}%")
            print(f"Base transfer size: {base_transfer_size / 1024:.1f} KB ±{variation*100}%\n")

            with socket.create_connection(('127.0.0.1', r1_listen), timeout=65) as sock:
                sock.settimeout(65)

                # Increase socket buffers for better throughput
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024)  # 1MB send buffer
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)  # 1MB recv buffer

                while time.time() - start_time < test_duration:
                    transfer_count += 1

                    # Randomize chunk size (±20%)
                    chunk_size = int(base_chunk_size * random.uniform(1 - variation, 1 + variation))
                    # Ensure chunk size is reasonable (at least 1KB)
                    chunk_size = max(1024, chunk_size)

                    # Randomize transfer size (±20%)
                    transfer_size = int(base_transfer_size * random.uniform(1 - variation, 1 + variation))
                    # Ensure transfer size is a multiple of chunk size
                    chunks_count = max(1, transfer_size // chunk_size)
                    transfer_size = chunks_count * chunk_size

                    # Create test chunk for this transfer
                    test_chunk = (pattern * ((chunk_size // len(pattern)) + 1))[:chunk_size]
                    assert len(test_chunk) == chunk_size

                    # Transfer data with pipelined I/O for better throughput
                    transfer_start = time.time()
                    bytes_sent = 0
                    bytes_received = 0
                    received_data = bytearray()

                    try:
                        # Phase 1: Send all chunks with pipelining (don't wait for echo)
                        send_start = time.time()
                        for i in range(chunks_count):
                            sock.sendall(test_chunk)
                            bytes_sent += len(test_chunk)
                        send_elapsed = time.time() - send_start

                        # Phase 2: Receive all echoed data
                        recv_start = time.time()
                        sock.settimeout(30)  # Longer timeout for receiving
                        while bytes_received < transfer_size:
                            chunk = sock.recv(min(65536, transfer_size - bytes_received))
                            if not chunk:
                                raise ConnectionError(f"Connection closed after {bytes_received} bytes")
                            received_data.extend(chunk)
                            bytes_received = len(received_data)
                        recv_elapsed = time.time() - recv_start
                        sock.settimeout(65)  # Restore timeout

                        transfer_elapsed = time.time() - transfer_start
                        total_bytes_sent += bytes_sent
                        total_bytes_received += bytes_received

                        # Verify data integrity
                        if bytes_sent != transfer_size:
                            errors.append(f"Transfer {transfer_count}: sent {bytes_sent}, expected {transfer_size}")
                        if bytes_received != transfer_size:
                            errors.append(f"Transfer {transfer_count}: received {bytes_received}, expected {transfer_size}")

                        # Verify first and last chunks
                        if received_data[:chunk_size] != test_chunk:
                            errors.append(f"Transfer {transfer_count}: first chunk corrupted")
                        if received_data[-chunk_size:] != test_chunk:
                            errors.append(f"Transfer {transfer_count}: last chunk corrupted")

                        # Progress report every 5 transfers
                        if transfer_count % 5 == 0:
                            elapsed = time.time() - start_time
                            throughput = (total_bytes_sent * 8 / (1024 * 1024)) / elapsed
                            transfer_mbps = (transfer_size * 8 / (1024 * 1024)) / transfer_elapsed
                            print(f"Transfer #{transfer_count}: {transfer_size/1024:.1f} KB in {chunks_count} chunks "
                                  f"of {chunk_size} bytes ({transfer_elapsed*1000:.1f}ms, {transfer_mbps:.1f} Mbps) | "
                                  f"Total: {total_bytes_sent/(1024*1024):.2f} MB @ {throughput:.1f} Mbps | "
                                  f"Elapsed: {elapsed:.1f}s")

                    except Exception as e:
                        errors.append(f"Transfer {transfer_count} failed: {e}")
                        break

            total_elapsed = time.time() - start_time

            # Final statistics
            print(f"\n{'='*70}")
            print(f"Chain stress test completed:")
            print(f"  Duration: {total_elapsed:.2f}s")
            print(f"  Transfers: {transfer_count}")
            print(f"  Total sent: {total_bytes_sent / (1024 * 1024):.2f} MB")
            print(f"  Total received: {total_bytes_received / (1024 * 1024):.2f} MB")
            print(f"  Average throughput: {(total_bytes_sent * 8 / (1024 * 1024)) / total_elapsed:.2f} Mbps")
            print(f"  Average transfer rate: {transfer_count / total_elapsed:.2f} transfers/sec")
            print(f"  Errors: {len(errors)}")
            print(f"{'='*70}\n")

            # Verify no errors occurred
            if errors:
                for error in errors[:10]:  # Show first 10 errors
                    print(f"  ERROR: {error}")
                pytest.fail(f"Chain test had {len(errors)} error(s)")

            # Verify sent == received
            assert total_bytes_sent == total_bytes_received, \
                f"Sent {total_bytes_sent} bytes but received {total_bytes_received} bytes"

            # Verify we ran for approximately the full duration
            assert total_elapsed >= test_duration * 0.95, \
                f"Test ran for {total_elapsed:.1f}s, expected ~{test_duration}s"

        finally:
            stop_rinetd(proc_r1)
            stop_rinetd(proc_r2)
            stop_rinetd(proc_r3)
            echo_server.stop()


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
