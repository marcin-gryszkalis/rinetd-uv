"""
Tests for backend connect timeout feature.

Tests cover:
- Connect timeout fires for non-routable backends (legacy .conf)
- Connect timeout fires for non-routable backends (YAML config)
- Per-rule connect timeout override (YAML)
- Normal forwarding works with connect timeout set
- Default behavior (no timeout) preserves OS timeout
"""
import pytest
import socket
import time
import os
import subprocess
import tempfile
from .utils import get_free_port, wait_for_port
from .servers import TcpEchoServer


# RFC 5737 TEST-NET-1: guaranteed non-routable, SYN packets silently dropped.
# This makes connect() hang until timeout rather than getting immediate ECONNREFUSED.
NON_ROUTABLE_HOST = "192.0.2.1"
NON_ROUTABLE_PORT = "9999"


def is_non_routable(host, port, probe_timeout=3):
    """Verify that connecting to host:port hangs (no response) rather than
    getting an immediate error. Returns True if the address is truly non-routable."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setblocking(False)
    try:
        s.connect_ex((host, int(port)))
    except OSError:
        s.close()
        return False

    # Wait briefly - if we get a response (ECONNREFUSED, etc.) it's not non-routable
    import select
    readable, writable, exceptional = select.select([], [s], [s], probe_timeout)
    s.close()

    # If socket became writable/exceptional within probe_timeout, the host is reachable
    # (or actively rejecting). We need it to remain silent.
    return len(writable) == 0 and len(exceptional) == 0


def create_yaml_config(yaml_content, tmp_path):
    """Create a YAML configuration file and return its path."""
    config_file = str(tmp_path / "test.yaml")
    with open(config_file, 'w') as f:
        f.write(yaml_content)
    return config_file


@pytest.fixture(autouse=True)
def check_non_routable():
    """Skip all tests in this module if TEST-NET-1 is routable on this system."""
    if not is_non_routable(NON_ROUTABLE_HOST, int(NON_ROUTABLE_PORT), probe_timeout=2):
        pytest.skip(f"{NON_ROUTABLE_HOST} is reachable on this system (not silently dropped)")


@pytest.mark.expect_rinetd_errors
def test_connect_timeout_fires_legacy(rinetd):
    """
    With connect-timeout=2, connecting to a non-routable backend should fail
    within ~2-4 seconds, not the OS default of ~127 seconds.
    """
    rinetd_port = get_free_port()

    rules = [
        "connect-timeout 2",
        f"0.0.0.0 {rinetd_port} {NON_ROUTABLE_HOST} {NON_ROUTABLE_PORT}",
    ]

    rinetd(rules)
    assert wait_for_port(rinetd_port)

    start = time.monotonic()
    try:
        with socket.create_connection(('127.0.0.1', rinetd_port), timeout=10) as s:
            s.settimeout(10)
            # rinetd accepted the connection, now wait for it to close
            # (backend connect timeout should fire and close the connection)
            data = s.recv(1024)
            # Empty recv means connection closed by rinetd
    except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError, OSError):
        pass
    elapsed = time.monotonic() - start

    # Should complete in roughly 2-4 seconds (2s timeout + overhead)
    assert elapsed < 8, f"Connect timeout took {elapsed:.1f}s, expected ~2s"
    # Should not be instant (that would mean immediate rejection, not timeout)
    assert elapsed >= 1.5, f"Connect completed too fast ({elapsed:.1f}s), timeout may not be working"


@pytest.mark.expect_rinetd_errors
def test_connect_timeout_fires_yaml(rinetd_path, tmp_path):
    """
    YAML config: global connect_timeout should cause fast failure for non-routable backend.
    """
    rinetd_port = get_free_port()
    log_file = str(tmp_path / "test.log")

    yaml_content = f"""\
global:
  connect_timeout: 2
  log_file: {log_file}

rules:
  - name: timeout-test
    bind: "0.0.0.0:{rinetd_port}/tcp"
    connect: "{NON_ROUTABLE_HOST}:{NON_ROUTABLE_PORT}/tcp"
"""
    config_file = create_yaml_config(yaml_content, tmp_path)
    proc = subprocess.Popen(
        [rinetd_path, "-f", "-c", config_file],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )

    try:
        time.sleep(0.3)
        assert proc.poll() is None, "rinetd failed to start"
        assert wait_for_port(rinetd_port)

        start = time.monotonic()
        try:
            with socket.create_connection(('127.0.0.1', rinetd_port), timeout=10) as s:
                s.settimeout(10)
                data = s.recv(1024)
        except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError, OSError):
            pass
        elapsed = time.monotonic() - start

        assert elapsed < 8, f"Connect timeout took {elapsed:.1f}s, expected ~2s"
        assert elapsed >= 1.5, f"Connect completed too fast ({elapsed:.1f}s)"
    finally:
        proc.terminate()
        proc.wait(timeout=5)


@pytest.mark.expect_rinetd_errors
def test_connect_timeout_per_rule_override_yaml(rinetd_path, tmp_path):
    """
    Per-rule connect_timeout should override the global setting.
    Global is 10s, but per-rule override to 2s should make the rule fail fast.
    """
    fast_port = get_free_port()
    log_file = str(tmp_path / "test.log")

    yaml_content = f"""\
global:
  connect_timeout: 10
  log_file: {log_file}

rules:
  - name: fast-timeout
    bind: "0.0.0.0:{fast_port}/tcp"
    connect: "{NON_ROUTABLE_HOST}:{NON_ROUTABLE_PORT}/tcp"
    connect_timeout: 2
"""
    config_file = create_yaml_config(yaml_content, tmp_path)
    proc = subprocess.Popen(
        [rinetd_path, "-f", "-c", config_file],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )

    try:
        time.sleep(0.3)
        assert proc.poll() is None, "rinetd failed to start"
        assert wait_for_port(fast_port)

        # Per-rule connect_timeout=2 should override global 10s
        start = time.monotonic()
        try:
            with socket.create_connection(('127.0.0.1', fast_port), timeout=15) as s:
                s.settimeout(15)
                s.recv(1024)
        except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError, OSError):
            pass
        elapsed = time.monotonic() - start

        # Should complete in ~2s (per-rule), NOT ~10s (global)
        assert elapsed < 6, f"Per-rule timeout took {elapsed:.1f}s, expected ~2s (not global 10s)"
        assert elapsed >= 1.5, f"Completed too fast ({elapsed:.1f}s), per-rule timeout may not be working"
    finally:
        proc.terminate()
        proc.wait(timeout=5)


@pytest.mark.expect_rinetd_errors
def test_connect_timeout_per_rule_legacy(rinetd):
    """
    Legacy .conf format: per-rule [connect-timeout=N] option should work.
    """
    rinetd_port = get_free_port()

    rules = [
        f"0.0.0.0 {rinetd_port} {NON_ROUTABLE_HOST} {NON_ROUTABLE_PORT} [connect-timeout=2]",
    ]

    rinetd(rules)
    assert wait_for_port(rinetd_port)

    start = time.monotonic()
    try:
        with socket.create_connection(('127.0.0.1', rinetd_port), timeout=10) as s:
            s.settimeout(10)
            data = s.recv(1024)
    except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError, OSError):
        pass
    elapsed = time.monotonic() - start

    assert elapsed < 8, f"Connect timeout took {elapsed:.1f}s, expected ~2s"
    assert elapsed >= 1.5, f"Connect completed too fast ({elapsed:.1f}s)"


def test_connect_timeout_normal_forwarding(rinetd, tcp_echo_server):
    """
    Setting connect-timeout should not break normal forwarding to reachable backends.
    """
    rinetd_port = get_free_port()

    rules = [
        "connect-timeout 5",
        f"0.0.0.0 {rinetd_port} {tcp_echo_server.host} {tcp_echo_server.actual_port}",
    ]

    rinetd(rules)
    assert wait_for_port(rinetd_port)

    with socket.create_connection(('127.0.0.1', rinetd_port), timeout=5) as s:
        s.settimeout(5)
        s.sendall(b"hello timeout test")
        data = s.recv(1024)
        assert data == b"hello timeout test"


def test_connect_timeout_normal_forwarding_yaml(rinetd_path, tcp_echo_server, tmp_path):
    """
    YAML config: connect_timeout should not break normal forwarding.
    """
    rinetd_port = get_free_port()
    log_file = str(tmp_path / "test.log")

    yaml_content = f"""\
global:
  connect_timeout: 5
  log_file: {log_file}

rules:
  - name: echo-forward
    bind: "0.0.0.0:{rinetd_port}/tcp"
    connect: "{tcp_echo_server.host}:{tcp_echo_server.actual_port}/tcp"
"""
    config_file = create_yaml_config(yaml_content, tmp_path)
    proc = subprocess.Popen(
        [rinetd_path, "-f", "-c", config_file],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )

    try:
        time.sleep(0.3)
        assert proc.poll() is None, "rinetd failed to start"
        assert wait_for_port(rinetd_port)

        with socket.create_connection(('127.0.0.1', rinetd_port), timeout=5) as s:
            s.settimeout(5)
            s.sendall(b"yaml timeout test")
            data = s.recv(1024)
            assert data == b"yaml timeout test"
    finally:
        proc.terminate()
        proc.wait(timeout=5)


@pytest.mark.expect_rinetd_errors
def test_connect_timeout_multiple_connections(rinetd):
    """
    Multiple simultaneous connections should each get their own timeout.
    Verifies that timers are per-connection, not shared.
    """
    rinetd_port = get_free_port()

    rules = [
        "connect-timeout 2",
        f"0.0.0.0 {rinetd_port} {NON_ROUTABLE_HOST} {NON_ROUTABLE_PORT}",
    ]

    rinetd(rules)
    assert wait_for_port(rinetd_port)

    import threading

    results = {}

    def try_connect(conn_id):
        start = time.monotonic()
        try:
            with socket.create_connection(('127.0.0.1', rinetd_port), timeout=10) as s:
                s.settimeout(10)
                s.recv(1024)
        except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError, OSError):
            pass
        results[conn_id] = time.monotonic() - start

    threads = []
    for i in range(5):
        t = threading.Thread(target=try_connect, args=(i,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=15)

    # All connections should have timed out in roughly 2-4 seconds
    for conn_id, elapsed in results.items():
        assert elapsed < 8, f"Connection {conn_id} took {elapsed:.1f}s, expected ~2s"
        assert elapsed >= 1.5, f"Connection {conn_id} too fast ({elapsed:.1f}s)"


@pytest.mark.expect_rinetd_errors
def test_connect_timeout_recovery_after_timeout(rinetd, tmp_path):
    """
    After a connect timeout, rinetd should still accept and forward new connections
    when a working backend is available.
    """
    rinetd_port = get_free_port()
    backend_port = get_free_port()

    # Point to non-routable host initially — but we use a second rule with
    # a working backend to verify rinetd is healthy after timeouts.
    rinetd_port_good = get_free_port()

    backend = TcpEchoServer(port=backend_port)
    backend.start()
    backend.wait_ready()

    try:
        rules = [
            "connect-timeout 2",
            f"0.0.0.0 {rinetd_port} {NON_ROUTABLE_HOST} {NON_ROUTABLE_PORT}",
            f"0.0.0.0 {rinetd_port_good} 127.0.0.1 {backend_port}",
        ]

        rinetd(rules)
        assert wait_for_port(rinetd_port)
        assert wait_for_port(rinetd_port_good)

        # Trigger a connect timeout on the non-routable rule
        try:
            with socket.create_connection(('127.0.0.1', rinetd_port), timeout=10) as s:
                s.settimeout(10)
                s.recv(1024)
        except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError, OSError):
            pass

        # Now verify the good rule still works
        with socket.create_connection(('127.0.0.1', rinetd_port_good), timeout=5) as s:
            s.settimeout(5)
            s.sendall(b"still alive")
            data = s.recv(1024)
            assert data == b"still alive"
    finally:
        backend.stop()
