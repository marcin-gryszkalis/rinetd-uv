"""
Tests for error handling and recovery scenarios.
"""
import pytest
import socket
import time
import threading
from .utils import get_free_port, wait_for_port, generate_random_data
from .servers import TcpEchoServer


def test_backend_unavailable_at_start(rinetd):
    """
    Test behavior when backend is not available at connection time.
    rinetd should accept the connection but fail to forward.
    """
    rinetd_port = get_free_port()
    # Use a port that nothing is listening on
    dead_backend_port = get_free_port()

    rules = [
        f"0.0.0.0 {rinetd_port} 127.0.0.1 {dead_backend_port}"
    ]

    rinetd(rules)
    assert wait_for_port(rinetd_port)

    # Connection should be accepted by rinetd, but forwarding should fail
    # The exact behavior depends on implementation - may close immediately or after timeout
    with pytest.raises((ConnectionRefusedError, ConnectionResetError, BrokenPipeError, socket.timeout, OSError)):
        with socket.create_connection(('127.0.0.1', rinetd_port), timeout=5) as s:
            s.settimeout(2)
            s.sendall(b"test")
            # Try to receive - should fail or get empty response
            data = s.recv(1024)
            if data == b"":
                raise ConnectionResetError("Connection closed by peer")


def test_backend_becomes_available(rinetd, tmp_path):
    """
    Test that connections succeed once backend becomes available.
    """
    rinetd_port = get_free_port()
    backend_port = get_free_port()

    rules = [
        f"0.0.0.0 {rinetd_port} 127.0.0.1 {backend_port}"
    ]

    rinetd(rules)
    assert wait_for_port(rinetd_port)

    # First connection should fail (no backend)
    failed = False
    try:
        with socket.create_connection(('127.0.0.1', rinetd_port), timeout=2) as s:
            s.settimeout(2)
            s.sendall(b"test")
            s.recv(1024)
    except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError, socket.timeout, OSError):
        failed = True

    assert failed, "First connection should have failed with no backend"

    # Start the backend
    backend = TcpEchoServer(port=backend_port)
    backend.start()
    backend.wait_ready()

    try:
        # Now connection should succeed
        with socket.create_connection(('127.0.0.1', rinetd_port), timeout=5) as s:
            s.settimeout(5)
            s.sendall(b"test_after_backend_up")
            received = s.recv(1024)
            assert received == b"test_after_backend_up"
    finally:
        backend.stop()


def test_backend_goes_down_and_recovers(rinetd):
    """
    Test behavior when backend goes down and comes back up.
    """
    rinetd_port = get_free_port()
    backend_port = get_free_port()

    # Start backend first
    backend = TcpEchoServer(port=backend_port)
    backend.start()
    backend.wait_ready()

    rules = [
        f"0.0.0.0 {rinetd_port} 127.0.0.1 {backend_port}"
    ]

    rinetd(rules)
    assert wait_for_port(rinetd_port)

    try:
        # Connection should work initially
        with socket.create_connection(('127.0.0.1', rinetd_port), timeout=5) as s:
            s.settimeout(5)
            s.sendall(b"test1")
            assert s.recv(5) == b"test1"

        # Stop backend
        backend.stop()
        time.sleep(0.5)

        # Connection should fail now
        failed = False
        try:
            with socket.create_connection(('127.0.0.1', rinetd_port), timeout=2) as s:
                s.settimeout(2)
                s.sendall(b"test2")
                s.recv(1024)
        except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError, socket.timeout, OSError):
            failed = True

        assert failed, "Connection should fail with backend down"

        # Restart backend on same port
        backend = TcpEchoServer(port=backend_port)
        backend.start()
        backend.wait_ready()

        # Connection should work again
        with socket.create_connection(('127.0.0.1', rinetd_port), timeout=5) as s:
            s.settimeout(5)
            s.sendall(b"test3")
            assert s.recv(5) == b"test3"

    finally:
        backend.stop()


def test_client_disconnect_mid_transfer(rinetd, tcp_echo_server):
    """
    Test that client disconnecting mid-transfer is handled gracefully.
    """
    rinetd_port = get_free_port()

    rules = [
        f"0.0.0.0 {rinetd_port} {tcp_echo_server.host} {tcp_echo_server.actual_port}"
    ]

    rinetd(rules)
    assert wait_for_port(rinetd_port)

    # Start a transfer and disconnect abruptly
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(('127.0.0.1', rinetd_port))
    s.sendall(b"partial_data")
    # Close without receiving - simulates client crash
    s.close()

    time.sleep(0.5)

    # rinetd should still accept new connections
    with socket.create_connection(('127.0.0.1', rinetd_port), timeout=5) as s:
        s.settimeout(5)
        s.sendall(b"after_disconnect")
        assert s.recv(16) == b"after_disconnect"


def test_rapid_connect_disconnect(rinetd, tcp_echo_server):
    """
    Test rapid connection/disconnection cycles don't exhaust resources.
    """
    rinetd_port = get_free_port()

    rules = [
        f"0.0.0.0 {rinetd_port} {tcp_echo_server.host} {tcp_echo_server.actual_port}"
    ]

    rinetd(rules)
    assert wait_for_port(rinetd_port)

    # Rapid connect/disconnect cycles
    for i in range(100):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect(('127.0.0.1', rinetd_port))
            s.close()
        except (ConnectionRefusedError, socket.timeout):
            # Some failures acceptable under rapid load
            pass

    # After rapid cycles, normal operation should work
    time.sleep(0.5)
    with socket.create_connection(('127.0.0.1', rinetd_port), timeout=5) as s:
        s.settimeout(5)
        s.sendall(b"stable")
        assert s.recv(6) == b"stable"


def test_half_close_handling(rinetd, tcp_echo_server):
    """
    Test that half-close (shutdown) is handled correctly.
    """
    rinetd_port = get_free_port()

    rules = [
        f"0.0.0.0 {rinetd_port} {tcp_echo_server.host} {tcp_echo_server.actual_port}"
    ]

    rinetd(rules)
    assert wait_for_port(rinetd_port)

    with socket.create_connection(('127.0.0.1', rinetd_port), timeout=5) as s:
        s.settimeout(5)

        # Send data
        s.sendall(b"before_shutdown")
        received = s.recv(15)
        assert received == b"before_shutdown"

        # Half-close the write side
        s.shutdown(socket.SHUT_WR)

        # Should still be able to receive any pending data
        # (in echo case, nothing more to receive)
        remaining = s.recv(1024)
        # Empty or nothing is expected after shutdown


def test_connection_timeout_backend_slow(rinetd, tmp_path):
    """
    Test behavior when backend is slow to accept connections.
    """
    rinetd_port = get_free_port()
    backend_port = get_free_port()

    rules = [
        f"0.0.0.0 {rinetd_port} 127.0.0.1 {backend_port}"
    ]

    rinetd(rules)
    assert wait_for_port(rinetd_port)

    # Create a listening socket but don't accept
    slow_backend = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    slow_backend.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    slow_backend.bind(('127.0.0.1', backend_port))
    slow_backend.listen(1)

    try:
        # Connection to rinetd should succeed, but may hang or timeout
        # depending on rinetd's connection timeout settings
        with socket.create_connection(('127.0.0.1', rinetd_port), timeout=5) as s:
            s.settimeout(2)
            # This may succeed if rinetd connects to backend's listen queue
            # or may hang/timeout if backend never accepts
            try:
                s.sendall(b"test")
            except (socket.timeout, BrokenPipeError, ConnectionResetError):
                pass  # Expected if backend never processes
    except socket.timeout:
        pass  # Also acceptable
    finally:
        slow_backend.close()
