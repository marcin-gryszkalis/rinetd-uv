"""
Transfer tests for rinetd - IPv6 and edge cases.

This file focuses on unique scenarios not covered by other test files:
- IPv6 support (pure IPv6, IPv4↔IPv6 cross-protocol forwarding)
- Zero-byte transfer edge case

For comprehensive protocol/size/mode testing, see:
- test_matrix.py: Exhaustive matrix testing of all protocol combinations
- test_stress.py: Randomized stress testing with large scale
- test_big.py: Very large transfers (1GB-16GB) with throughput measurement
"""
import pytest
import socket
import time
from .utils import generate_random_data, calculate_checksum, send_all, recv_all, get_free_port, wait_for_port, ipv6_available


def test_zero_byte_transfer(rinetd, tcp_echo_server):
    """Test zero-byte transfer edge case (important for connection handling)."""
    rinetd_port = get_free_port()

    rules = [
        f"0.0.0.0 {rinetd_port} {tcp_echo_server.host} {tcp_echo_server.actual_port}"
    ]

    rinetd(rules)
    assert wait_for_port(rinetd_port), "rinetd did not open port"

    size = 0
    data = generate_random_data(size)
    expected_checksum = calculate_checksum(data)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect(('127.0.0.1', rinetd_port))

        # Send zero bytes
        send_all(s, data)

        # Receive zero bytes (should work without hanging)
        received = recv_all(s, size)

    assert len(received) == size
    assert calculate_checksum(received) == expected_checksum


# === IPv6 Tests ===
# These tests verify IPv6 support. They are automatically skipped if IPv6
# is not available on the system (e.g., ::1 loopback disabled).

def wait_for_port_ipv6(port, host='::1', timeout=5.0):
    """Wait for an IPv6 port to be open."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with socket.create_connection((host, port), timeout=0.1):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            time.sleep(0.1)
    return False


@pytest.mark.ipv6
@pytest.mark.parametrize("size", [1, 1024, 65536])
def test_tcp_transfer_ipv6(rinetd, tcp_echo_server_ipv6, size):
    """Test TCP forwarding over IPv6 (both client and backend on IPv6)."""
    if not ipv6_available():
        pytest.skip("IPv6 not available")

    rinetd_port = get_free_port(ipv6=True)

    # Bind on IPv6, connect to IPv6 backend
    rules = [
        f"::0 {rinetd_port} ::1 {tcp_echo_server_ipv6.actual_port}"
    ]

    rinetd(rules)
    assert wait_for_port_ipv6(rinetd_port), "rinetd did not open IPv6 port"

    data = generate_random_data(size)
    expected_checksum = calculate_checksum(data)

    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect(('::1', rinetd_port))

        send_all(s, data)
        received = recv_all(s, size)

    assert len(received) == size
    assert calculate_checksum(received) == expected_checksum


@pytest.mark.ipv6
def test_ipv4_to_ipv6_forwarding(rinetd, tcp_echo_server_ipv6):
    """Test forwarding from IPv4 client to IPv6 backend."""
    if not ipv6_available():
        pytest.skip("IPv6 not available")

    rinetd_port = get_free_port()

    # Bind on IPv4, connect to IPv6 backend
    rules = [
        f"0.0.0.0 {rinetd_port} ::1 {tcp_echo_server_ipv6.actual_port}"
    ]

    rinetd(rules)
    assert wait_for_port(rinetd_port)

    size = 1024
    data = generate_random_data(size)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect(('127.0.0.1', rinetd_port))

        send_all(s, data)
        received = recv_all(s, size)

    assert len(received) == size
    assert received == data


@pytest.mark.ipv6
def test_ipv6_to_ipv4_forwarding(rinetd, tcp_echo_server):
    """Test forwarding from IPv6 client to IPv4 backend."""
    if not ipv6_available():
        pytest.skip("IPv6 not available")

    rinetd_port = get_free_port(ipv6=True)

    # Bind on IPv6, connect to IPv4 backend
    rules = [
        f"::0 {rinetd_port} 127.0.0.1 {tcp_echo_server.actual_port}"
    ]

    rinetd(rules)
    assert wait_for_port_ipv6(rinetd_port)

    size = 1024
    data = generate_random_data(size)

    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect(('::1', rinetd_port))

        send_all(s, data)
        received = recv_all(s, size)

    assert len(received) == size
    assert received == data
