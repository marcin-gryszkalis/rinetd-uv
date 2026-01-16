import pytest
import socket
import time
import os
from .utils import generate_random_data, calculate_checksum, send_all, recv_all, get_free_port, wait_for_port, ipv6_available

# Test parameters
TRANSFER_SIZES = [
    0,              # Zero bytes
    1,              # 1 byte
    1024,           # 1 KB
    65536,          # 64 KB
    1024 * 1024,    # 1 MB
    # 10 * 1024 * 1024, # 10 MB (commented out for speed during dev, uncomment for full suite)
]

@pytest.mark.parametrize("size", TRANSFER_SIZES)
def test_tcp_transfer(rinetd, tcp_echo_server, size):
    """Test TCP to TCP forwarding with various sizes."""
    rinetd_port = get_free_port()
    
    # Configure rinetd: bind_addr bind_port connect_addr connect_port
    rules = [
        f"0.0.0.0 {rinetd_port} {tcp_echo_server.host} {tcp_echo_server.actual_port}"
    ]
    
    rinetd(rules)
    assert wait_for_port(rinetd_port), "rinetd did not open port"
    
    # Generate data
    data = generate_random_data(size)
    expected_checksum = calculate_checksum(data)
    
    # Connect to rinetd
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect(('127.0.0.1', rinetd_port))
        
        # Send data
        send_all(s, data)
        
        # Receive echo
        received = recv_all(s, size)
        
    assert len(received) == size
    assert calculate_checksum(received) == expected_checksum

@pytest.mark.parametrize("size", [1, 1024, 60000]) # UDP has size limits per packet usually
def test_udp_transfer(rinetd, udp_echo_server, size):
    """Test UDP to UDP forwarding."""
    rinetd_port = get_free_port()
    
    # Configure rinetd for UDP: bind_addr bind_port/udp connect_addr connect_port/udp
    rules = [
        f"0.0.0.0 {rinetd_port}/udp {udp_echo_server.host} {udp_echo_server.actual_port}/udp"
    ]
    
    rinetd(rules)
    # UDP doesn't "listen" in the same way, so wait_for_port might not work as expected for UDP 
    # unless we check if we can send to it. But rinetd should be up quickly.
    time.sleep(0.5)
    
    data = generate_random_data(size)
    
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(2)
        s.sendto(data, ('127.0.0.1', rinetd_port))
        
        received, _ = s.recvfrom(65535)
        
    assert len(received) == size
    assert received == data

def test_unix_to_tcp(rinetd, tcp_echo_server, tmp_path):
    """Test Unix socket (bind) to TCP (connect) forwarding."""
    socket_path = str(tmp_path / "rinetd.sock")
    
    # Configure rinetd: unix:/path ... connect_addr connect_port
    rules = [
        f"unix:{socket_path} {tcp_echo_server.host} {tcp_echo_server.actual_port}"
    ]
    
    rinetd(rules)
    time.sleep(0.5)
    assert os.path.exists(socket_path)
    
    size = 1024
    data = generate_random_data(size)
    
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect(socket_path)
        
        send_all(s, data)
        
        received = recv_all(s, size)
        
    assert len(received) == size
    assert received == data

def test_tcp_to_unix(rinetd, unix_echo_server):
    """Test TCP (bind) to Unix socket (connect) forwarding."""
    rinetd_port = get_free_port()
    
    # Configure rinetd: bind_addr bind_port unix:/path
    rules = [
        f"0.0.0.0 {rinetd_port} unix:{unix_echo_server.path}"
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

@pytest.mark.slow
def test_large_transfer(rinetd, tcp_echo_server):
    """Test a large transfer (100MB) using streaming."""
    rinetd_port = get_free_port()

    rules = [
        f"0.0.0.0 {rinetd_port} {tcp_echo_server.host} {tcp_echo_server.actual_port}"
    ]

    rinetd(rules)
    assert wait_for_port(rinetd_port)

    size = 100 * 1024 * 1024  # 100MB

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(60)
        s.connect(('127.0.0.1', rinetd_port))

        from .utils import send_streaming, verify_streaming
        import threading

        def sender():
            send_streaming(s, size)

        t = threading.Thread(target=sender)
        t.start()

        success, msg, _ = verify_streaming(s, size)
        t.join()

        assert success, msg


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
    """Test TCP forwarding over IPv6."""
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

