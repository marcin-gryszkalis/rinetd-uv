import pytest
import socket
import threading
import os
import time
from .utils import (
    get_free_port, wait_for_port, generate_random_data, 
    calculate_checksum, send_all, recv_all,
    send_streaming, verify_streaming
)

# Matrix parameters
PROTOCOLS = [
    ("tcp", "tcp"),
    ("tcp", "unix"),
    ("udp", "udp"),
    ("unix", "tcp"),
    ("unix", "unix"),
]

# Sizes to test in the matrix
SIZES = [
    1024,           # 1 KB
    65536,          # 64 KB
    pytest.param(1048576, marks=pytest.mark.slow), # 1 MB
    pytest.param(10 * 1048576, marks=pytest.mark.slow), # 10 MB
]

# Chunk sizes (packet sizes) to test
CHUNK_SIZES = [
    1,              # Stressful (1 byte at a time)
    1024,           # Standard
    16384,          # Large
    pytest.param(65536, marks=pytest.mark.slow), # Very large
]


@pytest.mark.parametrize("listen_proto, connect_proto", PROTOCOLS)
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("chunk_size", CHUNK_SIZES)
def test_transfer_matrix(rinetd, tcp_echo_server, udp_echo_server, unix_echo_server, 
                         listen_proto, connect_proto, size, chunk_size, tmp_path):
    """
    Multidimensional matrix test for data transfer.
    Tests combinations of protocols, transfer sizes, and chunk sizes.
    """
    # Skip UDP with 1-byte chunks if it's too slow or problematic for UDP
    if listen_proto == "udp" and chunk_size == 1 and size > 1024:
        pytest.skip("UDP with 1-byte chunks is too slow for large sizes")

    # UDP has a maximum datagram size (65535 total, ~65507 payload)
    if listen_proto == "udp" and chunk_size > 65507:
        chunk_size = 65507


    # Setup rinetd ports/paths
    listen_port = None
    listen_path = None
    if listen_proto == "tcp" or listen_proto == "udp":
        listen_port = get_free_port()
    else:
        listen_path = str(tmp_path / f"listen_{listen_proto}_{connect_proto}_{size}_{chunk_size}.sock")

    # Setup backend info
    backend_host = "127.0.0.1"
    backend_port = None
    backend_path = None
    
    if connect_proto == "tcp":
        backend_port = tcp_echo_server.actual_port
    elif connect_proto == "udp":
        backend_port = udp_echo_server.actual_port
    elif connect_proto == "unix":
        backend_path = unix_echo_server.path

    # Build rinetd rule
    listen_spec = f"0.0.0.0 {listen_port}" if listen_port else f"unix:{listen_path}"
    if listen_proto == "udp":
        listen_spec += "/udp"
        
    connect_spec = f"{backend_host} {backend_port}" if backend_port else f"unix:{backend_path}"
    if connect_proto == "udp":
        connect_spec += "/udp"
        
    rules = [f"{listen_spec} {connect_spec}"]
    rinetd(rules)
    
    # Wait for rinetd to be ready
    if listen_port:
        if listen_proto == "tcp":
            assert wait_for_port(listen_port)
        else:
            time.sleep(0.2) # UDP
    else:
        time.sleep(0.2) # Unix
        assert os.path.exists(listen_path)

    # Generate random data with a seed for reproducibility
    seed = hash((listen_proto, connect_proto, size, chunk_size)) % 2**32
    
    if listen_proto == "udp":
        # UDP transfer (datagram-based)
        data = generate_random_data(size)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(5)
            # For UDP, we send in chunks if chunk_size < size
            # Note: rinetd-uv UDP might not reassemble packets if they are split by the client
            # but here we are testing the forwarding of datagrams.
            # If we send multiple datagrams, we expect multiple datagrams back.
            sent_bytes = 0
            received_data = b""
            while sent_bytes < size:
                to_send = min(size - sent_bytes, chunk_size)
                s.sendto(data[sent_bytes:sent_bytes+to_send], ('127.0.0.1', listen_port))
                try:
                    chunk, _ = s.recvfrom(65535)
                    received_data += chunk
                except socket.timeout:
                    break
                sent_bytes += to_send
            
            assert received_data == data
    else:
        # Stream transfer (TCP or Unix)
        family = socket.AF_INET if listen_port else socket.AF_UNIX
        addr = ('127.0.0.1', listen_port) if listen_port else listen_path
        
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect(addr)
            
            # Use streaming functions for better control
            def sender():
                send_streaming(s, size, chunk_size=chunk_size, seed=seed)
            
            t = threading.Thread(target=sender)
            t.start()
            
            success, msg = verify_streaming(s, size, chunk_size=chunk_size, seed=seed)
            t.join()
            
            assert success, msg
