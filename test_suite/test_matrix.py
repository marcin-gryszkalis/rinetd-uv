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

# Parallelism dimension
PARALLELISM = [1, 2, 5, 10]

# Minimum duration for each test case (seconds)
DEFAULT_DURATION = 10

@pytest.mark.parametrize("listen_proto, connect_proto", PROTOCOLS)
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("chunk_size", CHUNK_SIZES)
@pytest.mark.parametrize("parallelism", PARALLELISM)
def test_transfer_matrix(rinetd, tcp_echo_server, udp_echo_server, unix_echo_server, 
                         listen_proto, connect_proto, size, chunk_size, parallelism, tmp_path):
    """
    Multidimensional matrix test for data transfer.
    Tests combinations of protocols, transfer sizes, chunk sizes, and parallelism.
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
        listen_path = str(tmp_path / f"listen_{listen_proto}_{connect_proto}_{size}_{chunk_size}_{parallelism}.sock")

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
    seed = hash((listen_proto, connect_proto, size, chunk_size, parallelism)) % 2**32
    
    listen_addr = ('127.0.0.1', listen_port) if listen_port else listen_path
    
    from .utils import run_repeated_transfers
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=parallelism) as executor:
        futures = [
            executor.submit(run_repeated_transfers, listen_proto, listen_addr, size, chunk_size, seed + i, DEFAULT_DURATION)
            for i in range(parallelism)
        ]
        
        results = [f.result() for f in concurrent.futures.as_completed(futures)]
        
    failures = [r for r in results if not r[0]]
    assert len(failures) == 0, f"Failed {len(failures)}/{parallelism} clients: {failures[:5]}"
