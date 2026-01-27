import pytest
import socket
import threading
import os
import time
from .utils import (
    get_free_port, wait_for_port, generate_random_data,
    calculate_checksum, send_all, recv_all,
    send_streaming, verify_streaming,
    run_repeated_transfers_mode
)

# Matrix parameters
PROTOCOLS = [
    ("tcp", "tcp"),
    ("tcp", "unix"),
    ("udp", "udp"),
    ("unix", "tcp"),
    ("unix", "unix"),
]

# Server types to test
SERVER_TYPES = [
    "echo",            # Echo server: send data, receive same data back
    "upload",          # Upload server: send data, receive byte count
    "download",        # Download server: request data, verify received
    "upload_sha256",   # Upload server: send data, verify rolling SHA256
    "download_sha256", # Download server: request data, send rolling SHA256
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


def get_compatible_protocols(server_type):
    """Return list of compatible protocol combinations for a server type."""
    if server_type == "echo":
        # Echo works with all protocols
        return PROTOCOLS
    else:
        # Upload/download only work with TCP backend (no unix/udp backend servers)
        return [
            ("tcp", "tcp"),
            ("unix", "tcp"),
        ]


@pytest.mark.parametrize("server_type", SERVER_TYPES)
@pytest.mark.parametrize("listen_proto, connect_proto", PROTOCOLS)
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("chunk_size", CHUNK_SIZES)
@pytest.mark.parametrize("parallelism", PARALLELISM)
def test_transfer_matrix(rinetd, tcp_echo_server, udp_echo_server, unix_echo_server,
                         tcp_upload_server, tcp_download_server,
                         tcp_upload_sha256_server, tcp_download_sha256_server,
                         unix_upload_server, unix_download_server,
                         unix_upload_sha256_server, unix_download_sha256_server,
                         udp_download_sha256_server, udp_upload_sha256_server,
                         server_type, listen_proto, connect_proto, size, chunk_size,
                         parallelism, tmp_path):
    """
    Multidimensional matrix test for data transfer.
    Tests combinations of server types, protocols, transfer sizes, chunk sizes, and parallelism.
    """
    # Skip incompatible server_type/protocol combinations
    # echo and sha256 modes support UDP; upload/download (non-sha256) don't
    if server_type not in ("echo", "upload_sha256", "download_sha256") and (listen_proto == "udp" or connect_proto == "udp"):
        pytest.skip(f"{server_type} mode not supported with UDP")

    # Skip 1-byte chunks with large sizes to avoid OOM due to lack of flow control
    # (rinetd allocates 64KB buffer per read, with 1-byte chunks this causes
    # unbounded memory growth when reads outpace writes)
    if chunk_size == 1 and size > 1024:
        pytest.skip("1-byte chunks with large sizes cause OOM (no flow control)")

    # UDP with high parallelism causes packet loss (inherent UDP limitation)
    # if listen_proto == "udp" and parallelism > 5:
    #    pytest.skip("UDP with high parallelism causes packet loss")

    # UDP has a maximum datagram size (65535 total, ~65507 payload)
    # SHA256 modes append 32-byte hash to each packet, so reduce limit accordingly
    if listen_proto == "udp" or connect_proto == "udp":
        if server_type in ("upload_sha256", "download_sha256"):
            max_udp_chunk = 65507 - 32  # Reserve space for SHA256 hash
        else:
            max_udp_chunk = 65507
        if chunk_size > max_udp_chunk:
            chunk_size = max_udp_chunk

    # Setup rinetd ports/paths
    listen_port = None
    listen_path = None
    if listen_proto == "tcp" or listen_proto == "udp":
        listen_port = get_free_port()
    else:
        # Unix socket paths limited to 107 chars - use hash for uniqueness
        path_hash = hash((server_type, listen_proto, connect_proto, size, chunk_size, parallelism)) & 0xFFFFFFFF
        listen_path = str(tmp_path / f"l_{path_hash:08x}.sock")

    # Select backend server based on server_type
    backend_host = "127.0.0.1"
    backend_port = None
    backend_path = None

    if server_type == "echo":
        if connect_proto == "tcp":
            backend_port = tcp_echo_server.actual_port
        elif connect_proto == "udp":
            backend_port = udp_echo_server.actual_port
        elif connect_proto == "unix":
            backend_path = unix_echo_server.path
    elif server_type == "upload":
        if connect_proto == "tcp":
            backend_port = tcp_upload_server.actual_port
        elif connect_proto == "unix":
            backend_path = unix_upload_server.path
    elif server_type == "download":
        if connect_proto == "tcp":
            backend_port = tcp_download_server.actual_port
        elif connect_proto == "unix":
            backend_path = unix_download_server.path
    elif server_type == "upload_sha256":
        if connect_proto == "tcp":
            backend_port = tcp_upload_sha256_server.actual_port
        elif connect_proto == "unix":
            backend_path = unix_upload_sha256_server.path
        elif connect_proto == "udp":
            backend_port = udp_upload_sha256_server.actual_port
    elif server_type == "download_sha256":
        if connect_proto == "tcp":
            backend_port = tcp_download_sha256_server.actual_port
        elif connect_proto == "unix":
            backend_path = unix_download_sha256_server.path
        elif connect_proto == "udp":
            backend_port = udp_download_sha256_server.actual_port

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
            time.sleep(0.5)  # UDP needs more time on some platforms (FreeBSD)
    else:
        time.sleep(0.5)  # Unix

        assert os.path.exists(listen_path)

    # Generate random data with a seed for reproducibility
    seed = hash((server_type, listen_proto, connect_proto, size, chunk_size, parallelism)) % 2**32

    listen_addr = ('127.0.0.1', listen_port) if listen_port else listen_path

    import concurrent.futures

    # Create barrier for thread synchronization - all threads wait after their
    # probe phase completes, then start high-volume transfers simultaneously.
    # This prevents early threads from overwhelming the system while others
    # are still warming up their connection paths.
    barrier = threading.Barrier(parallelism)

    with concurrent.futures.ThreadPoolExecutor(max_workers=parallelism) as executor:
        futures = [
            executor.submit(
                run_repeated_transfers_mode,
                listen_proto, listen_addr, size, chunk_size, seed + i,
                DEFAULT_DURATION, server_type, barrier
            )
            for i in range(parallelism)
        ]

        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    failures = [r for r in results if not r[0]]

    # UDP with high parallelism and large packets may have some packet loss
    # This is expected UDP behavior under heavy load - allow up to 20% failure rate
    if listen_proto == "udp" and parallelism >= 5 and chunk_size >= 16384:
        max_failures = max(1, parallelism * 2 // 10)  # Allow up to 20% failures
        assert len(failures) <= max_failures, \
            f"Too many failures for UDP under load: {len(failures)}/{parallelism} (max {max_failures}): {failures[:5]}"
    else:
        assert len(failures) == 0, f"Failed {len(failures)}/{parallelism} clients: {failures[:5]}"
