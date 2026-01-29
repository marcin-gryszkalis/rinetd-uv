import pytest
import socket
import threading
import os
import time
from .utils import (
    get_free_port, wait_for_port, run_parallel_pairs
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


@pytest.mark.parametrize("server_type", SERVER_TYPES)
@pytest.mark.parametrize("listen_proto, connect_proto", PROTOCOLS)
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("chunk_size", CHUNK_SIZES)
@pytest.mark.parametrize("parallelism", PARALLELISM)
def test_transfer_matrix(rinetd, server_type, listen_proto, connect_proto,
                         size, chunk_size, parallelism, tmp_path):
    """
    Multidimensional matrix test for data transfer.

    Architecture: Each parallel "client" gets its own dedicated backend server.
    This eliminates server contention - we test rinetd's ability to multiplex
    connections, not the backend server's ability to handle burst load.

    For parallelism=5:
        Server1 <-- rinetd rule1 <-- Client1
        Server2 <-- rinetd rule2 <-- Client2
        Server3 <-- rinetd rule3 <-- Client3
        Server4 <-- rinetd rule4 <-- Client4
        Server5 <-- rinetd rule5 <-- Client5
    """
    # Skip incompatible server_type/protocol combinations
    # echo and sha256 modes support UDP; upload/download (non-sha256) don't
    if server_type not in ("echo", "upload_sha256", "download_sha256") and (listen_proto == "udp" or connect_proto == "udp"):
        pytest.skip(f"{server_type} mode not supported with UDP")

    # Skip 1-byte chunks with large sizes to avoid OOM due to lack of flow control
    if chunk_size == 1 and size > 1024:
        pytest.skip("1-byte chunks with large sizes cause OOM (no flow control)")

    # UDP has a maximum datagram size (65535 total, ~65507 payload)
    # SHA256 modes append 32-byte hash to each packet, so reduce limit accordingly
    if listen_proto == "udp" or connect_proto == "udp":
        if server_type in ("upload_sha256", "download_sha256"):
            max_udp_chunk = 65507 - 32  # Reserve space for SHA256 hash
        else:
            max_udp_chunk = 65507
        if chunk_size > max_udp_chunk:
            chunk_size = max_udp_chunk

    # Generate base seed for reproducibility
    base_seed = hash((server_type, listen_proto, connect_proto, size, chunk_size, parallelism)) % 2**32

    # Create configuration for each client-server pair
    pairs_config = [
        {
            "listen_proto": listen_proto,
            "connect_proto": connect_proto,
            "mode": server_type,
            "size": size,
            "chunk_size": chunk_size,
            "seed": base_seed + i,
        }
        for i in range(parallelism)
    ]

    # Run all pairs in parallel
    results = run_parallel_pairs(
        pairs_config=pairs_config,
        rinetd_starter=rinetd,
        duration=DEFAULT_DURATION,
        tmp_path=tmp_path,
    )

    # Check results
    failures = [r for r in results if not r["success"]]

    # All pairs should succeed - with 1:1 architecture, no contention expected
    assert len(failures) == 0, \
        f"Failed {len(failures)}/{parallelism} pairs: {[f['message'] for f in failures[:5]]}"
