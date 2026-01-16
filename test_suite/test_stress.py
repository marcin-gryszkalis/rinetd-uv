import pytest
import socket
import concurrent.futures
import time
import random
import os
from .utils import (
    get_free_port, wait_for_port, generate_random_data, calculate_checksum,
    send_all, recv_all, run_transfer_until_deadline, random_transfer_params
)

INACTIVE_WAIT = 30

# Duration can be overridden via environment variable
DEFAULT_STRESS_DURATION = 600  # 10 minutes default
QUICK_STRESS_DURATION = 10    # 10 seconds for quick tests


def get_stress_duration(is_quick=False):
    """Get stress duration from environment or use defaults."""
    env_duration = os.environ.get('STRESS_DURATION')
    if env_duration:
        return int(env_duration)
    return QUICK_STRESS_DURATION if is_quick else DEFAULT_STRESS_DURATION


def test_simple():
    print("Simple test running...")
    assert True


@pytest.mark.parametrize("num_clients,is_quick", [
    pytest.param(10, True, marks=pytest.mark.quick),
    pytest.param(50, False),
    pytest.param(100, False),
    pytest.param(500, False, marks=pytest.mark.slow),
    pytest.param(1000, False, marks=pytest.mark.slow),
])
def test_randomized_stress(rinetd, tcp_echo_server, unix_echo_server, num_clients, is_quick, tmp_path):
    """
    Stress test where each thread runs transfers with fully randomized parameters
    (SIZE and CHUNK_SIZE calculated using log-scale distribution).
    Stops gracefully at deadline by finishing current chunk, not whole transfer.

    Note: UDP is excluded from stress tests due to inherent unreliability under
    high concurrency (packet loss causes timeouts). Use test_matrix for UDP coverage.
    """
    # Use only reliable protocols for stress testing
    STRESS_PROTOCOLS = [
        ("tcp", "tcp"),
        ("tcp", "unix"),
        ("unix", "tcp"),
        ("unix", "unix"),
    ]

    num_threads = num_clients
    stress_duration = get_stress_duration(is_quick)

    # Setup rules for all protocol combinations
    rules = []
    protocol_map = {}  # (listen_proto, connect_proto) -> listen_addr

    for lp, cp in STRESS_PROTOCOLS:
        listen_port = None
        listen_path = None
        if lp == "tcp":
            listen_port = get_free_port()
            listen_addr = ('127.0.0.1', listen_port)
        else:
            listen_path = str(tmp_path / f"stress_listen_{lp}_{cp}_{num_clients}.sock")
            listen_addr = listen_path

        backend_host = "127.0.0.1"
        backend_port = None
        backend_path = None

        if cp == "tcp":
            backend_port = tcp_echo_server.actual_port
        elif cp == "unix":
            backend_path = unix_echo_server.path

        listen_spec = f"0.0.0.0 {listen_port}" if listen_port else f"unix:{listen_path}"
        connect_spec = f"{backend_host} {backend_port}" if backend_port else f"unix:{backend_path}"

        rules.append(f"{listen_spec} {connect_spec}")
        protocol_map[(lp, cp)] = listen_addr

    rinetd(rules)
    time.sleep(1)  # Give rinetd time to bind all

    deadline = time.time() + stress_duration

    def worker(thread_id):
        """
        Worker thread that runs randomized transfers until deadline.
        Uses log-scale randomization for SIZE and CHUNK_SIZE.
        Stops gracefully after completing current chunk when deadline is reached.
        """
        # Each thread gets its own RNG seeded from thread_id for reproducibility
        thread_rng = random.Random(thread_id + int(time.time()))
        total_count = 0

        while time.time() < deadline:
            # Pick random protocol combination (TCP/Unix only)
            lp, cp = thread_rng.choice(STRESS_PROTOCOLS)
            listen_addr = protocol_map[(lp, cp)]

            # Run transfers until deadline with fully randomized parameters
            success, msg, count = run_transfer_until_deadline(
                lp, listen_addr, deadline, rng=thread_rng
            )

            total_count += count

            if not success:
                return False, f"Thread {thread_id} failed: {msg}"

        return True, f"Thread {thread_id} completed {total_count} transfers"

    # Cap max_workers to avoid system exhaustion
    # Note: run_transfer also spawns a thread for TCP, so effective load is higher
    max_workers = min(num_threads, 500)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(worker, i) for i in range(num_threads)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    failures = [r for r in results if not r[0]]
    assert len(failures) == 0, f"Stress test failed: {failures[:5]}"


@pytest.mark.quick
def test_randomization_sanity():
    """Verify that random_transfer_params produces sensible values."""
    rng = random.Random(42)

    for proto in ["tcp", "udp", "unix"]:
        sizes = []
        chunks = []
        for _ in range(100):
            size, chunk = random_transfer_params(proto, rng)
            sizes.append(size)
            chunks.append(chunk)

            # Verify constraints
            assert size >= 1, f"Size too small: {size}"
            assert chunk >= 1, f"Chunk too small: {chunk}"
            assert chunk <= size or size == 0, f"Chunk {chunk} > size {size}"

            if proto == "udp":
                assert size <= 65507, f"UDP size too large: {size}"
                assert chunk <= 65507, f"UDP chunk too large: {chunk}"

        # Verify we get a good distribution (not all same values)
        assert len(set(sizes)) > 10, f"Not enough size variety for {proto}"
        assert len(set(chunks)) > 10, f"Not enough chunk variety for {proto}"

