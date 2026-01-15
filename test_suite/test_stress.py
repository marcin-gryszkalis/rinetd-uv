import pytest
import socket
import concurrent.futures
import time
from .utils import get_free_port, wait_for_port, generate_random_data, calculate_checksum, send_all, recv_all

INACTIVE_WAIT = 30
STRESS_DURATION = 300

def test_simple():
    print("Simple test running...")
    assert True

@pytest.mark.parametrize("num_clients", [
    pytest.param(10, marks=pytest.mark.quick),
    50,
    100,
    pytest.param(500, marks=pytest.mark.slow),
    pytest.param(1000, marks=pytest.mark.slow),
])
def test_randomized_stress(rinetd, tcp_echo_server, udp_echo_server, unix_echo_server, num_clients, tmp_path):
    """
    Stress test where each thread picks random parameters from the matrix
    and repeats connections for a defined duration.
    """
    import random
    from .test_matrix import PROTOCOLS, SIZES, CHUNK_SIZES
    from .utils import run_repeated_transfers

    num_threads = num_clients

    # We need to setup multiple rules in rinetd to cover different protocols
    # For simplicity, we'll setup one rule for each protocol combination
    rules = []
    protocol_map = {} # (listen_proto, connect_proto) -> listen_addr

    for lp, cp in PROTOCOLS:
        listen_port = None
        listen_path = None
        if lp in ["tcp", "udp"]:
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
        elif cp == "udp":
            backend_port = udp_echo_server.actual_port
        elif cp == "unix":
            backend_path = unix_echo_server.path

        listen_spec = f"0.0.0.0 {listen_port}" if listen_port else f"unix:{listen_path}"
        if lp == "udp": listen_spec += "/udp"
        connect_spec = f"{backend_host} {backend_port}" if backend_port else f"unix:{backend_path}"
        if cp == "udp": connect_spec += "/udp"

        rules.append(f"{listen_spec} {connect_spec}")
        protocol_map[(lp, cp)] = listen_addr

    rinetd(rules)
    time.sleep(1) # Give rinetd time to bind all

    def worker(thread_id):
        # Each thread runs for 'duration'
        start_time = time.time()
        total_count = 0
        while time.time() - start_time < STRESS_DURATION:
            # Pick random parameters
            lp, cp = random.choice(PROTOCOLS)
            # Handle pytest.param objects in SIZES/CHUNK_SIZES
            size = random.choice([s if not hasattr(s, 'values') else s.values[0] for s in SIZES])
            chunk_size = random.choice([c if not hasattr(c, 'values') else c.values[0] for c in CHUNK_SIZES])

            # UDP chunk size cap
            if lp == "udp" and chunk_size > 65507:
                chunk_size = 65507

            # Skip problematic UDP case
            if lp == "udp" and chunk_size == 1 and size > 1024:
                continue

            listen_addr = protocol_map[(lp, cp)]
            seed = random.randint(0, 2**32 - 1)

            # Run a single transfer
            from .utils import run_transfer
            success, msg = run_transfer(lp, listen_addr, size, chunk_size, seed)
            if not success:
                return False, f"Thread {thread_id} failed: {msg} (params: {lp}->{cp}, size={size}, chunk={chunk_size})"
            total_count += 1
        return True, f"Thread {thread_id} completed {total_count} transfers"

    # Use a reasonable cap for max_workers to avoid system exhaustion,
    # but still spawn num_threads total tasks.
    # Note: run_transfer also spawns a thread for TCP, so we are doubling the load.
    max_workers = min(num_threads, 500)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(worker, i) for i in range(num_threads)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    failures = [r for r in results if not r[0]]
    assert len(failures) == 0, f"Stress test failed: {failures[:5]}"

