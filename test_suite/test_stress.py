import pytest
import socket
import concurrent.futures
import time
from .utils import get_free_port, wait_for_port, generate_random_data, calculate_checksum, send_all, recv_all

def run_client(port, size, data, expected_checksum):
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=10) as s:
            send_all(s, data)
            received = recv_all(s, size)
            
        if len(received) != size:
            return False, f"Size mismatch: {len(received)} != {size}"
            
        if calculate_checksum(received) != expected_checksum:
            return False, "Checksum mismatch"
            
        return True, None
    except Exception as e:
        return False, str(e)

@pytest.mark.parametrize("num_clients", [
    pytest.param(10, marks=pytest.mark.quick),
    50,
    100,
    500,
    1000
])
def test_parallel_connections(rinetd, tcp_echo_server, num_clients):
    """Test multiple parallel connections."""
    rinetd_port = get_free_port()
    
    rules = [
        f"0.0.0.0 {rinetd_port} {tcp_echo_server.host} {tcp_echo_server.actual_port}"
    ]
    
    rinetd(rules)
    assert wait_for_port(rinetd_port)
    
    size = 1024 # 1KB
    data = generate_random_data(size)
    expected_checksum = calculate_checksum(data)
    
    # Use more workers for higher parallelism
    max_workers = min(num_clients, 200) 
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(run_client, rinetd_port, size, data, expected_checksum)
            for _ in range(num_clients)
        ]
        
        results = [f.result() for f in concurrent.futures.as_completed(futures)]
        
    failures = [r for r in results if not r[0]]
    assert len(failures) == 0, f"Failed {len(failures)}/{num_clients} connections: {failures[:5]}"


def test_long_duration(rinetd, tcp_echo_server):
    """Test a connection that stays open for a while (simulated)."""
    rinetd_port = get_free_port()
    
    rules = [
        f"0.0.0.0 {rinetd_port} {tcp_echo_server.host} {tcp_echo_server.actual_port}"
    ]
    
    rinetd(rules)
    assert wait_for_port(rinetd_port)
    
    with socket.create_connection(('127.0.0.1', rinetd_port), timeout=10) as s:
        # Send a bit
        s.send(b"ping")
        assert s.recv(4) == b"ping"
        
        # Wait
        time.sleep(2)
        
        # Send more
        s.send(b"pong")
        assert s.recv(4) == b"pong"

def test_randomized_stress(rinetd, tcp_echo_server, udp_echo_server, unix_echo_server, tmp_path):
    """
    Stress test where each thread picks random parameters from the matrix
    and repeats connections for a defined duration.
    """
    import random
    from .test_matrix import PROTOCOLS, SIZES, CHUNK_SIZES
    from .utils import run_repeated_transfers
    
    num_threads = 20
    duration = 300 # 5 minutes
    
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
            listen_path = str(tmp_path / f"stress_listen_{lp}_{cp}.sock")
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
        while time.time() - start_time < duration:
            # Pick random parameters
            lp, cp = random.choice(PROTOCOLS)
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

    max_workers = num_threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(worker, i) for i in range(num_threads)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]
        
    failures = [r for r in results if not r[0]]
    assert len(failures) == 0, f"Stress test failed: {failures[:5]}"
