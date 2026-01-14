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
