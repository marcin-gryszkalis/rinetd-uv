"""
Big transfer tests for rinetd.

These tests verify rinetd's ability to handle very large data transfers
(1GB, 8GB, 16GB) using optimal settings for maximum throughput.

Uses 1:1 client-server pair architecture - each client has its own dedicated
backend server, eliminating server contention and testing rinetd's throughput.

Run with: pytest -v -m big --timeout=86400
(Excluded from normal test runs due to duration and resource requirements)
"""
import pytest
import socket
import time
import random
import hashlib
import threading
from .utils import get_free_port, wait_for_port
from .servers import TcpUploadServer, TcpDownloadServer, TcpEchoServer

# Optimal chunk size for throughput (64KB)
CHUNK_SIZE = 65536

DEFAULT_TIMEOUT = 3600

# Big transfer sizes
SIZES = [
    pytest.param(1 * 1024**3, id="1GB", marks=pytest.mark.big),
    pytest.param(8 * 1024**3, id="8GB", marks=pytest.mark.big),
    pytest.param(16 * 1024**3, id="16GB", marks=pytest.mark.big),
]


def send_upload_data(sock, size, seed=42, progress_interval=100*1024*1024):
    """
    Send `size` bytes of seeded random data to socket.
    Reports progress every `progress_interval` bytes.
    Returns SHA256 hash of all data sent.
    """
    rng = random.Random(seed)
    hasher = hashlib.sha256()
    bytes_sent = 0
    start_time = time.time()
    last_report = 0

    while bytes_sent < size:
        to_send = min(CHUNK_SIZE, size - bytes_sent)
        data = rng.randbytes(to_send)
        sock.sendall(data)
        hasher.update(data)
        bytes_sent += to_send

        if bytes_sent - last_report >= progress_interval:
            elapsed = time.time() - start_time
            mb_sent = bytes_sent / (1024 * 1024)
            rate = mb_sent / elapsed if elapsed > 0 else 0
            print(f"  Upload: {mb_sent:.1f} MB sent ({rate:.1f} MB/s)")
            last_report = bytes_sent

    return hasher.hexdigest()


def recv_download_data(sock, size, seed=42, progress_interval=100*1024*1024):
    """
    Receive `size` bytes from socket and verify against seeded random data.
    Reports progress every `progress_interval` bytes.
    Returns (success, message, sha256_hash).
    """
    rng = random.Random(seed)
    hasher = hashlib.sha256()
    bytes_received = 0
    start_time = time.time()
    last_report = 0
    # Pre-generate expected bytes in CHUNK_SIZE blocks to avoid randbytes
    # alignment issues (randbytes is not splittable at non-4-byte boundaries)
    expect_buf = b''

    while bytes_received < size:
        to_recv = min(CHUNK_SIZE, size - bytes_received)
        data = sock.recv(to_recv)
        if not data:
            return False, f"Connection closed after {bytes_received} bytes", None

        hasher.update(data)

        # Generate expected data in aligned chunks as needed
        while len(expect_buf) < len(data):
            expect_buf += rng.randbytes(CHUNK_SIZE)

        if data != expect_buf[:len(data)]:
            return False, f"Data mismatch at byte {bytes_received}", None
        expect_buf = expect_buf[len(data):]

        bytes_received += len(data)

        if bytes_received - last_report >= progress_interval:
            elapsed = time.time() - start_time
            mb_recv = bytes_received / (1024 * 1024)
            rate = mb_recv / elapsed if elapsed > 0 else 0
            print(f"  Download: {mb_recv:.1f} MB received ({rate:.1f} MB/s)")
            last_report = bytes_received

    return True, "OK", hasher.hexdigest()


@pytest.mark.big
@pytest.mark.parametrize("size", SIZES)
def test_big_tcp_upload(rinetd, size):
    """
    Test large TCP upload through rinetd.

    Architecture: Dedicated backend server (1:1) eliminates server contention.
    Client sends `size` bytes of seeded random data.
    Server discards data and returns byte count.
    """
    # Create dedicated backend server for this test
    server = TcpUploadServer()
    server.start()
    assert server.wait_ready(timeout=10), "Backend server failed to start"

    try:
        rinetd_port = get_free_port()

        rules = [
            f"0.0.0.0 {rinetd_port} {server.host} {server.actual_port}"
        ]

        rinetd(rules)
        assert wait_for_port(rinetd_port), "rinetd did not open port"

        print(f"\nStarting {size / (1024**3):.0f}GB upload test...")
        start_time = time.time()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Set socket buffer sizes for better throughput
            s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024)
            s.settimeout(DEFAULT_TIMEOUT)
            s.connect(('127.0.0.1', rinetd_port))

            # Send size header (server protocol requires "<size>\n" before data)
            s.sendall(f"{size}\n".encode())

            # Send all data
            send_upload_data(s, size)

            # Shutdown write side to signal end
            s.shutdown(socket.SHUT_WR)

            # Read server's byte count response
            response = b""
            while True:
                chunk = s.recv(1024)
                if not chunk:
                    break
                response += chunk

        elapsed = time.time() - start_time
        rate_mbps = (size / (1024 * 1024)) / elapsed if elapsed > 0 else 0

        # Parse server response
        reported_bytes = int(response.decode().strip())
        print(f"Upload complete: {size} bytes sent, {reported_bytes} received by server")
        print(f"Time: {elapsed:.1f}s, Rate: {rate_mbps:.1f} MB/s")

        assert reported_bytes == size, f"Server received {reported_bytes} bytes, expected {size}"

    finally:
        server.stop()


@pytest.mark.big
@pytest.mark.parametrize("size", SIZES)
def test_big_tcp_download(rinetd, size):
    """
    Test large TCP download through rinetd.

    Architecture: Dedicated backend server (1:1) eliminates server contention.
    Client requests `size` bytes with a seed.
    Server generates seeded random data.
    Client verifies data integrity.
    """
    # Create dedicated backend server for this test
    server = TcpDownloadServer()
    server.start()
    assert server.wait_ready(timeout=10), "Backend server failed to start"

    try:
        rinetd_port = get_free_port()

        rules = [
            f"0.0.0.0 {rinetd_port} {server.host} {server.actual_port}"
        ]

        rinetd(rules)
        assert wait_for_port(rinetd_port), "rinetd did not open port"

        seed = 12345
        print(f"\nStarting {size / (1024**3):.0f}GB download test...")
        start_time = time.time()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Set socket buffer sizes for better throughput
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
            s.settimeout(DEFAULT_TIMEOUT)
            s.connect(('127.0.0.1', rinetd_port))

            # Send download request: "<size> <seed>\n"
            request = f"{size} {seed}\n".encode()
            s.sendall(request)

            # Receive and verify data
            success, msg, data_hash = recv_download_data(s, size, seed=seed)

        elapsed = time.time() - start_time
        rate_mbps = (size / (1024 * 1024)) / elapsed if elapsed > 0 else 0

        print(f"Download complete: {size} bytes received")
        print(f"Time: {elapsed:.1f}s, Rate: {rate_mbps:.1f} MB/s")

        assert success, msg

    finally:
        server.stop()


@pytest.mark.big
@pytest.mark.parametrize("size", SIZES)
def test_big_tcp_echo(rinetd, size):
    """
    Test large TCP echo (bidirectional) through rinetd.

    Architecture: Dedicated backend server (1:1) eliminates server contention.
    This tests the full duplex capability by sending data and receiving
    it echoed back simultaneously.
    """
    # Create dedicated backend server for this test
    server = TcpEchoServer()
    server.start()
    assert server.wait_ready(timeout=10), "Backend server failed to start"

    try:
        rinetd_port = get_free_port()

        rules = [
            f"0.0.0.0 {rinetd_port} {server.host} {server.actual_port}"
        ]

        rinetd(rules)
        assert wait_for_port(rinetd_port), "rinetd did not open port"

        seed = 54321
        print(f"\nStarting {size / (1024**3):.0f}GB echo test...")
        start_time = time.time()

        send_error = [None]
        send_hash = [None]

        def sender(sock, size, seed):
            try:
                rng = random.Random(seed)
                hasher = hashlib.sha256()
                bytes_sent = 0
                while bytes_sent < size:
                    to_send = min(CHUNK_SIZE, size - bytes_sent)
                    data = rng.randbytes(to_send)
                    sock.sendall(data)
                    hasher.update(data)
                    bytes_sent += to_send
                send_hash[0] = hasher.hexdigest()
            except Exception as e:
                send_error[0] = str(e)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
            s.settimeout(DEFAULT_TIMEOUT * 2)  # 2 hour timeout for bidirectional
            s.connect(('127.0.0.1', rinetd_port))

            # Start sender thread
            t = threading.Thread(target=sender, args=(s, size, seed))
            t.start()

            # Receive in main thread - generate expected data in CHUNK_SIZE blocks
            # to avoid randbytes alignment issues (not splittable at non-4-byte boundaries)
            rng = random.Random(seed)
            hasher = hashlib.sha256()
            bytes_received = 0
            last_report = 0
            progress_interval = 100 * 1024 * 1024
            expect_buf = b''

            while bytes_received < size:
                to_recv = min(CHUNK_SIZE, size - bytes_received)
                data = s.recv(to_recv)
                if not data:
                    break

                hasher.update(data)
                while len(expect_buf) < len(data):
                    expect_buf += rng.randbytes(CHUNK_SIZE)
                assert data == expect_buf[:len(data)], f"Data mismatch at byte {bytes_received}"
                expect_buf = expect_buf[len(data):]
                bytes_received += len(data)

                if bytes_received - last_report >= progress_interval:
                    elapsed = time.time() - start_time
                    mb = bytes_received / (1024 * 1024)
                    rate = mb / elapsed if elapsed > 0 else 0
                    print(f"  Echo: {mb:.1f} MB echoed ({rate:.1f} MB/s)")
                    last_report = bytes_received

            t.join()

        elapsed = time.time() - start_time
        rate_mbps = (size / (1024 * 1024)) / elapsed if elapsed > 0 else 0

        print(f"Echo complete: {size} bytes round-tripped")
        print(f"Time: {elapsed:.1f}s, Rate: {rate_mbps:.1f} MB/s")

        assert send_error[0] is None, f"Sender error: {send_error[0]}"
        assert bytes_received == size, f"Received {bytes_received} bytes, expected {size}"
        assert hasher.hexdigest() == send_hash[0], "SHA256 mismatch between sent and received data"

    finally:
        server.stop()


@pytest.mark.big
def test_big_multiple_concurrent(rinetd):
    """
    Test multiple large transfers running concurrently.

    Architecture: 1:1 pairs - each client gets its own dedicated backend server.
    Runs 4 parallel 1GB transfers (2 uploads, 2 downloads) to verify
    rinetd handles concurrent big transfers correctly with no server contention.
    """
    size = 1 * 1024**3  # 1GB each

    # Create 4 dedicated backend servers (1:1 architecture)
    upload_server_1 = TcpUploadServer()
    upload_server_2 = TcpUploadServer()
    download_server_1 = TcpDownloadServer()
    download_server_2 = TcpDownloadServer()

    servers = [upload_server_1, upload_server_2, download_server_1, download_server_2]

    # Start all servers
    for server in servers:
        server.start()
        assert server.wait_ready(timeout=10), f"Backend server {server} failed to start"

    try:
        # Allocate rinetd listen ports
        upload_port_1 = get_free_port()
        upload_port_2 = get_free_port()
        download_port_1 = get_free_port()
        download_port_2 = get_free_port()

        # Create rules for all 4 pairs
        rules = [
            f"0.0.0.0 {upload_port_1} {upload_server_1.host} {upload_server_1.actual_port}",
            f"0.0.0.0 {upload_port_2} {upload_server_2.host} {upload_server_2.actual_port}",
            f"0.0.0.0 {download_port_1} {download_server_1.host} {download_server_1.actual_port}",
            f"0.0.0.0 {download_port_2} {download_server_2.host} {download_server_2.actual_port}",
        ]

        rinetd(rules)
        assert wait_for_port(upload_port_1), "rinetd did not open upload_port_1"
        assert wait_for_port(upload_port_2), "rinetd did not open upload_port_2"
        assert wait_for_port(download_port_1), "rinetd did not open download_port_1"
        assert wait_for_port(download_port_2), "rinetd did not open download_port_2"

        results = {}

        def upload_worker(worker_id, port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024)
                    s.settimeout(DEFAULT_TIMEOUT)
                    s.connect(('127.0.0.1', port))

                    # Send size header (server protocol requires "<size>\n" before data)
                    s.sendall(f"{size}\n".encode())

                    rng = random.Random(worker_id)
                    bytes_sent = 0
                    while bytes_sent < size:
                        to_send = min(CHUNK_SIZE, size - bytes_sent)
                        data = rng.randbytes(to_send)
                        s.sendall(data)
                        bytes_sent += to_send

                    s.shutdown(socket.SHUT_WR)
                    response = b""
                    while True:
                        chunk = s.recv(1024)
                        if not chunk:
                            break
                        response += chunk

                    reported = int(response.decode().strip())
                    results[f"upload_{worker_id}"] = (reported == size, reported)
            except Exception as e:
                results[f"upload_{worker_id}"] = (False, str(e))

        def download_worker(worker_id, port):
            try:
                seed = worker_id * 1000
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
                    s.settimeout(DEFAULT_TIMEOUT)
                    s.connect(('127.0.0.1', port))

                    request = f"{size} {seed}\n".encode()
                    s.sendall(request)

                    rng = random.Random(seed)
                    bytes_received = 0
                    expect_buf = b''
                    while bytes_received < size:
                        to_recv = min(CHUNK_SIZE, size - bytes_received)
                        data = s.recv(to_recv)
                        if not data:
                            results[f"download_{worker_id}"] = (False, f"Disconnected at {bytes_received}")
                            return

                        while len(expect_buf) < len(data):
                            expect_buf += rng.randbytes(CHUNK_SIZE)
                        if data != expect_buf[:len(data)]:
                            results[f"download_{worker_id}"] = (False, f"Mismatch at {bytes_received}")
                            return
                        expect_buf = expect_buf[len(data):]
                        bytes_received += len(data)

                    results[f"download_{worker_id}"] = (bytes_received == size, bytes_received)
            except Exception as e:
                results[f"download_{worker_id}"] = (False, str(e))

        print("\nStarting 4x1GB concurrent transfer test (1:1 architecture)...")
        start_time = time.time()

        threads = [
            threading.Thread(target=upload_worker, args=(1, upload_port_1)),
            threading.Thread(target=upload_worker, args=(2, upload_port_2)),
            threading.Thread(target=download_worker, args=(1, download_port_1)),
            threading.Thread(target=download_worker, args=(2, download_port_2)),
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        elapsed = time.time() - start_time
        total_data = 4 * size
        rate_mbps = (total_data / (1024 * 1024)) / elapsed if elapsed > 0 else 0

        print(f"Concurrent transfers complete: {len(results)} workers finished")
        print(f"Time: {elapsed:.1f}s, Aggregate rate: {rate_mbps:.1f} MB/s")

        for name, (success, detail) in results.items():
            print(f"  {name}: {'OK' if success else 'FAILED'} - {detail}")
            assert success, f"{name} failed: {detail}"

    finally:
        for server in servers:
            server.stop()
