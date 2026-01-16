import os
import random
import string
import socket
import time
import tempfile
import hashlib
import math
import threading

def random_transfer_params(protocol, rng=None):
    """
    Generate random but sensible SIZE and CHUNK_SIZE for stress testing.
    Uses log-scale distribution to cover both small and large values.

    Args:
        protocol: 'tcp', 'udp', or 'unix'
        rng: random.Random instance for reproducibility (optional)

    Returns:
        (size, chunk_size) tuple
    """
    if rng is None:
        rng = random.Random()

    # Size: log-scale from 1 byte to 10MB (10^0 to 10^7)
    # This gives good coverage of edge cases (tiny) and stress cases (large)
    log_size = rng.uniform(0, 7)  # 1 byte to 10MB
    size = int(10 ** log_size)

    # Protocol-specific constraints
    if protocol == "udp":
        # UDP max payload is ~65507 bytes
        size = min(size, 65507)
        max_chunk = min(size, 65507)
    else:
        # TCP/Unix: reasonable chunk sizes
        max_chunk = min(size, 65536)

    # Chunk size: avoid pathological cases
    # - Minimum: at least 1, but prefer larger for big transfers
    # - Maximum: don't exceed size or protocol limit
    if size <= 16:
        # For tiny transfers, chunk_size = size (single chunk)
        chunk_size = size if size > 0 else 1
    else:
        # Log-scale chunk size, but constrained to avoid too many chunks
        # Aim for between 1 and 10000 chunks per transfer
        min_chunk = max(1, size // 10000)
        # For chunk size, use log-scale within the valid range
        if min_chunk < max_chunk:
            log_min = math.log10(max(1, min_chunk))
            log_max = math.log10(max(1, max_chunk))
            log_chunk = rng.uniform(log_min, log_max)
            chunk_size = int(10 ** log_chunk)
        else:
            chunk_size = min_chunk

    # Final safety clamps
    chunk_size = max(1, min(chunk_size, size if size > 0 else 1))

    # UDP with 1-byte chunks and large size is problematic - avoid it
    if protocol == "udp" and chunk_size == 1 and size > 1024:
        chunk_size = max(64, size // 1000)

    return size, chunk_size


def generate_random_data(size):
    """Generate random bytes of specified size."""
    return os.urandom(size)

def generate_random_string(length):
    """Generate a random string of fixed length."""
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))

def get_free_port():
    """
    Get a free port on localhost.
    Note: There's an inherent race condition between this function returning
    and the caller binding to the port. We use SO_REUSEADDR to mitigate this.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def wait_for_port(port, host='127.0.0.1', timeout=5.0):
    """Wait for a port to be open."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with socket.create_connection((host, port), timeout=0.1):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            time.sleep(0.1)
    return False

def calculate_checksum(data):
    """Calculate SHA256 checksum of data."""
    return hashlib.sha256(data).hexdigest()

def create_rinetd_conf(rules, filename=None, logfile=None):
    """
    Create a rinetd configuration file.
    rules: list of strings, each representing a line in the config.
    logfile: optional path to a log file.
    """
    if filename is None:
        fd, filename = tempfile.mkstemp(suffix='.conf', prefix='rinetd_test_')
        os.close(fd)
    
    with open(filename, 'w') as f:
        if logfile:
            f.write(f"logfile {logfile}\n")
        for rule in rules:
            f.write(f"{rule}\n")
            
    return filename

class SeededRandomStream:
    """A stream of pseudo-random bytes generated from a seed."""
    def __init__(self, seed, total_size):
        self.rng = random.Random(seed)
        self.total_size = total_size
        self.bytes_generated = 0

    def read(self, size):
        if self.bytes_generated >= self.total_size:
            return b""
        to_gen = min(size, self.total_size - self.bytes_generated)
        data = self.rng.randbytes(to_gen)
        self.bytes_generated += to_gen
        return data

def send_all(sock, data, chunk_size=None):
    """Send all data to a socket, optionally in chunks."""
    if chunk_size is None:
        sock.sendall(data)
    else:
        total_sent = 0
        while total_sent < len(data):
            to_send = min(len(data) - total_sent, chunk_size)
            sent = sock.send(data[total_sent:total_sent + to_send])
            if sent == 0:
                raise RuntimeError("Socket connection broken")
            total_sent += sent

def recv_all(sock, size, chunk_size=4096):
    """
    Receive exactly size bytes from a socket.
    Respects socket timeout settings. Raises RuntimeError on connection loss,
    socket.timeout on timeout.
    """
    chunks = []
    bytes_recd = 0
    while bytes_recd < size:
        to_recv = min(size - bytes_recd, chunk_size)
        try:
            chunk = sock.recv(to_recv)
        except socket.timeout:
            raise socket.timeout(f"Timed out after receiving {bytes_recd}/{size} bytes")
        if chunk == b'':
            raise RuntimeError(f"Socket connection broken after receiving {bytes_recd}/{size} bytes")
        chunks.append(chunk)
        bytes_recd += len(chunk)
    return b''.join(chunks)

def send_streaming(sock, total_size, chunk_size=65536, seed=None, deadline=None):
    """
    Send total_size bytes in chunks. If seed is provided, use random data.

    Args:
        sock: Socket to send on
        total_size: Total bytes to send
        chunk_size: Size of each chunk
        seed: Random seed for reproducible data (optional)
        deadline: time.time() value after which to stop gracefully (optional)

    Returns:
        bytes_sent: Number of bytes actually sent (may be < total_size if deadline hit)
    """
    if seed is not None:
        stream = SeededRandomStream(seed, total_size)
        bytes_sent = 0
        while bytes_sent < total_size:
            if deadline and time.time() >= deadline:
                return bytes_sent  # Graceful stop after current chunk
            data = stream.read(chunk_size)
            if not data:
                break
            sock.sendall(data)
            bytes_sent += len(data)
        return bytes_sent
    else:
        pattern = b"0123456789abcdef" * (chunk_size // 16)
        bytes_sent = 0
        while bytes_sent < total_size:
            if deadline and time.time() >= deadline:
                return bytes_sent  # Graceful stop after current chunk
            to_send = min(total_size - bytes_sent, chunk_size)
            sock.sendall(pattern[:to_send])
            bytes_sent += to_send
        return bytes_sent


def verify_streaming(sock, total_size, chunk_size=65536, seed=None, deadline=None):
    """
    Receive and verify total_size bytes in chunks.

    Args:
        sock: Socket to receive from
        total_size: Total bytes expected
        chunk_size: Size of each chunk
        seed: Random seed for reproducible verification (optional)
        deadline: time.time() value after which to stop gracefully (optional)

    Returns:
        (success, message, bytes_received) tuple
    """
    if seed is not None:
        stream = SeededRandomStream(seed, total_size)
        bytes_recd = 0
        while bytes_recd < total_size:
            if deadline and time.time() >= deadline:
                return True, "stopped at deadline", bytes_recd
            expected = stream.read(chunk_size)
            if not expected:
                break
            data = recv_all(sock, len(expected), chunk_size=chunk_size)
            if data != expected:
                return False, f"Data mismatch at offset {bytes_recd}", bytes_recd
            bytes_recd += len(data)
    else:
        pattern = b"0123456789abcdef" * (chunk_size // 16)
        bytes_recd = 0
        while bytes_recd < total_size:
            if deadline and time.time() >= deadline:
                return True, "stopped at deadline", bytes_recd
            to_recv = min(total_size - bytes_recd, chunk_size)
            data = recv_all(sock, to_recv, chunk_size=chunk_size)
            if data != pattern[:to_recv]:
                return False, f"Data mismatch at offset {bytes_recd}", bytes_recd
            bytes_recd += to_recv
    return True, None, bytes_recd



def recv_until_close(sock):
    """Receive data until the other end closes the connection."""
    chunks = []
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        except socket.timeout:
            break
        except OSError:
            break
    return b''.join(chunks)

def run_transfer(listen_proto, listen_addr, size, chunk_size, seed, deadline=None):
    """
    Run a single transfer and verify data integrity.

    Args:
        listen_proto: 'tcp', 'udp', or 'unix'
        listen_addr: Address tuple or Unix socket path
        size: Total bytes to transfer
        chunk_size: Size of each chunk
        seed: Random seed for data generation
        deadline: time.time() value after which to stop gracefully (optional)

    Returns:
        (success, message) tuple
    """
    if listen_proto == "udp":
        data = generate_random_data(size)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(5)
            sent_bytes = 0
            received_data = b""
            while sent_bytes < size:
                if deadline and time.time() >= deadline:
                    return True, "stopped at deadline"
                to_send = min(size - sent_bytes, chunk_size)
                s.sendto(data[sent_bytes:sent_bytes+to_send], listen_addr)
                try:
                    chunk, _ = s.recvfrom(65535)
                    received_data += chunk
                except socket.timeout:
                    return False, "UDP timeout"
                sent_bytes += to_send

            if received_data != data:
                return False, "UDP data mismatch"
            return True, None
    else:
        family = socket.AF_INET if isinstance(listen_addr, tuple) else socket.AF_UNIX
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            try:
                s.connect(listen_addr)
            except Exception as e:
                return False, f"Connect failed: {e}"

            sender_error = [None]
            sender_done = [False]

            def sender():
                try:
                    send_streaming(s, size, chunk_size=chunk_size, seed=seed, deadline=deadline)
                    sender_done[0] = True
                except Exception as e:
                    sender_error[0] = str(e)
                    try:
                        s.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass

            t = threading.Thread(target=sender)
            t.start()

            try:
                success, msg, _ = verify_streaming(s, size, chunk_size=chunk_size, seed=seed, deadline=deadline)
            except (RuntimeError, socket.timeout) as e:
                success, msg = False, str(e)

            t.join(timeout=5)

            if sender_error[0]:
                return False, f"Sender failed: {sender_error[0]}"
            return success, msg


def run_transfer_until_deadline(listen_proto, listen_addr, deadline, rng=None):
    """
    Run transfers with random parameters until deadline is reached.
    Stops gracefully after completing the current chunk (not whole transfer).

    Args:
        listen_proto: 'tcp', 'udp', or 'unix'
        listen_addr: Address tuple or Unix socket path
        deadline: time.time() value when to stop
        rng: random.Random instance for reproducibility (optional)

    Returns:
        (success, message, transfer_count) tuple
    """
    if rng is None:
        rng = random.Random()

    count = 0
    while time.time() < deadline:
        size, chunk_size = random_transfer_params(listen_proto, rng)
        seed = rng.randint(0, 2**32 - 1)

        success, msg = run_transfer(listen_proto, listen_addr, size, chunk_size, seed, deadline=deadline)

        if not success and msg != "stopped at deadline":
            return False, f"Transfer {count} failed: {msg}", count

        count += 1

        # Check deadline before starting next transfer
        if time.time() >= deadline:
            break

    return True, f"Completed {count} transfers", count


def run_repeated_transfers(listen_proto, listen_addr, size, chunk_size, seed, duration):
    """
    Repeat transfers until duration is reached.
    Note: This completes each full transfer before checking duration.
    For graceful stopping, use run_transfer_until_deadline instead.
    """
    start_time = time.time()
    count = 0
    while time.time() - start_time < duration:
        success, msg = run_transfer(listen_proto, listen_addr, size, chunk_size, seed)
        if not success:
            return False, f"Transfer {count} failed: {msg}"
        count += 1
    return True, f"Completed {count} transfers"
