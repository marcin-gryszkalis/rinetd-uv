import os
import random
import string
import socket
import time
import tempfile
import hashlib
import math
import threading
import resource

DEFAULT_TIMEOUT = 120

def get_file_limit():
    """
    Get the current file descriptor limit (soft limit).
    Returns (soft_limit, hard_limit) tuple.
    """
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        return soft, hard
    except (AttributeError, ValueError):
        # Windows or other systems without RLIMIT_NOFILE
        return 1024, 1024  # Assume conservative default


def try_increase_file_limit(target):
    """
    Try to increase the file descriptor limit to target.
    Returns the actual limit achieved (may be less than target).
    """
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        # Can only increase soft limit up to hard limit without root
        new_soft = min(target, hard)
        if new_soft > soft:
            resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft, hard))
            return new_soft
        return soft
    except (AttributeError, ValueError, OSError):
        return get_file_limit()[0]


def get_max_concurrent_connections(num_clients, protocols_count=4, safety_margin=100):
    """
    Calculate if we have enough file descriptors for a stress test.

    Each connection consumes approximately:
    - 1 FD for client socket
    - 2 FDs for rinetd (client + backend)
    - 1 FD for backend server per-connection (if using threading model)

    Plus base FDs for: stdin, stdout, stderr, server listeners, etc.

    Args:
        num_clients: Number of concurrent client threads
        protocols_count: Number of different protocol combinations
        safety_margin: Extra FDs to keep available

    Returns:
        (can_run, max_clients, reason) tuple
    """
    soft_limit, hard_limit = get_file_limit()

    # Try to increase limit if needed
    estimated_fds = num_clients * 4 + protocols_count * 2 + safety_margin + 50
    if estimated_fds > soft_limit:
        new_limit = try_increase_file_limit(estimated_fds)
        soft_limit = new_limit

    # Base FDs: stdin/stdout/stderr + listeners + misc
    base_fds = 50 + protocols_count * 2

    # Available for connections
    available = soft_limit - base_fds - safety_margin

    # Each concurrent connection needs ~4 FDs
    max_clients = available // 4

    if max_clients >= num_clients:
        return True, num_clients, None
    elif max_clients > 10:
        return True, max_clients, f"Reduced from {num_clients} to {max_clients} due to ulimit -n ({soft_limit})"
    else:
        return False, 0, f"ulimit -n too low ({soft_limit}), need at least {base_fds + safety_margin + 40} for minimal test"


def random_transfer_params(protocol, rng=None, max_size=10*1024*1024):
    """
    Generate random but sensible SIZE and CHUNK_SIZE for stress testing.
    Uses log-scale distribution to cover both small and large values.

    Args:
        protocol: 'tcp', 'udp', or 'unix'
        rng: random.Random instance for reproducibility (optional)
        max_size: Maximum transfer size in bytes (default 1MB for stress tests)

    Returns:
        (size, chunk_size) tuple
    """
    if rng is None:
        rng = random.Random()

    # Size: log-scale from 1 byte up to max_size
    # This gives good coverage of edge cases (tiny) and stress cases (large)
    log_max = math.log10(max(1, max_size))
    log_size = rng.uniform(0, log_max)
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

def ipv6_available():
    """
    Check if IPv6 loopback (::1) is available on this system.
    Returns True if IPv6 can be used, False otherwise.
    """
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('::1', 0))
            return True
    except (OSError, socket.error):
        return False


def get_free_port(ipv6=False):
    """
    Get a free port on localhost.
    Note: There's an inherent race condition between this function returning
    and the caller binding to the port. We use SO_REUSEADDR to mitigate this.

    Args:
        ipv6: If True, get a port on IPv6 loopback (::1)
    """
    if ipv6:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('::1', 0))
            return s.getsockname()[1]
    else:
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
    """
    A stream of pseudo-random bytes generated from a seed.

    IMPORTANT: Uses a chunk-aligned generation approach to ensure that
    read() calls of any size produce the same bytes at the same offsets.
    This is critical for verification - the sender may write in one chunk
    size, but TCP recv() may return different sized chunks.
    """
    INTERNAL_CHUNK_SIZE = 4096  # Internal generation chunk size

    def __init__(self, seed, total_size):
        self.seed = seed
        self.total_size = total_size
        self.bytes_generated = 0
        self._cache = b""
        self._cache_offset = 0  # Offset where cache starts

    def _generate_chunk(self, chunk_index):
        """Generate a specific chunk using deterministic seeding."""
        # Use chunk_index + seed to create deterministic bytes for each chunk
        chunk_rng = random.Random(self.seed ^ (chunk_index * 0x9e3779b9))
        chunk_start = chunk_index * self.INTERNAL_CHUNK_SIZE
        chunk_end = min(chunk_start + self.INTERNAL_CHUNK_SIZE, self.total_size)
        return chunk_rng.randbytes(chunk_end - chunk_start)

    def read(self, size):
        if self.bytes_generated >= self.total_size:
            return b""

        to_gen = min(size, self.total_size - self.bytes_generated)
        result = bytearray()

        while len(result) < to_gen:
            # Check if we need data beyond our cache
            needed_offset = self.bytes_generated + len(result)

            if (self._cache and
                needed_offset >= self._cache_offset and
                needed_offset < self._cache_offset + len(self._cache)):
                # Can serve from cache
                cache_pos = needed_offset - self._cache_offset
                available = len(self._cache) - cache_pos
                take = min(available, to_gen - len(result))
                result.extend(self._cache[cache_pos:cache_pos + take])
            else:
                # Generate new chunk and cache it
                chunk_index = needed_offset // self.INTERNAL_CHUNK_SIZE
                self._cache = self._generate_chunk(chunk_index)
                self._cache_offset = chunk_index * self.INTERNAL_CHUNK_SIZE
                # Continue loop to serve from the new cache

        self.bytes_generated += len(result)
        return bytes(result)

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

    NOTE: The deadline parameter is only checked BEFORE starting a transfer.
    Once a transfer starts, it completes fully. This ensures data integrity
    and proper connection cleanup.

    Args:
        listen_proto: 'tcp', 'udp', or 'unix'
        listen_addr: Address tuple or Unix socket path
        size: Total bytes to transfer
        chunk_size: Size of each chunk
        seed: Random seed for data generation
        deadline: time.time() value - if reached, return immediately without transfer

    Returns:
        (success, message) tuple
    """
    # Check deadline before starting - if past, just return success
    if deadline and time.time() >= deadline:
        return True, "stopped at deadline"

    if listen_proto == "udp":
        data = generate_random_data(size)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(DEFAULT_TIMEOUT)
            sent_bytes = 0
            received_data = b""
            while sent_bytes < size:
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
        # TCP/Unix: simple sequential send-then-receive (no threads needed)
        family = socket.AF_INET if isinstance(listen_addr, tuple) else socket.AF_UNIX
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(DEFAULT_TIMEOUT)
            try:
                s.connect(listen_addr)
            except Exception as e:
                return False, f"Connect failed: {e}"

            # Generate and send data
            stream = SeededRandomStream(seed, size)
            bytes_sent = 0
            while bytes_sent < size:
                chunk = stream.read(chunk_size)
                if not chunk:
                    break
                try:
                    s.sendall(chunk)
                    bytes_sent += len(chunk)
                except Exception as e:
                    return False, f"Send failed after {bytes_sent} bytes: {e}"

            # Receive and verify - use same seed for verification
            verify_stream = SeededRandomStream(seed, size)
            bytes_received = 0
            while bytes_received < size:
                try:
                    chunk = s.recv(chunk_size)
                except socket.timeout:
                    return False, f"Receive timeout after {bytes_received}/{size} bytes"
                if not chunk:
                    return False, f"Connection closed after {bytes_received}/{size} bytes"

                expected = verify_stream.read(len(chunk))
                if chunk != expected:
                    return False, f"Data mismatch at offset {bytes_received}"
                bytes_received += len(chunk)

            return True, None


def run_transfer_until_deadline(listen_proto, listen_addr, deadline, rng=None):
    """
    Run transfers with random parameters until deadline is reached.

    Graceful shutdown behavior:
    - Checks deadline BEFORE starting each new transfer
    - Once a transfer starts, it completes fully (no mid-transfer abort)
    - This ensures data integrity and proper connection cleanup

    Args:
        listen_proto: 'tcp', 'udp', or 'unix'
        listen_addr: Address tuple or Unix socket path
        deadline: time.time() value when to stop starting new transfers
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

        # Pass deadline so run_transfer can check it before starting
        # If past deadline, run_transfer returns immediately with "stopped at deadline"
        success, msg = run_transfer(listen_proto, listen_addr, size, chunk_size, seed, deadline=deadline)

        if msg == "stopped at deadline":
            # Deadline was reached, exit gracefully
            break

        if not success:
            return False, f"Transfer {count} failed: {msg}", count

        count += 1

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


def run_upload_transfer(listen_proto, listen_addr, size, chunk_size, seed, deadline=None):
    """
    Run an upload-only transfer: send data, verify server received correct byte count.

    Protocol (proxy-friendly):
    - Client sends: "<size>\n" followed by exactly <size> bytes
    - Server responds: "<received_bytes>\n"

    Args:
        listen_proto: 'tcp' or 'unix' (UDP not supported for upload mode)
        listen_addr: Address tuple or Unix socket path
        size: Total bytes to upload
        chunk_size: Size of each chunk
        seed: Random seed for data generation
        deadline: time.time() value - if reached, return immediately

    Returns:
        (success, message) tuple
    """
    if deadline and time.time() >= deadline:
        return True, "stopped at deadline"

    if listen_proto == "udp":
        return False, "UDP not supported for upload mode"

    family = socket.AF_INET if isinstance(listen_addr, tuple) else socket.AF_UNIX
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.settimeout(DEFAULT_TIMEOUT)
        try:
            s.connect(listen_addr)
        except Exception as e:
            return False, f"Connect failed: {e}"

        # Send size header
        header = f"{size}\n".encode()
        try:
            s.sendall(header)
        except Exception as e:
            return False, f"Failed to send header: {e}"

        # Send data
        stream = SeededRandomStream(seed, size)
        bytes_sent = 0
        while bytes_sent < size:
            chunk = stream.read(chunk_size)
            if not chunk:
                break
            try:
                s.sendall(chunk)
                bytes_sent += len(chunk)
            except Exception as e:
                return False, f"Send failed after {bytes_sent} bytes: {e}"

        # Receive byte count response
        try:
            response = b""
            while b"\n" not in response:
                chunk = s.recv(1024)
                if not chunk:
                    break
                response += chunk

            received_count = int(response.strip())
            if received_count != size:
                return False, f"Server received {received_count} bytes, expected {size}"
            return True, None

        except Exception as e:
            return False, f"Failed to receive byte count: {e}"


def run_download_transfer(listen_proto, listen_addr, size, chunk_size, seed, deadline=None):
    """
    Run a download-only transfer: request data from server, verify received data.

    Protocol:
    - Client sends: "<size> <seed>\n"
    - Server responds with <size> bytes of seeded random data

    Args:
        listen_proto: 'tcp' or 'unix' (UDP not supported for download mode)
        listen_addr: Address tuple or Unix socket path
        size: Total bytes to download
        chunk_size: Size of each chunk (for receiving)
        seed: Random seed for data verification
        deadline: time.time() value - if reached, return immediately

    Returns:
        (success, message) tuple
    """
    if deadline and time.time() >= deadline:
        return True, "stopped at deadline"

    if listen_proto == "udp":
        return False, "UDP not supported for download mode"

    family = socket.AF_INET if isinstance(listen_addr, tuple) else socket.AF_UNIX
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.settimeout(DEFAULT_TIMEOUT)
        try:
            s.connect(listen_addr)
        except Exception as e:
            return False, f"Connect failed: {e}"

        # Send request: "<size> <seed>\n"
        request = f"{size} {seed}\n".encode()
        try:
            s.sendall(request)
        except Exception as e:
            return False, f"Failed to send request: {e}"

        # Receive and verify data
        # Server uses random.Random(seed).randbytes(size) all at once
        # We must pre-generate to match (randbytes behavior differs for small vs large calls)
        rng = random.Random(seed)
        expected_data = rng.randbytes(size)
        bytes_received = 0

        while bytes_received < size:
            try:
                chunk = s.recv(chunk_size)
            except socket.timeout:
                return False, f"Receive timeout after {bytes_received}/{size} bytes"
            if not chunk:
                return False, f"Connection closed after {bytes_received}/{size} bytes"

            expected = expected_data[bytes_received:bytes_received + len(chunk)]
            if chunk != expected:
                return False, f"Data mismatch at offset {bytes_received}"
            bytes_received += len(chunk)

        return True, None


def run_upload_sha256_transfer(listen_proto, listen_addr, size, chunk_size, seed, deadline=None):
    """
    Run an upload transfer with SHA256 verification.

    For TCP/Unix (rolling hash):
    - Client sends: "<size>\n" followed by exactly <size> bytes
    - Server buffers data, and after each HASH_CHUNK_SIZE bytes, sends back rolling SHA256 (32 bytes)
    - At end, server sends final hash of any remaining data

    For UDP (per-packet hash):
    - Client sends: <data><sha256_of_data> (chunk_size + 32 bytes)
    - Server verifies hash, responds: <computed_sha256> (32 bytes)
    - Client confirms response matches what it sent

    Args:
        listen_proto: 'tcp', 'unix', or 'udp'
        listen_addr: Address tuple or Unix socket path
        size: Total bytes to upload
        chunk_size: Size of each send chunk
        seed: Random seed for data generation
        deadline: time.time() value - if reached, return immediately

    Returns:
        (success, message) tuple
    """
    if deadline and time.time() >= deadline:
        return True, "stopped at deadline"

    if listen_proto == "udp":
        # UDP: per-packet SHA256 verification (stateless protocol)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(DEFAULT_TIMEOUT)

            stream = SeededRandomStream(seed, size)
            bytes_sent = 0

            while bytes_sent < size:
                to_send = min(chunk_size, size - bytes_sent)
                data = stream.read(to_send)

                # Compute hash of this chunk
                data_hash = hashlib.sha256(data).digest()

                # Send data + hash as single packet
                try:
                    s.sendto(data + data_hash, listen_addr)
                except Exception as e:
                    return False, f"Failed to send at offset {bytes_sent}: {e}"

                # Receive server's computed hash
                try:
                    response, _ = s.recvfrom(64)  # 32 bytes expected
                except socket.timeout:
                    return False, f"UDP timeout at offset {bytes_sent}"

                if len(response) < 32:
                    return False, f"Short response at offset {bytes_sent}: got {len(response)}, expected 32"

                server_hash = response[:32]

                # Verify server computed same hash (confirms data integrity)
                if server_hash != data_hash:
                    return False, f"Hash mismatch at offset {bytes_sent}"

                bytes_sent += len(data)

            return True, None

    # TCP/Unix: rolling hash protocol
    HASH_CHUNK_SIZE = 65536  # Server's fixed hash boundary size

    family = socket.AF_INET if isinstance(listen_addr, tuple) else socket.AF_UNIX
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.settimeout(DEFAULT_TIMEOUT)
        try:
            s.connect(listen_addr)
        except Exception as e:
            return False, f"Connect failed: {e}"

        # Send size header first
        header = f"{size}\n".encode()
        try:
            s.sendall(header)
        except Exception as e:
            return False, f"Failed to send header: {e}"

        # Send all data (using test's chunk_size for send operations)
        stream = SeededRandomStream(seed, size)
        bytes_sent = 0
        while bytes_sent < size:
            chunk = stream.read(chunk_size)
            if not chunk:
                break
            try:
                s.sendall(chunk)
                bytes_sent += len(chunk)
            except Exception as e:
                return False, f"Send failed after {bytes_sent} bytes: {e}"

        # Now receive and verify rolling hashes
        # Server sends 32-byte SHA256 after each HASH_CHUNK_SIZE bytes processed
        verify_stream = SeededRandomStream(seed, size)
        hasher = hashlib.sha256()
        bytes_hashed = 0
        expected_hashes = []

        # Calculate expected hashes using server's fixed hash boundary
        while bytes_hashed < size:
            to_hash = min(HASH_CHUNK_SIZE, size - bytes_hashed)
            chunk_data = verify_stream.read(to_hash)
            hasher.update(chunk_data)
            bytes_hashed += to_hash
            # Server sends hash after each HASH_CHUNK_SIZE boundary, or at end
            if bytes_hashed % HASH_CHUNK_SIZE == 0 or bytes_hashed == size:
                expected_hashes.append(hasher.digest())

        # Receive hashes from server
        for i, expected_hash in enumerate(expected_hashes):
            try:
                received_hash = recv_all(s, 32)
            except Exception as e:
                return False, f"Failed to receive hash {i}: {e}"

            if received_hash != expected_hash:
                return False, f"Hash mismatch at chunk {i}: expected {expected_hash.hex()}, got {received_hash.hex()}"

        return True, None


def run_download_sha256_transfer(listen_proto, listen_addr, size, chunk_size, seed, deadline=None):
    """
    Run a download transfer with SHA256 verification.

    For TCP/Unix (rolling hash):
    - Client sends: "<size> <seed> <chunk_size>\n"
    - Server sends data in chunks using random.Random(seed).randbytes()
    - After each chunk, client sends back rolling SHA256 (32 bytes)
    - Server verifies the hash

    For UDP (per-packet hash):
    - Client sends: "<offset> <chunk_size> <seed>\n" per request
    - Server responds: <data><sha256_of_data> (chunk_size + 32 bytes)
    - Each packet is self-contained with its own SHA256

    Args:
        listen_proto: 'tcp', 'unix', or 'udp'
        listen_addr: Address tuple or Unix socket path
        size: Total bytes to download
        chunk_size: Size of each chunk
        seed: Random seed for data verification
        deadline: time.time() value - if reached, return immediately

    Returns:
        (success, message) tuple
    """
    if deadline and time.time() >= deadline:
        return True, "stopped at deadline"

    if listen_proto == "udp":
        # UDP: per-packet SHA256 verification (stateless protocol)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(DEFAULT_TIMEOUT)
            bytes_received = 0

            while bytes_received < size:
                # Request this chunk: "<offset> <chunk_size> <seed>\n"
                to_recv = min(chunk_size, size - bytes_received)
                request = f"{bytes_received} {to_recv} {seed}\n".encode()
                try:
                    s.sendto(request, listen_addr)
                except Exception as e:
                    return False, f"Failed to send request at offset {bytes_received}: {e}"

                # Receive data + sha256 (chunk_size + 32 bytes)
                try:
                    response, _ = s.recvfrom(to_recv + 32 + 100)  # Extra buffer for safety
                except socket.timeout:
                    return False, f"UDP timeout at offset {bytes_received}"

                if len(response) < to_recv + 32:
                    return False, f"Short response at offset {bytes_received}: got {len(response)}, expected {to_recv + 32}"

                data = response[:to_recv]
                received_hash = response[to_recv:to_recv + 32]

                # Generate expected data using same algorithm as server
                chunk_rng = random.Random(seed ^ (bytes_received * 0x9e3779b9))
                expected_data = chunk_rng.randbytes(to_recv)

                if data != expected_data:
                    return False, f"Data mismatch at offset {bytes_received}"

                # Verify SHA256
                expected_hash = hashlib.sha256(data).digest()
                if received_hash != expected_hash:
                    return False, f"Hash mismatch at offset {bytes_received}"

                bytes_received += len(data)

            return True, None

    # TCP/Unix: rolling hash protocol
    family = socket.AF_INET if isinstance(listen_addr, tuple) else socket.AF_UNIX
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.settimeout(DEFAULT_TIMEOUT)
        try:
            s.connect(listen_addr)
        except Exception as e:
            return False, f"Connect failed: {e}"

        # Send request: "<size> <seed> <chunk_size>\n"
        request = f"{size} {seed} {chunk_size}\n".encode()
        try:
            s.sendall(request)
        except Exception as e:
            return False, f"Failed to send request: {e}"

        # Server uses simple random.Random(seed).randbytes() - must match exactly
        rng = random.Random(seed)
        hasher = hashlib.sha256()
        bytes_received = 0

        while bytes_received < size:
            to_recv = min(chunk_size, size - bytes_received)
            try:
                data = recv_all(s, to_recv)
            except socket.timeout:
                return False, f"Receive timeout after {bytes_received}/{size} bytes"
            except Exception as e:
                return False, f"Receive failed after {bytes_received}/{size} bytes: {e}"

            # Verify data matches expected (using same RNG as server)
            expected = rng.randbytes(len(data))
            if data != expected:
                return False, f"Data mismatch at offset {bytes_received}"

            bytes_received += len(data)

            # Update hash and send to server
            hasher.update(data)
            try:
                s.sendall(hasher.digest())
            except Exception as e:
                return False, f"Failed to send hash after {bytes_received} bytes: {e}"

        return True, None


def run_repeated_transfers_mode(listen_proto, listen_addr, size, chunk_size, seed, duration, mode="echo"):
    """
    Repeat transfers until duration is reached, with specified transfer mode.

    Args:
        mode: "echo", "upload", "download", "upload_sha256", or "download_sha256"
    """
    transfer_fn = {
        "echo": run_transfer,
        "upload": run_upload_transfer,
        "download": run_download_transfer,
        "upload_sha256": run_upload_sha256_transfer,
        "download_sha256": run_download_sha256_transfer,
    }.get(mode, run_transfer)

    start_time = time.time()
    count = 0
    while time.time() - start_time < duration:
        success, msg = transfer_fn(listen_proto, listen_addr, size, chunk_size, seed)
        if not success:
            return False, f"Transfer {count} failed: {msg}"
        count += 1
    return True, f"Completed {count} transfers"
