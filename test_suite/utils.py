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
import struct

DEFAULT_TIMEOUT = 120
BARRIER_TIMEOUT = 60

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

def run_transfer(listen_proto, listen_addr, size, chunk_size, seed, deadline=None, udp_sock=None):
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
        udp_sock: Optional pre-created UDP socket for reuse (avoids source port
                  randomization which would create new rinetd sessions)

    Returns:
        (success, message) tuple
    """
    # Check deadline before starting - if past, just return success
    if deadline and time.time() >= deadline:
        return True, "stopped at deadline"

    if listen_proto == "udp":
        data = generate_random_data(size)
        own_socket = udp_sock is None
        s = udp_sock if udp_sock else socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 128 * 1024)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 128 * 1024)

        try:
            if own_socket:
                s.settimeout(DEFAULT_TIMEOUT)
            sent_bytes = 0
            received_data = b""
            seq_num = 0

            while sent_bytes < size:
                to_send = min(size - sent_bytes, chunk_size)

                # Prepend 4-byte sequence number to each UDP packet
                # Format: [seq_num (4 bytes, little-endian)][payload (to_send bytes)]
                payload = data[sent_bytes:sent_bytes+to_send]
                packet = struct.pack('<I', seq_num) + payload

                try:
                    s.sendto(packet, listen_addr)
                except OSError as e:
                    return False, f"UDP send failed at offset {sent_bytes}: {e}"

                try:
                    echo_packet, _ = s.recvfrom(65535)
                except socket.timeout:
                    return False, f"UDP timeout waiting for echo at offset {sent_bytes}/{size}, seq {seq_num}"
                except OSError as e:
                    return False, f"UDP recv failed at offset {sent_bytes}: {e}"

                # Verify packet has sequence number (at least 4 bytes)
                if len(echo_packet) < 4:
                    return False, f"UDP echo packet too short at seq {seq_num}: got {len(echo_packet)} bytes, need at least 4"

                # Extract and verify sequence number
                recv_seq = struct.unpack('<I', echo_packet[:4])[0]
                if recv_seq != seq_num:
                    return False, f"UDP sequence mismatch at offset {sent_bytes}: expected seq {seq_num}, got {recv_seq}"

                # Extract payload and verify
                recv_payload = echo_packet[4:]
                if len(recv_payload) != to_send:
                    return False, f"UDP payload size mismatch at seq {seq_num}: expected {to_send} bytes, got {len(recv_payload)}"

                if recv_payload != payload:
                    # Show first differing byte for debugging
                    for i, (expected, actual) in enumerate(zip(payload, recv_payload)):
                        if expected != actual:
                            return False, f"UDP data mismatch at seq {seq_num}, byte {i}: expected 0x{expected:02x}, got 0x{actual:02x}"
                    return False, f"UDP data mismatch at seq {seq_num} (lengths differ)"

                received_data += recv_payload
                sent_bytes += to_send
                seq_num += 1

            if received_data != data:
                return False, f"UDP final data mismatch: got {len(received_data)} bytes, expected {len(data)}"
            return True, None
        finally:
            if own_socket:
                s.close()
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


def run_upload_sha256_transfer(listen_proto, listen_addr, size, chunk_size, seed, deadline=None, udp_sock=None):
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
        udp_sock: Optional pre-created UDP socket for reuse

    Returns:
        (success, message) tuple
    """
    if deadline and time.time() >= deadline:
        return True, "stopped at deadline"

    if listen_proto == "udp":
        # UDP: per-packet SHA256 verification (stateless protocol)
        own_socket = udp_sock is None
        s = udp_sock if udp_sock else socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 128 * 1024)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 128 * 1024)

        try:
            if own_socket:
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
                except OSError as e:
                    return False, f"Failed to send at offset {bytes_sent}: {e}"

                # Receive server's computed hash
                try:
                    response, _ = s.recvfrom(64)  # 32 bytes expected
                except socket.timeout:
                    return False, f"UDP timeout at offset {bytes_sent}/{size}"
                except OSError as e:
                    return False, f"UDP recv failed at offset {bytes_sent}: {e}"

                if len(response) < 32:
                    return False, f"Short response at offset {bytes_sent}: got {len(response)}, expected 32"

                server_hash = response[:32]

                # Verify server computed same hash (confirms data integrity)
                if server_hash != data_hash:
                    return False, f"Hash mismatch at offset {bytes_sent}"

                bytes_sent += len(data)

            return True, None
        finally:
            if own_socket:
                s.close()

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


def run_download_sha256_transfer(listen_proto, listen_addr, size, chunk_size, seed, deadline=None, udp_sock=None):
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
        udp_sock: Optional pre-created UDP socket for reuse

    Returns:
        (success, message) tuple
    """
    if deadline and time.time() >= deadline:
        return True, "stopped at deadline"

    if listen_proto == "udp":
        # UDP: per-packet SHA256 verification (stateless protocol)
        own_socket = udp_sock is None
        s = udp_sock if udp_sock else socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 128 * 1024)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 128 * 1024)

        try:
            if own_socket:
                s.settimeout(DEFAULT_TIMEOUT)
            bytes_received = 0

            while bytes_received < size:
                # Request this chunk: "<offset> <chunk_size> <seed>\n"
                to_recv = min(chunk_size, size - bytes_received)
                request = f"{bytes_received} {to_recv} {seed}\n".encode()
                try:
                    s.sendto(request, listen_addr)
                except OSError as e:
                    return False, f"Failed to send request at offset {bytes_received}: {e}"

                # Receive data + sha256 (chunk_size + 32 bytes)
                try:
                    response, _ = s.recvfrom(to_recv + 32 + 100)  # Extra buffer for safety
                except socket.timeout:
                    return False, f"UDP timeout at offset {bytes_received}/{size}"
                except OSError as e:
                    return False, f"UDP recv failed at offset {bytes_received}: {e}"

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
        finally:
            if own_socket:
                s.close()

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


def run_repeated_transfers_mode(listen_proto, listen_addr, size, chunk_size, seed, duration, mode="echo", barrier=None):
    """
    Repeat transfers until duration is reached, with specified transfer mode.

    For UDP: reuses a single socket across all transfers to maintain the same
    source port. This prevents rinetd from creating a new backend connection
    for each transfer (which would exhaust file descriptors).

    Args:
        mode: "echo", "upload", "download", "upload_sha256", or "download_sha256"
        barrier: Optional threading.Barrier - if provided, all threads wait at
                 the barrier after probe phase before starting high-volume transfers.
                 This ensures all paths are warmed up before load begins.
    """
    transfer_fn = {
        "echo": run_transfer,
        "upload": run_upload_transfer,
        "download": run_download_transfer,
        "upload_sha256": run_upload_sha256_transfer,
        "download_sha256": run_download_sha256_transfer,
    }.get(mode, run_transfer)

    # For UDP, create a shared socket to reuse across all transfers
    # (same source port = same rinetd connection = no FD exhaustion)
    udp_sock = None
    if listen_proto == "udp":
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.settimeout(DEFAULT_TIMEOUT)
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 128 * 1024)
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 128 * 1024)

        # Probe phase: send a small packet to warm up the connection path.
        # This ensures rinetd has created the UDP association and the backend
        # is ready before we send large data. Without this, the first large
        # packets from parallel clients can be lost due to timing issues.
        # Note: download_sha256 doesn't need probe (server sends after request).
        if mode != "download_sha256":
            max_probe_retries = 5
            for attempt in range(max_probe_retries):
                try:
                    if mode == "upload_sha256":
                        # upload_sha256 server expects <data><sha256_of_data>
                        probe_data = b"PROBE"
                        probe_hash = hashlib.sha256(probe_data).digest()
                        udp_sock.sendto(probe_data + probe_hash, listen_addr)
                        response, _ = udp_sock.recvfrom(64)
                        # Server responds with computed hash (32 bytes)
                        if len(response) == 32:
                            break  # Path is ready
                    else:
                        # echo mode: send data, expect same data back
                        probe_data = b"PROBE"
                        udp_sock.sendto(probe_data, listen_addr)
                        response, _ = udp_sock.recvfrom(64)
                        if response == probe_data:
                            break  # Path is ready
                except socket.timeout:
                    if attempt == max_probe_retries - 1:
                        return False, f"UDP probe failed: path not ready after {max_probe_retries} retries"
                    continue

    # Wait at barrier after probe phase - ensures all threads have warmed up
    # their connection paths before any thread starts high-volume transfers.
    # This prevents early threads from overwhelming the system while others
    # are still completing their probes.
    if barrier is not None:
        try:
            barrier.wait(timeout=BARRIER_TIMEOUT)
        except Exception as e:
            return False, f"Barrier wait failed: {e}"

    try:
        start_time = time.time()
        count = 0
        while time.time() - start_time < duration:
            if udp_sock:
                success, msg = transfer_fn(listen_proto, listen_addr, size, chunk_size, seed, udp_sock=udp_sock)
            else:
                success, msg = transfer_fn(listen_proto, listen_addr, size, chunk_size, seed)
            if not success:
                return False, f"Transfer {count} failed: {msg}"
            count += 1
        return True, f"Completed {count} transfers"
    finally:
        if udp_sock:
            udp_sock.close()


# =============================================================================
# Client-Server Pair Architecture
# =============================================================================
# Each pair consists of:
#   - A dedicated backend server
#   - A dedicated rinetd rule (listen port → server port)
#   - A client that transfers data through rinetd
#   - A barrier to synchronize server readiness with client start
#
# This eliminates server contention - each client has its own server.

from .servers import (
    TcpEchoServer, UdpEchoServer, UnixEchoServer,
    TcpUploadServer, TcpDownloadServer,
    TcpUploadSha256Server, TcpDownloadSha256Server,
    UdpUploadSha256Server, UdpDownloadSha256Server,
    UnixUploadServer, UnixDownloadServer,
    UnixUploadSha256Server, UnixDownloadSha256Server,
)


def create_backend_server(protocol, mode, socket_path=None, host='127.0.0.1', port=0):
    """
    Factory function to create the appropriate backend server.

    Args:
        protocol: "tcp", "udp", or "unix"
        mode: "echo", "upload", "download", "upload_sha256", or "download_sha256"
        socket_path: Required for unix protocol
        host: IP address to bind to for TCP/UDP (default: 127.0.0.1)
        port: Port to bind to for TCP/UDP (default: 0 for random)

    Returns:
        Server instance (not started)
    """
    server_map = {
        ("tcp", "echo"): TcpEchoServer,
        ("tcp", "upload"): TcpUploadServer,
        ("tcp", "download"): TcpDownloadServer,
        ("tcp", "upload_sha256"): TcpUploadSha256Server,
        ("tcp", "download_sha256"): TcpDownloadSha256Server,
        ("udp", "echo"): UdpEchoServer,
        ("udp", "upload_sha256"): UdpUploadSha256Server,
        ("udp", "download_sha256"): UdpDownloadSha256Server,
        ("unix", "echo"): UnixEchoServer,
        ("unix", "upload"): UnixUploadServer,
        ("unix", "download"): UnixDownloadServer,
        ("unix", "upload_sha256"): UnixUploadSha256Server,
        ("unix", "download_sha256"): UnixDownloadSha256Server,
    }

    key = (protocol, mode)
    if key not in server_map:
        raise ValueError(f"No server for protocol={protocol}, mode={mode}")

    server_class = server_map[key]

    if protocol == "unix":
        if not socket_path:
            raise ValueError("socket_path required for unix protocol")
        return server_class(socket_path)
    else:
        # TCP/UDP servers accept (host, port) - pass dedicated host IP and port
        return server_class(host=host, port=port)


def run_client_server_pair(listen_proto, connect_proto, mode, size, chunk_size,
                           seed, duration, tmp_path, pair_id,
                           servers_ready_barrier, rinetd_ready_barrier,
                           shared_rules, shared_listen_info):
    """
    Run a single client-server pair with two-phase barrier synchronization.

    This function:
    1. Creates and starts a dedicated backend server
    2. Stores rule in shared_rules (for main thread to start rinetd)
    3. Waits at servers_ready_barrier (syncs with main thread)
    4. Waits at rinetd_ready_barrier (syncs with main thread after rinetd is ready)
    5. Runs transfers for the specified duration
    6. Stops the server and returns results

    Args:
        listen_proto: Protocol for rinetd listener ("tcp", "udp", "unix")
        connect_proto: Protocol for backend connection ("tcp", "udp", "unix")
        mode: Transfer mode ("echo", "upload", "download", "upload_sha256", "download_sha256")
        size: Transfer size in bytes
        chunk_size: Chunk size for transfers
        seed: Random seed for data generation
        duration: How long to run transfers (seconds)
        tmp_path: Temporary directory for unix sockets
        pair_id: Unique identifier for this pair (for socket paths)
        servers_ready_barrier: Barrier to signal servers are ready (for main to start rinetd)
        rinetd_ready_barrier: Barrier to wait for rinetd to be ready (before starting transfers)
        shared_rules: List to store rinetd rule (shared with main thread)
        shared_listen_info: List to store (proto, port/path, ip) tuples (shared with main thread)

    Returns:
        dict with keys:
            - "success": bool
            - "message": str
            - "listen_port": int or None
            - "listen_path": str or None
            - "backend_port": int or None
            - "backend_path": str or None
            - "rinetd_rule": str
    """
    result = {
        "success": False,
        "message": "",
        "listen_port": None,
        "listen_path": None,
        "listen_ip": None,
        "backend_port": None,
        "backend_path": None,
        "backend_ip": None,
        "rinetd_rule": "",
    }

    server = None
    try:
        # Create backend server with fixed IP and port range
        if connect_proto == "unix":
            backend_path = str(tmp_path / f"backend_{pair_id}.sock")
            server = create_backend_server(connect_proto, mode, backend_path)
            result["backend_path"] = backend_path
        else:
            # Use 127.0.0.3 for backend servers with port = base + pair_id
            # This matches the rinetd listen port strategy (separate IP to avoid conflicts)
            backend_ip = "127.0.0.3"
            backend_port = 20000 + pair_id
            if backend_port > 65535:
                raise ValueError(f"pair_id {pair_id} exceeds port range (max 45535)")
            server = create_backend_server(connect_proto, mode, host=backend_ip, port=backend_port)
            result["backend_ip"] = backend_ip

        # Start server and wait for it to be ready
        server.start()
        if not server.wait_ready(timeout=10):
            result["message"] = "Backend server failed to start"
            return result

        # Get backend address
        if connect_proto == "unix":
            result["backend_path"] = server.path
        else:
            result["backend_port"] = server.actual_port

        # Allocate listen port/path
        if listen_proto == "unix":
            listen_path = str(tmp_path / f"listen_{pair_id}.sock")
            result["listen_path"] = listen_path
        else:
            # Use fixed IP with port range allocation
            # Linux allows 127.0.0.0/8, but FreeBSD requires explicit IP configuration
            # Use 127.0.0.2 for rinetd listen addresses with port = base + pair_id
            # Base port 20000 avoids conflicts with common services
            # Supports up to ~45,000 pairs (20000-65535)
            listen_ip = "127.0.0.2"
            listen_port = 20000 + pair_id
            if listen_port > 65535:
                raise ValueError(f"pair_id {pair_id} exceeds port range (max 45535)")
            result["listen_port"] = listen_port
            result["listen_ip"] = listen_ip

        # Build rinetd rule
        if listen_proto == "unix":
            listen_spec = f"unix:{result['listen_path']}"
        else:
            # Use dedicated IP address for this pair (eliminates port conflicts)
            listen_spec = f"{result['listen_ip']} {result['listen_port']}"
            if listen_proto == "udp":
                listen_spec += "/udp"

        if connect_proto == "unix":
            connect_spec = f"unix:{result['backend_path']}"
        else:
            # Use dedicated backend IP (eliminates port conflicts on backend side)
            connect_spec = f"{result['backend_ip']} {result['backend_port']}"
            if connect_proto == "udp":
                connect_spec += "/udp"

        result["rinetd_rule"] = f"{listen_spec} {connect_spec}"

        # Store rule and listen info in shared structures BEFORE barrier
        # Main thread needs these to start rinetd
        shared_rules[pair_id] = result["rinetd_rule"]
        shared_listen_info[pair_id] = (
            listen_proto,
            result["listen_port"] or result["listen_path"],
            result.get("listen_ip")  # IP address for TCP/UDP (None for unix)
        )

        # Phase 1: Signal that server is ready and rule is built
        # Main thread will collect rules and start rinetd after this barrier
        try:
            servers_ready_barrier.wait(timeout=BARRIER_TIMEOUT)
        except threading.BrokenBarrierError:
            result["message"] = "Servers ready barrier broken - another pair failed"
            return result

        # Phase 2: Wait for rinetd to be ready
        # Main thread will signal this after rinetd is started and ports are verified
        try:
            rinetd_ready_barrier.wait(timeout=BARRIER_TIMEOUT)
        except threading.BrokenBarrierError:
            result["message"] = "rinetd ready barrier broken - rinetd failed to start"
            return result

        # After second barrier: rinetd is confirmed running, start transfers
        if listen_proto == "unix":
            listen_addr = result["listen_path"]
        else:
            # Use the dedicated IP address allocated for this pair
            listen_addr = (result["listen_ip"], result["listen_port"])

        # Run transfers
        transfer_fn = {
            "echo": run_transfer,
            "upload": run_upload_transfer,
            "download": run_download_transfer,
            "upload_sha256": run_upload_sha256_transfer,
            "download_sha256": run_download_sha256_transfer,
        }.get(mode, run_transfer)

        # For UDP, create a socket to reuse
        udp_sock = None
        if listen_proto == "udp":
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.settimeout(DEFAULT_TIMEOUT)
            udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * 1024 * 1024)
            udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 * 1024 * 1024)

        try:
            start_time = time.time()
            count = 0
            while time.time() - start_time < duration:
                if udp_sock:
                    success, msg = transfer_fn(listen_proto, listen_addr, size, chunk_size, seed, udp_sock=udp_sock)
                else:
                    success, msg = transfer_fn(listen_proto, listen_addr, size, chunk_size, seed)
                if not success:
                    result["message"] = f"Transfer {count} failed: {msg}"
                    return result
                count += 1

            result["success"] = True
            result["message"] = f"Completed {count} transfers"
        finally:
            if udp_sock:
                udp_sock.close()

    except Exception as e:
        result["message"] = f"Exception: {e}"
    finally:
        if server:
            server.stop()

    return result


def run_parallel_pairs(pairs_config, rinetd_starter, duration, tmp_path):
    """
    Run multiple client-server pairs in parallel with two-phase synchronization.

    Flow:
        1. All pairs create their backend servers
        2. servers_ready_barrier: all servers ready → main thread starts rinetd
        3. Main thread starts rinetd and verifies it's ready
        4. rinetd_ready_barrier: rinetd ready → all pairs start transfers
        5. All pairs run transfers for duration
        6. Collect and return results

    Args:
        pairs_config: List of dicts, each with keys:
            - listen_proto, connect_proto, mode, size, chunk_size, seed
        rinetd_starter: Callable that takes list of rules and starts rinetd
        duration: How long to run transfers (seconds)
        tmp_path: Temporary directory for unix sockets

    Returns:
        List of result dicts from each pair
    """
    import concurrent.futures

    num_pairs = len(pairs_config)

    # Two-phase barriers: N pairs + 1 main thread
    servers_ready_barrier = threading.Barrier(num_pairs + 1)
    rinetd_ready_barrier = threading.Barrier(num_pairs + 1)

    results = [None] * num_pairs
    rules = [None] * num_pairs
    listen_info = [None] * num_pairs  # Store (proto, port/path, ip) for verification

    def run_pair_wrapper(pair_id, config):
        """Wrapper to run a pair and store results."""
        result = run_client_server_pair(
            listen_proto=config["listen_proto"],
            connect_proto=config["connect_proto"],
            mode=config["mode"],
            size=config["size"],
            chunk_size=config["chunk_size"],
            seed=config["seed"],
            duration=duration,
            tmp_path=tmp_path,
            pair_id=pair_id,
            servers_ready_barrier=servers_ready_barrier,
            rinetd_ready_barrier=rinetd_ready_barrier,
            shared_rules=rules,
            shared_listen_info=listen_info,
        )
        return result

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_pairs) as executor:
        # Submit all pairs
        futures = {
            executor.submit(run_pair_wrapper, i, config): i
            for i, config in enumerate(pairs_config)
        }

        # Phase 1: Wait for all servers to be ready
        try:
            servers_ready_barrier.wait(timeout=BARRIER_TIMEOUT)
        except threading.BrokenBarrierError:
            # Some pair failed during setup - abort
            rinetd_ready_barrier.abort()
            for future in futures:
                future.cancel()
            return [{"success": False, "message": "Setup failed"} for _ in range(num_pairs)]

        # Small grace period to ensure all servers have fully bound their ports
        # (especially important when starting many servers simultaneously)
        time.sleep(0.2)

        # Prepare and start rinetd
        valid_rules = [r for r in rules if r]
        if not valid_rules:
            rinetd_ready_barrier.abort()
            return [{"success": False, "message": "No valid rules"} for _ in range(num_pairs)]

        rinetd_starter(valid_rules)

        # Verify rinetd is ready by checking all listen ports/paths
        rinetd_ok = True
        for item in listen_info:
            if item is None:
                continue
            proto, addr, ip = item
            if addr is None:
                continue
            if proto == "tcp":
                # Use dedicated IP address for port check
                if not wait_for_port(addr, host=ip, timeout=10):
                    rinetd_ok = False
                    break
            elif proto == "unix":
                # Wait for unix socket to exist
                for _ in range(50):
                    if os.path.exists(addr):
                        break
                    time.sleep(0.1)
                else:
                    rinetd_ok = False
                    break
            else:
                # UDP - small delay (can't easily verify UDP is listening)
                time.sleep(0.3)

        if not rinetd_ok:
            rinetd_ready_barrier.abort()
            return [{"success": False, "message": "rinetd failed to start"} for _ in range(num_pairs)]

        # Phase 2: Signal that rinetd is ready - pairs can start transfers
        try:
            rinetd_ready_barrier.wait(timeout=BARRIER_TIMEOUT)
        except threading.BrokenBarrierError:
            return [{"success": False, "message": "rinetd ready barrier failed"} for _ in range(num_pairs)]

        # Collect results
        for future in concurrent.futures.as_completed(futures):
            pair_id = futures[future]
            try:
                results[pair_id] = future.result()
            except Exception as e:
                results[pair_id] = {"success": False, "message": f"Exception: {e}"}

    return results
