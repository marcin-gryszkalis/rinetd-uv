import os
import random
import string
import socket
import time
import tempfile
import hashlib

def generate_random_data(size):
    """Generate random bytes of specified size."""
    return os.urandom(size)

def generate_random_string(length):
    """Generate a random string of fixed length."""
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))

def get_free_port():
    """Get a free port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
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
    """Receive exactly size bytes from a socket."""
    chunks = []
    bytes_recd = 0
    while bytes_recd < size:
        to_recv = min(size - bytes_recd, chunk_size)
        chunk = sock.recv(to_recv)
        if chunk == b'':
            raise RuntimeError("Socket connection broken")
        chunks.append(chunk)
        bytes_recd += len(chunk)
    return b''.join(chunks)

def send_streaming(sock, total_size, chunk_size=65536, seed=None):
    """Send total_size bytes in chunks. If seed is provided, use random data."""
    if seed is not None:
        stream = SeededRandomStream(seed, total_size)
        bytes_sent = 0
        while bytes_sent < total_size:
            data = stream.read(chunk_size)
            if not data:
                break
            sock.sendall(data)
            bytes_sent += len(data)
    else:
        pattern = b"0123456789abcdef" * (chunk_size // 16)
        bytes_sent = 0
        while bytes_sent < total_size:
            to_send = min(total_size - bytes_sent, chunk_size)
            sock.sendall(pattern[:to_send])
            bytes_sent += to_send

def verify_streaming(sock, total_size, chunk_size=65536, seed=None):
    """Receive and verify total_size bytes in chunks."""
    if seed is not None:
        stream = SeededRandomStream(seed, total_size)
        bytes_recd = 0
        while bytes_recd < total_size:
            expected = stream.read(chunk_size)
            if not expected:
                break
            data = recv_all(sock, len(expected), chunk_size=chunk_size)
            if data != expected:
                return False, f"Data mismatch at offset {bytes_recd}"
            bytes_recd += len(data)
    else:
        pattern = b"0123456789abcdef" * (chunk_size // 16)
        bytes_recd = 0
        while bytes_recd < total_size:
            to_recv = min(total_size - bytes_recd, chunk_size)
            data = recv_all(sock, to_recv, chunk_size=chunk_size)
            if data != pattern[:to_recv]:
                return False, f"Data mismatch at offset {bytes_recd}"
            bytes_recd += to_recv
    return True, None



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

def run_transfer(listen_proto, listen_addr, size, chunk_size, seed):
    """Run a single transfer and verify data integrity."""
    if listen_proto == "udp":
        data = generate_random_data(size)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(5)
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
        family = socket.AF_INET if isinstance(listen_addr, tuple) else socket.AF_UNIX
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            try:
                s.connect(listen_addr)
            except Exception as e:
                return False, f"Connect failed: {e}"
            
            import threading
            def sender():
                try:
                    send_streaming(s, size, chunk_size=chunk_size, seed=seed)
                except Exception:
                    pass
            
            t = threading.Thread(target=sender)
            t.start()
            
            success, msg = verify_streaming(s, size, chunk_size=chunk_size, seed=seed)
            t.join()
            return success, msg

def run_repeated_transfers(listen_proto, listen_addr, size, chunk_size, seed, duration):
    """Repeat transfers until duration is reached."""
    start_time = time.time()
    count = 0
    while time.time() - start_time < duration:
        success, msg = run_transfer(listen_proto, listen_addr, size, chunk_size, seed)
        if not success:
            return False, f"Transfer {count} failed: {msg}"
        count += 1
    return True, f"Completed {count} transfers"
