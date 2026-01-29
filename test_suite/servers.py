import socket
import threading
import os
import sys
import time
import select
import hashlib
import random
from enum import Enum

BACKLOG = 512

class TransferMode(Enum):
    """Transfer modes for testing different data flow patterns."""
    ECHO = "echo"                    # Client sends, server echoes back
    UPLOAD_ONLY = "upload_only"      # Client sends, server discards (returns byte count)
    DOWNLOAD_ONLY = "download_only"  # Server generates data, client receives
    UPLOAD_SHA256 = "upload_sha256"  # Client sends, server returns rolling SHA256
    DOWNLOAD_SHA256 = "download_sha256"  # Server sends, client returns rolling SHA256

class BaseEchoServer(threading.Thread):
    def __init__(self, address):
        super().__init__()
        self.address = address
        self.running = True
        self.ready = threading.Event()
        self.sock = None
        self.daemon = True

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        self.join(timeout=2)

    def wait_ready(self, timeout=5):
        return self.ready.wait(timeout)

class TcpEchoServer(BaseEchoServer):
    def __init__(self, host='127.0.0.1', port=0):
        super().__init__((host, port))
        self.host = host
        self.port = port
        self.actual_port = 0

    def run(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.actual_port = self.sock.getsockname()[1]
            self.sock.listen(BACKLOG)
            self.ready.set()

            while self.running:
                try:
                    r, _, _ = select.select([self.sock], [], [], 0.5)
                    if not r:
                        continue

                    conn, addr = self.sock.accept()
                    client_thread = threading.Thread(target=self.handle_client, args=(conn,))
                    client_thread.daemon = True
                    client_thread.start()
                except OSError:
                    break
        except Exception as e:
            print(f"TcpEchoServer error: {e}", file=sys.stderr)
        finally:
            if self.sock:
                self.sock.close()

    def handle_client(self, conn):
        # Don't check self.running here - let in-flight transfers complete
        # The handler runs until the CLIENT closes the connection
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                conn.sendall(data)
        except (OSError, ConnectionError, BrokenPipeError):
            pass  # Expected when client disconnects
        finally:
            conn.close()

class TcpEchoServerIPv6(BaseEchoServer):
    """IPv6 TCP echo server."""
    def __init__(self, host='::1', port=0):
        super().__init__((host, port))
        self.host = host
        self.port = port
        self.actual_port = 0

    def run(self):
        try:
            self.sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.actual_port = self.sock.getsockname()[1]
            self.sock.listen(BACKLOG)
            self.ready.set()

            while self.running:
                try:
                    r, _, _ = select.select([self.sock], [], [], 0.5)
                    if not r:
                        continue

                    conn, addr = self.sock.accept()
                    client_thread = threading.Thread(target=self.handle_client, args=(conn,))
                    client_thread.daemon = True
                    client_thread.start()
                except OSError:
                    break
        except Exception as e:
            print(f"TcpEchoServerIPv6 error: {e}", file=sys.stderr)
        finally:
            if self.sock:
                self.sock.close()

    def handle_client(self, conn):
        # Don't check self.running here - let in-flight transfers complete
        # The handler runs until the CLIENT closes the connection
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                conn.sendall(data)
        except (OSError, ConnectionError, BrokenPipeError):
            pass  # Expected when client disconnects
        finally:
            conn.close()


class UdpEchoServer(BaseEchoServer):
    def __init__(self, host='127.0.0.1', port=0):
        super().__init__((host, port))
        self.host = host
        self.port = port
        self.actual_port = 0

    def run(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Large buffers to handle burst of parallel clients sending 64KB each
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * 1024 * 1024)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 * 1024 * 1024)
            self.sock.bind((self.host, self.port))
            self.actual_port = self.sock.getsockname()[1]
            self.ready.set()

            while self.running:
                try:
                    r, _, _ = select.select([self.sock], [], [], 0.5)
                    if not r:
                        continue

                    data, addr = self.sock.recvfrom(65535)
                    self.sock.sendto(data, addr)
                except OSError:
                    break
        except Exception as e:
            print(f"UdpEchoServer error: {e}", file=sys.stderr)
        finally:
            if self.sock:
                self.sock.close()

class UnixEchoServer(BaseEchoServer):
    def __init__(self, path):
        super().__init__(path)
        self.path = path

    def run(self):
        if os.path.exists(self.path):
            os.unlink(self.path)

        try:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.bind(self.path)
            self.sock.listen(BACKLOG)
            self.ready.set()

            while self.running:
                try:
                    r, _, _ = select.select([self.sock], [], [], 0.5)
                    if not r:
                        continue

                    conn, addr = self.sock.accept()
                    client_thread = threading.Thread(target=self.handle_client, args=(conn,))
                    client_thread.daemon = True
                    client_thread.start()
                except OSError:
                    break
        except Exception as e:
            print(f"UnixEchoServer error: {e}", file=sys.stderr)
        finally:
            if self.sock:
                self.sock.close()
            if os.path.exists(self.path):
                try:
                    os.unlink(self.path)
                except OSError:
                    pass

    def handle_client(self, conn):
        # Don't check self.running here - let in-flight transfers complete
        # The handler runs until the CLIENT closes the connection
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                conn.sendall(data)
        except (OSError, ConnectionError, BrokenPipeError):
            pass  # Expected when client disconnects
        finally:
            conn.close()


# === Alternative Transfer Mode Servers ===

class TcpUploadServer(BaseEchoServer):
    """
    Server that accepts data uploads and discards them.
    Protocol (proxy-friendly, no half-close needed):
    - Client sends: "<size>\n" followed by exactly <size> bytes
    - Server responds: "<received_bytes>\n"
    """
    def __init__(self, host='127.0.0.1', port=0):
        super().__init__((host, port))
        self.host = host
        self.port = port
        self.actual_port = 0

    def run(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.actual_port = self.sock.getsockname()[1]
            self.sock.listen(BACKLOG)
            self.ready.set()

            while self.running:
                try:
                    r, _, _ = select.select([self.sock], [], [], 0.5)
                    if not r:
                        continue
                    conn, addr = self.sock.accept()
                    client_thread = threading.Thread(target=self.handle_upload, args=(conn,))
                    client_thread.daemon = True
                    client_thread.start()
                except OSError:
                    break
        except Exception as e:
            print(f"TcpUploadServer error: {e}", file=sys.stderr)
        finally:
            if self.sock:
                self.sock.close()

    def handle_upload(self, conn):
        """Receive specified amount of data, return byte count."""
        try:
            # Read the size header: "<size>\n"
            header = b""
            while b"\n" not in header and len(header) < 100:
                chunk = conn.recv(100)
                if not chunk:
                    return
                header += chunk

            line = header.split(b"\n")[0].decode().strip()
            expected_size = int(line)

            # Calculate how much of the data was already read with the header
            extra_data = header[header.index(b"\n") + 1:]
            total_bytes = len(extra_data)

            # Read remaining data
            remaining = expected_size - total_bytes
            while remaining > 0:
                chunk = conn.recv(min(65536, remaining))
                if not chunk:
                    break
                total_bytes += len(chunk)
                remaining -= len(chunk)

            # Send response
            conn.sendall(f"{total_bytes}\n".encode())

        except (OSError, ConnectionError, BrokenPipeError, ValueError):
            pass
        finally:
            conn.close()


class TcpDownloadServer(BaseEchoServer):
    """
    Server that generates and sends data to clients.
    Client sends: "<size> <seed>\\n" to request data.
    Server responds with <size> bytes of seeded random data.
    """
    def __init__(self, host='127.0.0.1', port=0):
        super().__init__((host, port))
        self.host = host
        self.port = port
        self.actual_port = 0

    def run(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.actual_port = self.sock.getsockname()[1]
            self.sock.listen(BACKLOG)
            self.ready.set()

            while self.running:
                try:
                    r, _, _ = select.select([self.sock], [], [], 0.5)
                    if not r:
                        continue
                    conn, addr = self.sock.accept()
                    client_thread = threading.Thread(target=self.handle_download, args=(conn,))
                    client_thread.daemon = True
                    client_thread.start()
                except OSError:
                    break
        except Exception as e:
            print(f"TcpDownloadServer error: {e}", file=sys.stderr)
        finally:
            if self.sock:
                self.sock.close()

    def handle_download(self, conn):
        """Read request, generate and send data."""
        try:
            request = b""
            while b"\n" not in request and len(request) < 100:
                chunk = conn.recv(100)
                if not chunk:
                    return
                request += chunk

            line = request.split(b"\n")[0].decode().strip()
            parts = line.split()
            if len(parts) != 2:
                return

            size = int(parts[0])
            seed = int(parts[1])

            rng = random.Random(seed)
            chunk_size = 65536
            bytes_sent = 0

            # Don't check self.running - let in-flight transfers complete
            while bytes_sent < size:
                to_send = min(chunk_size, size - bytes_sent)
                data = rng.randbytes(to_send)
                conn.sendall(data)
                bytes_sent += len(data)

        except (OSError, ConnectionError, BrokenPipeError, ValueError):
            pass
        finally:
            conn.close()


class TcpUploadSha256Server(BaseEchoServer):
    """
    Server that accepts uploads and returns rolling SHA256 after each chunk.
    Protocol (proxy-friendly, length-prefixed):
    - Client sends: "<size>\n" followed by exactly <size> bytes
    - Server buffers data, after each chunk_size bytes sends back rolling SHA256 (32 bytes)
    - After all data received, sends final SHA256 for any remaining bytes
    """
    def __init__(self, host='127.0.0.1', port=0, chunk_size=65536):
        super().__init__((host, port))
        self.host = host
        self.port = port
        self.actual_port = 0
        self.chunk_size = chunk_size

    def run(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.actual_port = self.sock.getsockname()[1]
            self.sock.listen(BACKLOG)
            self.ready.set()

            while self.running:
                try:
                    r, _, _ = select.select([self.sock], [], [], 0.5)
                    if not r:
                        continue
                    conn, addr = self.sock.accept()
                    client_thread = threading.Thread(target=self.handle_upload_sha256, args=(conn,))
                    client_thread.daemon = True
                    client_thread.start()
                except OSError:
                    break
        except Exception as e:
            print(f"TcpUploadSha256Server error: {e}", file=sys.stderr)
        finally:
            if self.sock:
                self.sock.close()

    def handle_upload_sha256(self, conn):
        """Receive specified amount of data, return rolling SHA256 after each chunk."""
        hasher = hashlib.sha256()
        buffer = b""

        try:
            # Read the size header: "<size>\n"
            header = b""
            while b"\n" not in header and len(header) < 100:
                chunk = conn.recv(100)
                if not chunk:
                    return
                header += chunk

            line = header.split(b"\n")[0].decode().strip()
            expected_size = int(line)

            # Calculate how much of the data was already read with the header
            extra_data = header[header.index(b"\n") + 1:]
            buffer = extra_data
            total_received = len(extra_data)

            # Read remaining data and send rolling hashes
            while total_received < expected_size:
                chunk = conn.recv(min(65536, expected_size - total_received))
                if not chunk:
                    break
                buffer += chunk
                total_received += len(chunk)

                # Send hash after each chunk_size boundary
                while len(buffer) >= self.chunk_size:
                    hash_chunk = buffer[:self.chunk_size]
                    buffer = buffer[self.chunk_size:]
                    hasher.update(hash_chunk)
                    conn.sendall(hasher.digest())

            # Send final hash for remaining bytes
            if buffer:
                hasher.update(buffer)
                conn.sendall(hasher.digest())

        except (OSError, ConnectionError, BrokenPipeError, ValueError):
            pass
        finally:
            conn.close()


class TcpDownloadSha256Server(BaseEchoServer):
    """
    Server that sends data and expects rolling SHA256 responses.
    Protocol:
    - Client sends: "<size> <seed> <chunk_size>\\n"
    - Server sends chunks and verifies client's SHA256 after each
    """
    def __init__(self, host='127.0.0.1', port=0):
        super().__init__((host, port))
        self.host = host
        self.port = port
        self.actual_port = 0

    def run(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.actual_port = self.sock.getsockname()[1]
            self.sock.listen(BACKLOG)
            self.ready.set()

            while self.running:
                try:
                    r, _, _ = select.select([self.sock], [], [], 0.5)
                    if not r:
                        continue
                    conn, addr = self.sock.accept()
                    client_thread = threading.Thread(target=self.handle_download_sha256, args=(conn,))
                    client_thread.daemon = True
                    client_thread.start()
                except OSError:
                    break
        except Exception as e:
            print(f"TcpDownloadSha256Server error: {e}", file=sys.stderr)
        finally:
            if self.sock:
                self.sock.close()

    def handle_download_sha256(self, conn):
        """Send data, verify client's rolling SHA256."""
        try:
            request = b""
            while b"\n" not in request and len(request) < 100:
                chunk = conn.recv(100)
                if not chunk:
                    return
                request += chunk

            line = request.split(b"\n")[0].decode().strip()
            parts = line.split()
            if len(parts) != 3:
                return

            size = int(parts[0])
            seed = int(parts[1])
            chunk_size = int(parts[2])

            rng = random.Random(seed)
            hasher = hashlib.sha256()
            bytes_sent = 0

            # Don't check self.running - let in-flight transfers complete
            while bytes_sent < size:
                to_send = min(chunk_size, size - bytes_sent)
                data = rng.randbytes(to_send)
                conn.sendall(data)
                bytes_sent += len(data)

                hasher.update(data)

                client_hash = b""
                while len(client_hash) < 32:
                    chunk = conn.recv(32 - len(client_hash))
                    if not chunk:
                        return
                    client_hash += chunk

                if client_hash != hasher.digest():
                    return  # Hash mismatch

        except (OSError, ConnectionError, BrokenPipeError, ValueError):
            pass
        finally:
            conn.close()


class UdpDownloadSha256Server(BaseEchoServer):
    """
    UDP server that generates data and returns it with per-packet SHA256.
    Protocol (stateless, per-packet):
    - Client sends: "<offset> <chunk_size> <seed>\n"
    - Server responds: <data><sha256_of_data> (chunk_size + 32 bytes)

    Each packet is self-contained with its own SHA256, making it suitable
    for UDP's connectionless, potentially unreliable nature.
    """
    def __init__(self, host='127.0.0.1', port=0):
        super().__init__((host, port))
        self.host = host
        self.port = port
        self.actual_port = 0

    def run(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * 1024 * 1024)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 * 1024 * 1024)
            self.sock.bind((self.host, self.port))
            self.actual_port = self.sock.getsockname()[1]
            self.ready.set()

            while self.running:
                try:
                    r, _, _ = select.select([self.sock], [], [], 0.5)
                    if not r:
                        continue

                    data, addr = self.sock.recvfrom(65535)
                    self.handle_request(data, addr)
                except OSError:
                    break
        except Exception as e:
            print(f"UdpDownloadSha256Server error: {e}", file=sys.stderr)
        finally:
            if self.sock:
                self.sock.close()

    def handle_request(self, request, addr):
        """Handle a single UDP request: generate data chunk with SHA256."""
        try:
            line = request.decode().strip()
            parts = line.split()
            if len(parts) != 3:
                return

            offset = int(parts[0])
            chunk_size = int(parts[1])
            seed = int(parts[2])

            # Generate deterministic data for this specific chunk
            # Use offset in seed to ensure each chunk is unique but reproducible
            chunk_rng = random.Random(seed ^ (offset * 0x9e3779b9))
            data = chunk_rng.randbytes(chunk_size)

            # Compute SHA256 of this chunk
            chunk_hash = hashlib.sha256(data).digest()

            # Send data + hash as single packet
            self.sock.sendto(data + chunk_hash, addr)

        except (ValueError, OSError):
            pass


class UdpUploadSha256Server(BaseEchoServer):
    """
    UDP server that receives data with per-packet SHA256 and verifies it.
    Protocol (stateless, per-packet):
    - Client sends: <data><sha256_of_data> (chunk_size + 32 bytes)
    - Server computes sha256(data), responds: <computed_sha256> (32 bytes)

    Client can verify the response matches what it sent to confirm
    the data was received and verified correctly.
    """
    def __init__(self, host='127.0.0.1', port=0):
        super().__init__((host, port))
        self.host = host
        self.port = port
        self.actual_port = 0

    def run(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * 1024 * 1024)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 * 1024 * 1024)
            self.sock.bind((self.host, self.port))
            self.actual_port = self.sock.getsockname()[1]
            self.ready.set()

            while self.running:
                try:
                    r, _, _ = select.select([self.sock], [], [], 0.5)
                    if not r:
                        continue

                    data, addr = self.sock.recvfrom(65535)
                    self.handle_request(data, addr)
                except OSError:
                    break
        except Exception as e:
            print(f"UdpUploadSha256Server error: {e}", file=sys.stderr)
        finally:
            if self.sock:
                self.sock.close()

    def handle_request(self, packet, addr):
        """Handle a single UDP packet: verify SHA256 and respond."""
        try:
            if len(packet) < 33:  # At least 1 byte data + 32 byte hash
                return

            # Last 32 bytes are the hash
            data = packet[:-32]
            received_hash = packet[-32:]

            # Compute hash of received data
            computed_hash = hashlib.sha256(data).digest()

            # Respond with computed hash (client can verify it matches)
            self.sock.sendto(computed_hash, addr)

        except (ValueError, OSError):
            pass


# === Unix Socket Versions of Alternative Transfer Mode Servers ===

class UnixUploadServer(BaseEchoServer):
    """
    Unix socket server that accepts data uploads and discards them.
    Protocol (proxy-friendly, no half-close needed):
    - Client sends: "<size>\n" followed by exactly <size> bytes
    - Server responds: "<received_bytes>\n"
    """
    def __init__(self, path):
        super().__init__(path)
        self.path = path

    def run(self):
        if os.path.exists(self.path):
            os.unlink(self.path)

        try:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.bind(self.path)
            self.sock.listen(BACKLOG)
            self.ready.set()

            while self.running:
                try:
                    r, _, _ = select.select([self.sock], [], [], 0.5)
                    if not r:
                        continue
                    conn, addr = self.sock.accept()
                    client_thread = threading.Thread(target=self.handle_upload, args=(conn,))
                    client_thread.daemon = True
                    client_thread.start()
                except OSError:
                    break
        except Exception as e:
            print(f"UnixUploadServer error: {e}", file=sys.stderr)
        finally:
            if self.sock:
                self.sock.close()
            if os.path.exists(self.path):
                try:
                    os.unlink(self.path)
                except OSError:
                    pass

    def handle_upload(self, conn):
        """Receive specified amount of data, return byte count."""
        try:
            header = b""
            while b"\n" not in header and len(header) < 100:
                chunk = conn.recv(100)
                if not chunk:
                    return
                header += chunk

            line = header.split(b"\n")[0].decode().strip()
            expected_size = int(line)

            extra_data = header[header.index(b"\n") + 1:]
            total_bytes = len(extra_data)

            remaining = expected_size - total_bytes
            while remaining > 0:
                chunk = conn.recv(min(65536, remaining))
                if not chunk:
                    break
                total_bytes += len(chunk)
                remaining -= len(chunk)

            conn.sendall(f"{total_bytes}\n".encode())

        except (OSError, ConnectionError, BrokenPipeError, ValueError):
            pass
        finally:
            conn.close()


class UnixDownloadServer(BaseEchoServer):
    """
    Unix socket server that generates and sends data to clients.
    Client sends: "<size> <seed>\\n" to request data.
    Server responds with <size> bytes of seeded random data.
    """
    def __init__(self, path):
        super().__init__(path)
        self.path = path

    def run(self):
        if os.path.exists(self.path):
            os.unlink(self.path)

        try:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.bind(self.path)
            self.sock.listen(BACKLOG)
            self.ready.set()

            while self.running:
                try:
                    r, _, _ = select.select([self.sock], [], [], 0.5)
                    if not r:
                        continue
                    conn, addr = self.sock.accept()
                    client_thread = threading.Thread(target=self.handle_download, args=(conn,))
                    client_thread.daemon = True
                    client_thread.start()
                except OSError:
                    break
        except Exception as e:
            print(f"UnixDownloadServer error: {e}", file=sys.stderr)
        finally:
            if self.sock:
                self.sock.close()
            if os.path.exists(self.path):
                try:
                    os.unlink(self.path)
                except OSError:
                    pass

    def handle_download(self, conn):
        """Read request, generate and send data."""
        try:
            request = b""
            while b"\n" not in request and len(request) < 100:
                chunk = conn.recv(100)
                if not chunk:
                    return
                request += chunk

            line = request.split(b"\n")[0].decode().strip()
            parts = line.split()
            if len(parts) != 2:
                return

            size = int(parts[0])
            seed = int(parts[1])

            rng = random.Random(seed)
            chunk_size = 65536
            bytes_sent = 0

            while bytes_sent < size:
                to_send = min(chunk_size, size - bytes_sent)
                data = rng.randbytes(to_send)
                conn.sendall(data)
                bytes_sent += len(data)

        except (OSError, ConnectionError, BrokenPipeError, ValueError):
            pass
        finally:
            conn.close()


class UnixUploadSha256Server(BaseEchoServer):
    """
    Unix socket server that accepts uploads and returns rolling SHA256.
    Protocol (proxy-friendly, length-prefixed):
    - Client sends: "<size>\n" followed by exactly <size> bytes
    - Server buffers data, after each chunk_size bytes sends back rolling SHA256 (32 bytes)
    - After all data received, sends final SHA256 for any remaining bytes
    """
    def __init__(self, path, chunk_size=65536):
        super().__init__(path)
        self.path = path
        self.chunk_size = chunk_size

    def run(self):
        if os.path.exists(self.path):
            os.unlink(self.path)

        try:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.bind(self.path)
            self.sock.listen(BACKLOG)
            self.ready.set()

            while self.running:
                try:
                    r, _, _ = select.select([self.sock], [], [], 0.5)
                    if not r:
                        continue
                    conn, addr = self.sock.accept()
                    client_thread = threading.Thread(target=self.handle_upload_sha256, args=(conn,))
                    client_thread.daemon = True
                    client_thread.start()
                except OSError:
                    break
        except Exception as e:
            print(f"UnixUploadSha256Server error: {e}", file=sys.stderr)
        finally:
            if self.sock:
                self.sock.close()
            if os.path.exists(self.path):
                try:
                    os.unlink(self.path)
                except OSError:
                    pass

    def handle_upload_sha256(self, conn):
        """Receive specified amount of data, return rolling SHA256 after each chunk."""
        hasher = hashlib.sha256()
        buffer = b""

        try:
            header = b""
            while b"\n" not in header and len(header) < 100:
                chunk = conn.recv(100)
                if not chunk:
                    return
                header += chunk

            line = header.split(b"\n")[0].decode().strip()
            expected_size = int(line)

            extra_data = header[header.index(b"\n") + 1:]
            buffer = extra_data
            total_received = len(extra_data)

            while total_received < expected_size:
                chunk = conn.recv(min(65536, expected_size - total_received))
                if not chunk:
                    break
                buffer += chunk
                total_received += len(chunk)

                while len(buffer) >= self.chunk_size:
                    hash_chunk = buffer[:self.chunk_size]
                    buffer = buffer[self.chunk_size:]
                    hasher.update(hash_chunk)
                    conn.sendall(hasher.digest())

            if buffer:
                hasher.update(buffer)
                conn.sendall(hasher.digest())

        except (OSError, ConnectionError, BrokenPipeError, ValueError):
            pass
        finally:
            conn.close()


class UnixDownloadSha256Server(BaseEchoServer):
    """
    Unix socket server that sends data and expects rolling SHA256 responses.
    Protocol:
    - Client sends: "<size> <seed> <chunk_size>\\n"
    - Server sends chunks and verifies client's SHA256 after each
    """
    def __init__(self, path):
        super().__init__(path)
        self.path = path

    def run(self):
        if os.path.exists(self.path):
            os.unlink(self.path)

        try:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.bind(self.path)
            self.sock.listen(BACKLOG)
            self.ready.set()

            while self.running:
                try:
                    r, _, _ = select.select([self.sock], [], [], 0.5)
                    if not r:
                        continue
                    conn, addr = self.sock.accept()
                    client_thread = threading.Thread(target=self.handle_download_sha256, args=(conn,))
                    client_thread.daemon = True
                    client_thread.start()
                except OSError:
                    break
        except Exception as e:
            print(f"UnixDownloadSha256Server error: {e}", file=sys.stderr)
        finally:
            if self.sock:
                self.sock.close()
            if os.path.exists(self.path):
                try:
                    os.unlink(self.path)
                except OSError:
                    pass

    def handle_download_sha256(self, conn):
        """Send data, verify client's rolling SHA256."""
        try:
            request = b""
            while b"\n" not in request and len(request) < 100:
                chunk = conn.recv(100)
                if not chunk:
                    return
                request += chunk

            line = request.split(b"\n")[0].decode().strip()
            parts = line.split()
            if len(parts) != 3:
                return

            size = int(parts[0])
            seed = int(parts[1])
            chunk_size = int(parts[2])

            rng = random.Random(seed)
            hasher = hashlib.sha256()
            bytes_sent = 0

            while bytes_sent < size:
                to_send = min(chunk_size, size - bytes_sent)
                data = rng.randbytes(to_send)
                conn.sendall(data)
                bytes_sent += len(data)

                hasher.update(data)

                client_hash = b""
                while len(client_hash) < 32:
                    chunk = conn.recv(32 - len(client_hash))
                    if not chunk:
                        return
                    client_hash += chunk

                if client_hash != hasher.digest():
                    return  # Hash mismatch

        except (OSError, ConnectionError, BrokenPipeError, ValueError):
            pass
        finally:
            conn.close()
