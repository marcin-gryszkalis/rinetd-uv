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
    Returns total bytes received when client closes connection.
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
        """Receive all data, return byte count at end."""
        total_bytes = 0
        try:
            # Don't check self.running - let in-flight transfers complete
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                total_bytes += len(data)
            conn.sendall(f"{total_bytes}\n".encode())
        except (OSError, ConnectionError, BrokenPipeError):
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
    Protocol:
    - Client sends data in chunks
    - After receiving each chunk, server sends back the rolling SHA256 (32 bytes)
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
        """Receive data, return rolling SHA256 after each chunk."""
        hasher = hashlib.sha256()
        buffer = b""

        try:
            # Don't check self.running - let in-flight transfers complete
            while True:
                data = conn.recv(65536)
                if not data:
                    break

                buffer += data

                while len(buffer) >= self.chunk_size:
                    chunk = buffer[:self.chunk_size]
                    buffer = buffer[self.chunk_size:]
                    hasher.update(chunk)
                    conn.sendall(hasher.digest())

            if buffer:
                hasher.update(buffer)
                conn.sendall(hasher.digest())

        except (OSError, ConnectionError, BrokenPipeError):
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
