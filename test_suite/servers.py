import socket
import threading
import os
import sys
import time
import select

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
            self.sock.listen(100)
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
        try:
            while self.running:
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
            self.sock.listen(100)
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
        try:
            while self.running:
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
            self.sock.listen(100)
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
        try:
            while self.running:
                data = conn.recv(4096)
                if not data:
                    break
                conn.sendall(data)
        except (OSError, ConnectionError, BrokenPipeError):
            pass  # Expected when client disconnects
        finally:
            conn.close()
