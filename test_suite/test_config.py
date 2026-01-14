import pytest
import socket
import os
import time
from .utils import get_free_port, wait_for_port

def test_allow_rule(rinetd, tcp_echo_server):
    """Test 'allow' rule."""
    rinetd_port = get_free_port()
    
    rules = [
        "allow 127.0.0.1",
        f"0.0.0.0 {rinetd_port} {tcp_echo_server.host} {tcp_echo_server.actual_port}"
    ]
    
    rinetd(rules)
    assert wait_for_port(rinetd_port)
    
    # Should succeed
    with socket.create_connection(('127.0.0.1', rinetd_port), timeout=2) as s:
        s.send(b"test")
        assert s.recv(4) == b"test"

def test_deny_rule(rinetd, tcp_echo_server):
    """Test 'deny' rule."""
    rinetd_port = get_free_port()
    
    rules = [
        "deny 127.0.0.1",
        f"0.0.0.0 {rinetd_port} {tcp_echo_server.host} {tcp_echo_server.actual_port}"
    ]
    
    rinetd(rules)
    assert wait_for_port(rinetd_port)
    
    # Should fail (connection closed by peer)
    try:
        with socket.create_connection(('127.0.0.1', rinetd_port), timeout=2) as s:
            # Some implementations might accept then close, or just close.
            # If we can send and recv, it failed.
            s.send(b"test")
            data = s.recv(4)
            assert data == b"", "Connection should have been closed"
    except (ConnectionResetError, ConnectionAbortedError, socket.timeout, OSError):
        # This is expected
        pass

def test_logfile(rinetd, tcp_echo_server, tmp_path):
    """Test logfile creation."""
    rinetd_port = get_free_port()
    logfile = str(tmp_path / "rinetd.log")
    
    rules = [
        f"logfile \"{logfile}\"",
        f"0.0.0.0 {rinetd_port} {tcp_echo_server.host} {tcp_echo_server.actual_port}"
    ]
    
    rinetd(rules)
    assert wait_for_port(rinetd_port)
    
    # Make a connection to generate log
    with socket.create_connection(('127.0.0.1', rinetd_port), timeout=2) as s:
        s.send(b"test")
        s.recv(4)
        
    # Wait for log flush (rinetd might buffer)
    time.sleep(1)
    
    assert os.path.exists(logfile)
    with open(logfile, 'r') as f:
        content = f.read()
        assert "127.0.0.1" in content # Client IP should be logged

def test_bind_options(rinetd, tcp_echo_server):
    """Test bind options parsing (timeout, etc)."""
    rinetd_port = get_free_port()
    
    # Test with timeout option
    rules = [
        f"0.0.0.0 {rinetd_port} {tcp_echo_server.host} {tcp_echo_server.actual_port} [timeout=5]"
    ]
    
    rinetd(rules)
    assert wait_for_port(rinetd_port)
    
    # Just verify it works
    with socket.create_connection(('127.0.0.1', rinetd_port), timeout=2) as s:
        s.send(b"test")
        assert s.recv(4) == b"test"

def test_pidfile(rinetd, tcp_echo_server, tmp_path):
    """Test pidfile creation."""
    rinetd_port = get_free_port()
    pidfile = str(tmp_path / "rinetd.pid")
    
    rules = [
        f"pidfile \"{pidfile}\"",
        f"0.0.0.0 {rinetd_port} {tcp_echo_server.host} {tcp_echo_server.actual_port}"
    ]
    
    rinetd(rules)
    assert wait_for_port(rinetd_port)
    
    assert os.path.exists(pidfile)
    with open(pidfile, 'r') as f:
        pid = int(f.read().strip())
        assert pid > 0

def test_logcommon(rinetd, tcp_echo_server, tmp_path):
    """Test logcommon directive."""
    rinetd_port = get_free_port()
    logfile = str(tmp_path / "rinetd.log")
    
    rules = [
        "logcommon",
        f"logfile \"{logfile}\"",
        f"0.0.0.0 {rinetd_port} {tcp_echo_server.host} {tcp_echo_server.actual_port}"
    ]
    
    rinetd(rules)
    assert wait_for_port(rinetd_port)
    
    with socket.create_connection(('127.0.0.1', rinetd_port), timeout=2) as s:
        s.send(b"test")
        s.recv(4)
        
    time.sleep(1)
    
    assert os.path.exists(logfile)
    with open(logfile, 'r') as f:
        content = f.read()
        # Common log format usually starts with client IP and has [date]
        assert "127.0.0.1" in content
        assert "[" in content and "]" in content

def test_buffersize(rinetd, tcp_echo_server):
    """Test buffersize directive."""
    rinetd_port = get_free_port()
    
    rules = [
        "buffersize 16384",
        f"0.0.0.0 {rinetd_port} {tcp_echo_server.host} {tcp_echo_server.actual_port}"
    ]
    
    rinetd(rules)
    assert wait_for_port(rinetd_port)
    
    # Verify it still works
    with socket.create_connection(('127.0.0.1', rinetd_port), timeout=2) as s:
        s.send(b"test")
        assert s.recv(4) == b"test"

def test_keepalive(rinetd, tcp_echo_server):
    """Test keepalive option."""
    rinetd_port = get_free_port()
    
    rules = [
        f"0.0.0.0 {rinetd_port} {tcp_echo_server.host} {tcp_echo_server.actual_port} [keepalive=on]"
    ]
    
    rinetd(rules)
    assert wait_for_port(rinetd_port)
    
    with socket.create_connection(('127.0.0.1', rinetd_port), timeout=2) as s:
        s.send(b"test")
        assert s.recv(4) == b"test"

def test_include_directive(rinetd, tcp_echo_server, tmp_path):
    """Test include directive."""
    rinetd_port = get_free_port()
    include_file = str(tmp_path / "included.conf")
    
    with open(include_file, 'w') as f:
        f.write(f"0.0.0.0 {rinetd_port} {tcp_echo_server.host} {tcp_echo_server.actual_port}\n")
        
    rules = [
        f"include \"{include_file}\""
    ]
    
    rinetd(rules)
    assert wait_for_port(rinetd_port)
    
    with socket.create_connection(('127.0.0.1', rinetd_port), timeout=2) as s:
        s.send(b"test")
        assert s.recv(4) == b"test"

def test_dns_refresh(rinetd, tcp_echo_server):
    """Test dns-refresh directive."""
    rinetd_port = get_free_port()
    
    rules = [
        "dns-refresh 60",
        f"0.0.0.0 {rinetd_port} {tcp_echo_server.host} {tcp_echo_server.actual_port} [dns-refresh=30]"
    ]
    
    rinetd(rules)
    assert wait_for_port(rinetd_port)
    
    with socket.create_connection(('127.0.0.1', rinetd_port), timeout=2) as s:
        s.send(b"test")
        assert s.recv(4) == b"test"

def test_source_address(rinetd, tcp_echo_server):
    """Test src (source address) option."""
    rinetd_port = get_free_port()
    
    # Use 127.0.0.1 as source address
    rules = [
        f"0.0.0.0 {rinetd_port} {tcp_echo_server.host} {tcp_echo_server.actual_port} [src=127.0.0.1]"
    ]
    
    rinetd(rules)
    assert wait_for_port(rinetd_port)
    
    with socket.create_connection(('127.0.0.1', rinetd_port), timeout=2) as s:
        s.send(b"test")
        assert s.recv(4) == b"test"

def test_unix_socket_mode(rinetd, tcp_echo_server, tmp_path):
    """Test mode option for Unix sockets."""
    socket_path = str(tmp_path / "rinetd.sock")
    
    # Set mode to 0666
    rules = [
        f"unix:{socket_path} {tcp_echo_server.host} {tcp_echo_server.actual_port} [mode=0666]"
    ]
    
    rinetd(rules)
    time.sleep(0.5)
    
    assert os.path.exists(socket_path)
    mode = os.stat(socket_path).st_mode & 0o777
    assert mode == 0o666


