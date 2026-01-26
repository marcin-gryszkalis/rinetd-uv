import pytest
import socket
import os
import time
import subprocess
from .utils import get_free_port, wait_for_port, create_rinetd_conf

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
    """Test basic single file include."""
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


def test_include_wildcard(rinetd, tcp_echo_server, tmp_path):
    """Test wildcard pattern include (include *.conf)."""
    port1 = get_free_port()
    port2 = get_free_port()
    port3 = get_free_port()

    # Create a subdirectory with multiple config files
    include_dir = tmp_path / "includes"
    include_dir.mkdir()

    # Create multiple config files to be included
    (include_dir / "server1.conf").write_text(
        f"0.0.0.0 {port1} {tcp_echo_server.host} {tcp_echo_server.actual_port}\n"
    )
    (include_dir / "server2.conf").write_text(
        f"0.0.0.0 {port2} {tcp_echo_server.host} {tcp_echo_server.actual_port}\n"
    )
    (include_dir / "server3.conf").write_text(
        f"0.0.0.0 {port3} {tcp_echo_server.host} {tcp_echo_server.actual_port}\n"
    )

    rules = [
        f"include \"{include_dir}/*.conf\""
    ]

    rinetd(rules)

    # All three ports should be listening
    for port in [port1, port2, port3]:
        assert wait_for_port(port), f"Port {port} should be open"
        with socket.create_connection(('127.0.0.1', port), timeout=2) as s:
            s.send(b"test")
            assert s.recv(4) == b"test"


def test_include_nested(rinetd, tcp_echo_server, tmp_path):
    """Test nested includes (3 levels: A -> B -> C)."""
    port1 = get_free_port()
    port2 = get_free_port()
    port3 = get_free_port()

    # Create level 3 (deepest)
    level3 = tmp_path / "level3.conf"
    level3.write_text(f"0.0.0.0 {port3} {tcp_echo_server.host} {tcp_echo_server.actual_port}\n")

    # Create level 2 (includes level 3)
    level2 = tmp_path / "level2.conf"
    level2.write_text(
        f"0.0.0.0 {port2} {tcp_echo_server.host} {tcp_echo_server.actual_port}\n"
        f"include \"{level3}\"\n"
    )

    # Create level 1 (includes level 2)
    level1 = tmp_path / "level1.conf"
    level1.write_text(
        f"0.0.0.0 {port1} {tcp_echo_server.host} {tcp_echo_server.actual_port}\n"
        f"include \"{level2}\"\n"
    )

    rules = [
        f"include \"{level1}\""
    ]

    rinetd(rules)

    # All three ports should be listening
    for port in [port1, port2, port3]:
        assert wait_for_port(port), f"Port {port} should be open"
        with socket.create_connection(('127.0.0.1', port), timeout=2) as s:
            s.send(b"test")
            assert s.recv(4) == b"test"


def test_include_circular_detection(rinetd_path, tmp_path):
    """Test circular include detection (A -> B -> A should fail)."""
    port1 = get_free_port()
    port2 = get_free_port()

    file_a = tmp_path / "circular_a.conf"
    file_b = tmp_path / "circular_b.conf"

    # A includes B
    file_a.write_text(
        f"0.0.0.0 {port1} 127.0.0.1 9999\n"
        f"include \"{file_b}\"\n"
    )

    # B includes A (circular)
    file_b.write_text(
        f"0.0.0.0 {port2} 127.0.0.1 9998\n"
        f"include \"{file_a}\"\n"
    )

    # Start rinetd directly (not using fixture as we expect failure)
    proc = subprocess.Popen(
        [rinetd_path, "-c", str(file_a), "-f"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    try:
        stdout, stderr = proc.communicate(timeout=2.0)
        # Process should exit with error
        assert proc.returncode != 0, "rinetd should fail with circular include"
        assert "circular include" in stderr.lower(), f"Expected 'circular include' error, got: {stderr}"
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        pytest.fail("rinetd should have failed quickly with circular include error")


def test_include_max_depth(rinetd_path, tmp_path):
    """Test maximum include depth limit (default is 10, try 11 levels)."""
    # Create 11 levels of nested includes (exceeds max depth of 10)
    files = []
    for i in range(11, 0, -1):
        f = tmp_path / f"deep_{i:02d}.conf"
        files.append(f)

    # Write files from deepest to shallowest
    for i, f in enumerate(files):
        port = get_free_port()
        if i == 0:
            # Deepest file - no include
            f.write_text(f"0.0.0.0 {port} 127.0.0.1 9999\n")
        else:
            # Include the previous (deeper) file
            f.write_text(
                f"0.0.0.0 {port} 127.0.0.1 9999\n"
                f"include \"{files[i-1]}\"\n"
            )

    # Start with the shallowest file (which starts the chain of 11 includes)
    main_file = files[-1]

    proc = subprocess.Popen(
        [rinetd_path, "-c", str(main_file), "-f"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    try:
        stdout, stderr = proc.communicate(timeout=2.0)
        # Process should exit with error
        assert proc.returncode != 0, "rinetd should fail with max depth exceeded"
        assert "maximum include depth" in stderr.lower() or "max" in stderr.lower(), \
            f"Expected max depth error, got: {stderr}"
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        pytest.fail("rinetd should have failed quickly with max depth error")


def test_include_relative_path(rinetd, tcp_echo_server, tmp_path):
    """Test relative path resolution (paths relative to including file)."""
    port1 = get_free_port()
    port2 = get_free_port()

    # Create subdirectory structure
    subdir = tmp_path / "subdir"
    subdir.mkdir()

    # Child config in subdirectory
    child = subdir / "child.conf"
    child.write_text(f"0.0.0.0 {port2} {tcp_echo_server.host} {tcp_echo_server.actual_port}\n")

    # Parent config uses relative path to include child
    parent = tmp_path / "parent.conf"
    parent.write_text(
        f"0.0.0.0 {port1} {tcp_echo_server.host} {tcp_echo_server.actual_port}\n"
        f"include \"subdir/child.conf\"\n"
    )

    rules = [
        f"include \"{parent}\""
    ]

    rinetd(rules)

    # Both ports should be listening
    for port in [port1, port2]:
        assert wait_for_port(port), f"Port {port} should be open"
        with socket.create_connection(('127.0.0.1', port), timeout=2) as s:
            s.send(b"test")
            assert s.recv(4) == b"test"


@pytest.mark.expect_rinetd_errors
def test_include_no_match_warning(rinetd, tcp_echo_server, tmp_path):
    """Test that non-matching wildcard pattern logs warning but continues."""
    rinetd_port = get_free_port()

    rules = [
        f"0.0.0.0 {rinetd_port} {tcp_echo_server.host} {tcp_echo_server.actual_port}",
        f"include \"{tmp_path}/nonexistent/*.conf\"",  # No files match
    ]

    # rinetd should start despite no files matching the pattern
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


# === Access Control Wildcard Tests ===

def test_allow_wildcard_star(rinetd, tcp_echo_server):
    """Test allow rule with * wildcard (matches any characters)."""
    rinetd_port = get_free_port()

    rules = [
        "allow 127.0.0.*",  # Should match 127.0.0.1
        f"0.0.0.0 {rinetd_port} {tcp_echo_server.host} {tcp_echo_server.actual_port}"
    ]

    rinetd(rules)
    assert wait_for_port(rinetd_port)

    # Should succeed - 127.0.0.1 matches 127.0.0.*
    with socket.create_connection(('127.0.0.1', rinetd_port), timeout=2) as s:
        s.send(b"test")
        assert s.recv(4) == b"test"


def test_deny_wildcard_star(rinetd, tcp_echo_server):
    """Test deny rule with * wildcard."""
    rinetd_port = get_free_port()

    rules = [
        "deny 127.*",  # Should match 127.0.0.1
        f"0.0.0.0 {rinetd_port} {tcp_echo_server.host} {tcp_echo_server.actual_port}"
    ]

    rinetd(rules)
    assert wait_for_port(rinetd_port)

    # Should fail - 127.0.0.1 matches 127.*
    try:
        with socket.create_connection(('127.0.0.1', rinetd_port), timeout=2) as s:
            s.send(b"test")
            data = s.recv(4)
            assert data == b"", "Connection should have been denied"
    except (ConnectionResetError, ConnectionAbortedError, socket.timeout, OSError):
        pass  # Expected


def test_allow_wildcard_question(rinetd, tcp_echo_server):
    """Test allow rule with ? wildcard (matches single character)."""
    rinetd_port = get_free_port()

    rules = [
        "allow 127.0.0.?",  # Should match 127.0.0.1 (single digit)
        f"0.0.0.0 {rinetd_port} {tcp_echo_server.host} {tcp_echo_server.actual_port}"
    ]

    rinetd(rules)
    assert wait_for_port(rinetd_port)

    # Should succeed - 127.0.0.1 matches 127.0.0.?
    with socket.create_connection(('127.0.0.1', rinetd_port), timeout=2) as s:
        s.send(b"test")
        assert s.recv(4) == b"test"


def test_allow_all_wildcard(rinetd, tcp_echo_server):
    """Test allow rule with full wildcard (allow all)."""
    rinetd_port = get_free_port()

    rules = [
        "allow *",  # Allow everything
        f"0.0.0.0 {rinetd_port} {tcp_echo_server.host} {tcp_echo_server.actual_port}"
    ]

    rinetd(rules)
    assert wait_for_port(rinetd_port)

    with socket.create_connection(('127.0.0.1', rinetd_port), timeout=2) as s:
        s.send(b"test")
        assert s.recv(4) == b"test"


# === Multiple Rules Tests ===

def test_multiple_tcp_rules(rinetd, tcp_echo_server):
    """Test multiple forwarding rules in single config."""
    port1 = get_free_port()
    port2 = get_free_port()
    port3 = get_free_port()

    rules = [
        f"0.0.0.0 {port1} {tcp_echo_server.host} {tcp_echo_server.actual_port}",
        f"0.0.0.0 {port2} {tcp_echo_server.host} {tcp_echo_server.actual_port}",
        f"0.0.0.0 {port3} {tcp_echo_server.host} {tcp_echo_server.actual_port}",
    ]

    rinetd(rules)

    # All three ports should work
    for port in [port1, port2, port3]:
        assert wait_for_port(port), f"Port {port} should be open"
        with socket.create_connection(('127.0.0.1', port), timeout=2) as s:
            s.send(b"test")
            assert s.recv(4) == b"test"


def test_mixed_protocol_rules(rinetd, tcp_echo_server, udp_echo_server, unix_echo_server, tmp_path):
    """Test TCP, UDP, and Unix socket rules together."""
    tcp_port = get_free_port()
    udp_port = get_free_port()
    unix_path = str(tmp_path / "mixed.sock")

    rules = [
        f"0.0.0.0 {tcp_port} {tcp_echo_server.host} {tcp_echo_server.actual_port}",
        f"0.0.0.0 {udp_port}/udp {udp_echo_server.host} {udp_echo_server.actual_port}/udp",
        f"unix:{unix_path} {tcp_echo_server.host} {tcp_echo_server.actual_port}",
    ]

    rinetd(rules)

    # Test TCP
    assert wait_for_port(tcp_port)
    with socket.create_connection(('127.0.0.1', tcp_port), timeout=2) as s:
        s.send(b"tcp_test")
        assert s.recv(8) == b"tcp_test"

    # Test UDP
    time.sleep(0.2)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(2)
        s.sendto(b"udp_test", ('127.0.0.1', udp_port))
        received, _ = s.recvfrom(65535)
        assert received == b"udp_test"

    # Test Unix
    time.sleep(0.2)
    assert os.path.exists(unix_path)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(2)
        s.connect(unix_path)
        s.send(b"unix_test")
        assert s.recv(9) == b"unix_test"


def test_per_rule_allow_deny(rinetd, tcp_echo_server):
    """Test per-rule allow/deny (after the forwarding rule)."""
    port_allowed = get_free_port()
    port_denied = get_free_port()

    rules = [
        f"0.0.0.0 {port_allowed} {tcp_echo_server.host} {tcp_echo_server.actual_port}",
        "allow 127.0.0.1",  # Allow for the above rule
        f"0.0.0.0 {port_denied} {tcp_echo_server.host} {tcp_echo_server.actual_port}",
        "deny 127.0.0.1",   # Deny for this rule
    ]

    rinetd(rules)

    # First port should work (allowed)
    assert wait_for_port(port_allowed)
    with socket.create_connection(('127.0.0.1', port_allowed), timeout=2) as s:
        s.send(b"test")
        assert s.recv(4) == b"test"

    # Second port should be denied
    assert wait_for_port(port_denied)
    try:
        with socket.create_connection(('127.0.0.1', port_denied), timeout=2) as s:
            s.send(b"test")
            data = s.recv(4)
            assert data == b"", "Connection should have been denied"
    except (ConnectionResetError, ConnectionAbortedError, socket.timeout, OSError):
        pass  # Expected


