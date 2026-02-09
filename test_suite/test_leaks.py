import pytest
import socket
import time
import re
import signal
from .utils import get_free_port, wait_for_port, generate_random_data, send_all, recv_all


def parse_valgrind_output(stderr):
    """
    Parse Valgrind output and return leak information.
    Returns dict with 'definitely_lost', 'indirectly_lost', 'possibly_lost', 'errors'.
    """
    result = {
        'definitely_lost': 0,
        'indirectly_lost': 0,
        'possibly_lost': 0,
        'errors': 0,
        'raw_output': stderr
    }

    # Match "definitely lost: X bytes in Y blocks"
    match = re.search(r'definitely lost:\s*([\d,]+)\s*bytes', stderr)
    if match:
        result['definitely_lost'] = int(match.group(1).replace(',', ''))

    match = re.search(r'indirectly lost:\s*([\d,]+)\s*bytes', stderr)
    if match:
        result['indirectly_lost'] = int(match.group(1).replace(',', ''))

    match = re.search(r'possibly lost:\s*([\d,]+)\s*bytes', stderr)
    if match:
        result['possibly_lost'] = int(match.group(1).replace(',', ''))

    # Match "ERROR SUMMARY: X errors"
    match = re.search(r'ERROR SUMMARY:\s*(\d+)\s*errors', stderr)
    if match:
        result['errors'] = int(match.group(1))

    return result


@pytest.mark.valgrind
def test_memory_leaks_tcp(rinetd, tcp_echo_server, request):
    """
    Run a simple transfer test under valgrind to check for leaks.
    This test forces valgrind execution for the rinetd process.
    """
    import shutil
    if not shutil.which("valgrind"):
        pytest.skip("valgrind not found")

    rinetd_port = get_free_port()

    rules = [
        f"0.0.0.0 {rinetd_port} {tcp_echo_server.host} {tcp_echo_server.actual_port}"
    ]

    proc = rinetd(rules, valgrind=True)

    assert wait_for_port(rinetd_port), "rinetd did not start"

    # Exercise code paths with multiple connections
    for i in range(10):
        with socket.create_connection(('127.0.0.1', rinetd_port), timeout=5) as s:
            data = b"leak_check_" + str(i).encode() + b"_" * 100
            s.sendall(data)
            received = recv_all(s, len(data))
            assert received == data, f"Data mismatch on iteration {i}"

    # Gracefully terminate rinetd to allow Valgrind to produce complete report
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except Exception:
        proc.kill()
        proc.wait()

    # Capture Valgrind output
    stdout_output = ""
    stderr_output = ""
    try:
        if proc.stdout and not proc.stdout.closed:
            stdout_output = proc.stdout.read()
        if proc.stderr and not proc.stderr.closed:
            stderr_output = proc.stderr.read()
    except ValueError:
        pass

    # Parse and verify Valgrind results
    valgrind_result = parse_valgrind_output(stderr_output)

    # Assert no memory leaks
    assert valgrind_result['definitely_lost'] == 0, \
        f"Valgrind found definitely lost memory: {valgrind_result['definitely_lost']} bytes\n{stderr_output}"
    assert valgrind_result['indirectly_lost'] == 0, \
        f"Valgrind found indirectly lost memory: {valgrind_result['indirectly_lost']} bytes\n{stderr_output}"
    assert valgrind_result['errors'] == 0, \
        f"Valgrind found {valgrind_result['errors']} errors\n{stderr_output}"


@pytest.mark.valgrind
def test_memory_leaks_udp(rinetd, udp_echo_server, request):
    """
    Run UDP transfer test under valgrind to check for leaks.
    """
    import shutil
    import platform
    if not shutil.which("valgrind"):
        pytest.skip("valgrind not found")

    # Skip on FreeBSD due to Valgrind UDP socket compatibility issues
    # See: https://github.com/paulfloyd/freebsd_valgrind/issues/137
    # FreeBSD's Valgrind has signal handling issues that cause UDP socket
    # operations to hang (sigreturn rflags errors)
    if platform.system() == "FreeBSD":
        pytest.skip("Valgrind UDP tests hang on FreeBSD due to known signal handling issues")

    rinetd_port = get_free_port()

    rules = [
        f"0.0.0.0 {rinetd_port}/udp 127.0.0.1 {udp_echo_server.actual_port}/udp"
    ]

    proc = rinetd(rules, valgrind=True)
    # Valgrind adds significant overhead, need longer wait for UDP readiness
    time.sleep(2)

    # Exercise UDP code paths
    for i in range(10):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(10)  # Longer timeout under Valgrind
            data = f"udp_leak_check_{i}".encode()
            s.sendto(data, ('127.0.0.1', rinetd_port))
            received, _ = s.recvfrom(65535)
            assert received == data, f"UDP data mismatch on iteration {i}"

    # Gracefully terminate
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except Exception:
        proc.kill()
        proc.wait()

    stderr_output = ""
    try:
        if proc.stderr and not proc.stderr.closed:
            stderr_output = proc.stderr.read()
    except ValueError:
        pass

    valgrind_result = parse_valgrind_output(stderr_output)

    assert valgrind_result['definitely_lost'] == 0, \
        f"Valgrind found definitely lost memory: {valgrind_result['definitely_lost']} bytes\n{stderr_output}"
    assert valgrind_result['errors'] == 0, \
        f"Valgrind found {valgrind_result['errors']} errors\n{stderr_output}"


@pytest.mark.valgrind
def test_memory_leaks_rapid_connections(rinetd, tcp_echo_server, request):
    """
    Test for leaks under rapid connection/disconnection cycles.
    """
    import shutil
    if not shutil.which("valgrind"):
        pytest.skip("valgrind not found")

    rinetd_port = get_free_port()

    rules = [
        f"0.0.0.0 {rinetd_port} {tcp_echo_server.host} {tcp_echo_server.actual_port}"
    ]

    proc = rinetd(rules, valgrind=True)
    assert wait_for_port(rinetd_port), "rinetd did not start"

    # Rapid connect/disconnect cycles to stress connection handling
    for i in range(50):
        try:
            with socket.create_connection(('127.0.0.1', rinetd_port), timeout=2) as s:
                s.sendall(b"x")
                s.recv(1)
        except Exception:
            pass  # Some failures expected under load

    proc.terminate()
    try:
        proc.wait(timeout=10)
    except Exception:
        proc.kill()
        proc.wait()

    stderr_output = ""
    try:
        if proc.stderr and not proc.stderr.closed:
            stderr_output = proc.stderr.read()
    except ValueError:
        pass

    valgrind_result = parse_valgrind_output(stderr_output)

    assert valgrind_result['definitely_lost'] == 0, \
        f"Valgrind found definitely lost memory after rapid connections: {valgrind_result['definitely_lost']} bytes\n{stderr_output}"
