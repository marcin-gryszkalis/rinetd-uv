import pytest
import os
import sys
import subprocess
import time
import shutil
import tempfile
from .servers import (
    TcpEchoServer, TcpEchoServerIPv6, UdpEchoServer, UnixEchoServer,
    TcpUploadServer, TcpDownloadServer, TcpUploadSha256Server, TcpDownloadSha256Server,
    UnixUploadServer, UnixDownloadServer, UnixUploadSha256Server, UnixDownloadSha256Server,
    UdpDownloadSha256Server
)
from .utils import ipv6_available
from .utils import create_rinetd_conf, get_free_port, wait_for_port

# Add test_suite directory to path so we can import modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def pytest_addoption(parser):
    parser.addoption("--rinetd-path", action="store", default=None, help="Path to rinetd executable")
    parser.addoption("--valgrind", action="store_true", help="Run tests under valgrind")

@pytest.fixture(scope="session")
def rinetd_path(request):
    path = request.config.getoption("--rinetd-path")
    if path:
        return os.path.abspath(path)
    
    # Try to find it in the parent directory (build dir)
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates = [
        os.path.join(base_dir, "rinetd"),
        os.path.join(base_dir, "src", "rinetd"),
        os.path.join(base_dir, "rinetd-uv"),
        os.path.join(base_dir, "src", "rinetd-uv"),
    ]
    
    for candidate in candidates:
        if os.path.exists(candidate) and os.access(candidate, os.X_OK):
            return candidate
            
    pytest.fail("Could not find rinetd executable. Use --rinetd-path to specify it.")

@pytest.fixture
def tcp_echo_server():
    server = TcpEchoServer()
    server.start()
    server.wait_ready()
    yield server
    server.stop()


@pytest.fixture
def tcp_echo_server_ipv6():
    """IPv6 TCP echo server. Skips if IPv6 unavailable."""
    if not ipv6_available():
        pytest.skip("IPv6 not available on this system")
    server = TcpEchoServerIPv6()
    server.start()
    server.wait_ready()
    yield server
    server.stop()


@pytest.fixture
def udp_echo_server():
    server = UdpEchoServer()
    server.start()
    server.wait_ready()
    yield server
    server.stop()

@pytest.fixture
def unix_echo_server(tmp_path):
    socket_path = str(tmp_path / "echo.sock")
    server = UnixEchoServer(socket_path)
    server.start()
    server.wait_ready()
    yield server
    server.stop()


# === Alternative Transfer Mode Server Fixtures ===

@pytest.fixture
def tcp_upload_server():
    """Server that accepts uploads and returns byte count."""
    server = TcpUploadServer()
    server.start()
    server.wait_ready()
    yield server
    server.stop()


@pytest.fixture
def tcp_download_server():
    """Server that generates and sends seeded random data."""
    server = TcpDownloadServer()
    server.start()
    server.wait_ready()
    yield server
    server.stop()


@pytest.fixture
def tcp_upload_sha256_server():
    """Server that returns rolling SHA256 after each received chunk."""
    server = TcpUploadSha256Server()
    server.start()
    server.wait_ready()
    yield server
    server.stop()


@pytest.fixture
def tcp_download_sha256_server():
    """Server that sends data and verifies client's rolling SHA256."""
    server = TcpDownloadSha256Server()
    server.start()
    server.wait_ready()
    yield server
    server.stop()


@pytest.fixture
def udp_download_sha256_server():
    """UDP server that sends data chunks with per-packet SHA256."""
    server = UdpDownloadSha256Server()
    server.start()
    server.wait_ready()
    yield server
    server.stop()


# === Unix Socket Alternative Transfer Mode Server Fixtures ===

@pytest.fixture
def unix_upload_server(tmp_path):
    """Unix socket server that accepts uploads and returns byte count."""
    socket_path = str(tmp_path / "upload.sock")
    server = UnixUploadServer(socket_path)
    server.start()
    server.wait_ready()
    yield server
    server.stop()


@pytest.fixture
def unix_download_server(tmp_path):
    """Unix socket server that generates and sends seeded random data."""
    socket_path = str(tmp_path / "download.sock")
    server = UnixDownloadServer(socket_path)
    server.start()
    server.wait_ready()
    yield server
    server.stop()


@pytest.fixture
def unix_upload_sha256_server(tmp_path):
    """Unix socket server that returns rolling SHA256 after each received chunk."""
    socket_path = str(tmp_path / "upload_sha256.sock")
    server = UnixUploadSha256Server(socket_path)
    server.start()
    server.wait_ready()
    yield server
    server.stop()


@pytest.fixture
def unix_download_sha256_server(tmp_path):
    """Unix socket server that sends data and verifies client's rolling SHA256."""
    socket_path = str(tmp_path / "download_sha256.sock")
    server = UnixDownloadSha256Server(socket_path)
    server.start()
    server.wait_ready()
    yield server
    server.stop()


@pytest.fixture
def rinetd(request, rinetd_path, tmp_path):
    """
    Fixture to run rinetd.
    Usage: rinetd(rules_list)
    Returns: subprocess.Popen object
    """
    process = None
    config_file = None
    logfile_path = None
    using_valgrind = False

    def _run_rinetd(rules, valgrind=False, logfile=None):
        nonlocal process, config_file, logfile_path, using_valgrind

        # Generate a log file in tmp_path to avoid parallel test conflicts
        test_name = request.node.name.replace("[", "_").replace("]", "_").replace("/", "_")
        if logfile:
            logfile_path = logfile
        else:
            logfile_path = str(tmp_path / f"{test_name}.log")

        config_file = create_rinetd_conf(rules, logfile=logfile_path)

        cmd = []
        using_valgrind = valgrind or request.config.getoption("--valgrind")
        if using_valgrind:
            cmd.extend([
                "valgrind",
                "--leak-check=full",
                "--show-leak-kinds=definite,indirect",
                "--track-fds=yes",
                "--error-exitcode=1",
                "--quiet"
            ])

        cmd.extend([rinetd_path, "-f", "-c", config_file])

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )

        # Give it a moment to start
        time.sleep(0.2)

        if process.poll() is not None:
            stdout, stderr = process.communicate()
            pytest.fail(f"rinetd failed to start:\nStdout: {stdout}\nStderr: {stderr}")

        return process

    yield _run_rinetd

    # Cleanup
    if process:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

        # Capture output for debugging
        stdout_output = ""
        stderr_output = ""
        try:
            if process.stdout and not process.stdout.closed:
                stdout_output = process.stdout.read()
            if process.stderr and not process.stderr.closed:
                stderr_output = process.stderr.read()
        except ValueError:
            pass

        if stdout_output:
            print(f"\n[rinetd stdout]:\n{stdout_output}")
        if stderr_output:
            print(f"\n[rinetd stderr]:\n{stderr_output}")

        # Valgrind error checking - only for tests not explicitly handling valgrind themselves
        # (test_leaks.py handles valgrind output directly)
        if using_valgrind and "test_memory_leaks" not in request.node.name:
            import re
            # Check for definitely lost memory
            def_lost_match = re.search(r'definitely lost:\s*([\d,]+)\s*bytes', stderr_output)
            if def_lost_match:
                bytes_lost = int(def_lost_match.group(1).replace(',', ''))
                if bytes_lost > 0:
                    pytest.fail(f"Valgrind found {bytes_lost} bytes definitely lost\n{stderr_output}")

            # Check error summary
            error_match = re.search(r'ERROR SUMMARY:\s*(\d+)\s*errors', stderr_output)
            if error_match:
                error_count = int(error_match.group(1))
                if error_count > 0:
                    pytest.fail(f"Valgrind reported {error_count} errors\n{stderr_output}")

    if config_file and os.path.exists(config_file):
        os.unlink(config_file)

