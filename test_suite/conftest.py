import pytest
import os
import sys
import subprocess
import time
import shutil
import tempfile
from .servers import TcpEchoServer, UdpEchoServer, UnixEchoServer
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

@pytest.fixture
def rinetd(request, rinetd_path):
    """
    Fixture to run rinetd.
    Usage: rinetd(rules_list)
    Returns: subprocess.Popen object
    """
    process = None
    config_file = None
    
    def _run_rinetd(rules, valgrind=False):
        nonlocal process, config_file
        
        # Generate a log file name based on the test name
        test_name = request.node.name.replace("[", "_").replace("]", "_").replace("/", "_")
        logfile = f"/tmp/{test_name}.log"
        
        config_file = create_rinetd_conf(rules, logfile=logfile)
        
        cmd = []
        if valgrind or request.config.getoption("--valgrind"):
            cmd.extend(["valgrind", "--leak-check=full", "--track-fds=yes", "--error-exitcode=1", "--quiet"])
            
        cmd.extend([rinetd_path, "-f", "-c", config_file])
        
        # Start rinetd
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
        
        # Print output for debugging
        stdout_output = ""
        stderr_output = ""
        try:
            if process.stdout and not process.stdout.closed:
                stdout_output = process.stdout.read()
            if process.stderr and not process.stderr.closed:
                stderr_output = process.stderr.read()
        except ValueError:
            # Pipes might be closed if communicate() was called
            pass
        
        if stdout_output:
            print(f"\n[rinetd stdout]:\n{stdout_output}")
        if stderr_output:
            print(f"\n[rinetd stderr]:\n{stderr_output}")

        # Check exit code if valgrind was used
        # Note: If we terminated it, the exit code might be related to the signal (e.g. -15)
        # unless rinetd catches it and exits with 0 or a specific code.
        # Valgrind with --error-exitcode=1 will return 1 if errors found, 
        # but only if the program exits normally (or handles signal and exits).
        # If rinetd doesn't handle SIGTERM, valgrind might not report errors via exit code 
        # in the way we expect if it's killed.
        # However, we can check stderr for "definitely lost" or similar.
        
        args = getattr(process, 'args', [])
        if any("valgrind" in str(arg) for arg in args):
             if "definitely lost: 0 bytes in 0 blocks" not in stderr_output and "ERROR SUMMARY: 0 errors" not in stderr_output:
                 # This is a heuristic, might need adjustment based on actual valgrind output
                 # If we see "ERROR SUMMARY: X errors" where X > 0, it's a fail.
                 import re
                 match = re.search(r"ERROR SUMMARY: (\d+) errors", stderr_output)
                 if match and int(match.group(1)) > 0:
                     print(stderr_output, file=sys.stderr)
                     pytest.fail(f"Valgrind reported {match.group(1)} errors")

    if config_file and os.path.exists(config_file):
        os.unlink(config_file)

