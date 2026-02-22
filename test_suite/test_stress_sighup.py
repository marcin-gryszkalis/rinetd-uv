"""
Stress test with periodic SIGHUP reloads and dynamic config changes.

Tests two key properties of rinetd-uv under simultaneous load:
  1. Existing TCP connections are NOT disrupted by SIGHUP config reload.
     Each pair uses a single persistent TCP connection for the full test
     duration.  Any mid-test connection drop is a hard test failure.
  2. Config reload correctly handles rule addition and removal while the
     server keeps running under load.

Both the legacy .conf format and YAML format are tested.

All tunables are defined at the top of this file.
"""
import concurrent.futures
import json
import os
import random
import signal
import socket
import subprocess
import threading
import time

import pytest

from .servers import TcpEchoServer
from .utils import (
    DEFAULT_TIMEOUT,
    SeededRandomStream,
    get_file_limit,
    random_transfer_params,
    recv_all,
    wait_for_port,
)

# ============================================================
# Tunables – modify these values to adjust test behaviour
# ============================================================

# How often rinetd receives SIGHUP (seconds)
SIGHUP_INTERVAL = 15

# Extra (decoy) forwarding rules that are added/removed on each reload cycle
EXTRA_RULES_COUNT = 20       # Initial number of extra (decoy) rules
EXTRA_RULES_CHANGE = 2       # Rules removed AND added per reload

# Status / stats settings
STATUS_INTERVAL = 10         # Write JSON status file every N seconds
STATS_LOG_INTERVAL = 10      # Log stats to stderr every N seconds

# Buffer pool settings
POOL_MIN_FREE = 16
POOL_MAX_FREE = 32
POOL_TRIM_DELAY = 1000       # milliseconds

# Per-rule connect timeout: random value drawn from this range (seconds)
CONNECT_TIMEOUT_MIN = 5
CONNECT_TIMEOUT_MAX = 30

# Test duration
DEFAULT_STRESS_DURATION = 90  # seconds
QUICK_STRESS_DURATION = 20    # seconds for the "quick" parametrize variant

# IP addresses used for port allocation (all within 127.0.0.0/8 on Linux)
LISTEN_IP = "127.0.0.2"       # rinetd listeners for test pairs
BACKEND_IP = "127.0.0.3"      # backend echo servers
EXTRA_LISTEN_IP = "127.0.0.5" # rinetd listeners for decoy rules (no test clients)
EXTRA_BACKEND_IP = "127.0.0.6"# decoy backend address (no server running here)

# Port bases: actual port = base + pair_id / extra_id
PAIR_BASE_PORT = 20000
EXTRA_BASE_PORT = 45000

# Maximum transfer size per individual echo exchange (bytes).
# Kept below typical loopback socket buffer to avoid a send/recv deadlock on
# a half-duplex persistent connection where the client sends all before reading.
MAX_TRANSFER_SIZE = 256 * 1024  # 256 KB

# Noise address ranges used for random allow/deny ACL entries (non-test ranges)
_NOISE_RANGES = [
    "10.0.0.*", "10.1.*", "10.2.0.*",
    "192.168.0.*", "192.168.1.*", "192.168.100.*",
    "172.16.*", "172.17.*",
    "1.2.3.*", "4.5.6.*", "7.8.9.*",
    "203.0.113.*", "198.51.100.*",
]


# ============================================================
# ACL helpers
# ============================================================

def _acl_legacy(rng: random.Random, always_allow=None, catchall_deny: bool = True) -> list:
    """
    Build a list of ``allow`` / ``deny`` lines for a legacy .conf rule block.

    Patterns in always_allow are inserted first so test clients are never
    blocked by subsequent noise.  0–4 random noise patterns from non-test
    address ranges follow.

    ``catchall_deny=True`` appends ``deny *`` as a final guard – suitable for
    per-rule blocks.  Set it to ``False`` for the *global* block, because
    rinetd's 4-pass ACL evaluates global-deny rules *before* per-rule-allow
    rules, so a global ``deny *`` would reject every connection regardless of
    any per-rule ``allow`` entries.
    """
    lines = []
    for pat in (always_allow or []):
        lines.append(f"allow {pat}")
    for pat in rng.sample(_NOISE_RANGES, rng.randint(0, min(4, len(_NOISE_RANGES)))):
        lines.append(f"{rng.choice(['allow', 'deny'])} {pat}")
    if catchall_deny:
        lines.append("deny *")
    return lines


def _acl_yaml(rng: random.Random, always_allow=None, catchall_deny: bool = True):
    """
    Build ``(allow_list, deny_list)`` tuples for a YAML ``access:`` section.

    ``catchall_deny`` controls whether ``"*"`` is appended to the deny list.
    Same reasoning as for ``_acl_legacy``: omit it in the global block to
    avoid blocking test clients at the global-deny pass.
    """
    allow = list(always_allow or [])
    deny = []
    for pat in rng.sample(_NOISE_RANGES, rng.randint(0, min(4, len(_NOISE_RANGES)))):
        if rng.choice((True, False)):
            allow.append(pat)
        else:
            deny.append(pat)
    if catchall_deny:
        deny.append("*")
    return allow, deny


# ============================================================
# Config writers
# ============================================================

def _write_legacy_config(
    config_path: str,
    rng: random.Random,
    pair_rules: list,
    extra_rules: list,
    status_file: str,
    log_file: str,
) -> None:
    """
    Write a rinetd legacy .conf file with all required directives.

    pair_rules are permanent across reload cycles; extra_rules change on each
    SIGHUP.  Both are lists of (listen_ip, listen_port, backend_ip, backend_port).

    Per-rule ACLs on pair rules always allow ``127.0.0.*`` first so test
    clients are never blocked.  Decoy rule ACLs are fully random.
    """
    lines = [
        f"logfile {log_file}",
        f"statusfile {status_file}",
        f"statusinterval {STATUS_INTERVAL}",
        "statusformat json",
        f"statsloginterval {STATS_LOG_INTERVAL}",
        f"pool-min-free {POOL_MIN_FREE}",
        f"pool-max-free {POOL_MAX_FREE}",
        f"pool-trim-delay {POOL_TRIM_DELAY}",
        "",
    ]
    # Global access rules – always allow test clients as a safety net.
    # catchall_deny=False: rinetd's 4-pass ACL runs global-deny BEFORE
    # per-rule-allow, so a global "deny *" would block all connections
    # even if per-rule blocks explicitly allow the client.
    lines += _acl_legacy(rng, always_allow=["127.0.0.*"], catchall_deny=False)
    lines.append("")

    for listen_ip, listen_port, backend_ip, backend_port in pair_rules:
        ct = rng.randint(CONNECT_TIMEOUT_MIN, CONNECT_TIMEOUT_MAX)
        lines.append(
            f"{listen_ip} {listen_port} {backend_ip} {backend_port}"
            f" [connect-timeout={ct}]"
        )
        # Per-rule ACL: must always permit test clients (127.x.x.x).
        # catchall_deny=False: rinetd pass 4 (per-rule deny) fires AFTER
        # pass 3 (per-rule allow) and independently of it, so "deny *"
        # would block 127.0.0.1 even though it matched "allow 127.0.0.*".
        lines += _acl_legacy(rng, always_allow=["127.0.0.*"], catchall_deny=False)
        lines.append("")

    for listen_ip, listen_port, backend_ip, backend_port in extra_rules:
        ct = rng.randint(CONNECT_TIMEOUT_MIN, CONNECT_TIMEOUT_MAX)
        lines.append(
            f"{listen_ip} {listen_port} {backend_ip} {backend_port}"
            f" [connect-timeout={ct}]"
        )
        # Decoy rules: fully random ACLs (no test clients connect here)
        lines += _acl_legacy(rng, always_allow=None)
        lines.append("")

    with open(config_path, "w") as fh:
        fh.write("\n".join(lines) + "\n")


def _write_yaml_config(
    config_path: str,
    rng: random.Random,
    pair_rules: list,
    extra_rules: list,
    status_file: str,
    log_file: str,
) -> None:
    """
    Write a rinetd YAML configuration file equivalent to ``_write_legacy_config``.

    Rule names are derived from the listen port (e.g. ``pair-20000``,
    ``extra-45007``) which guarantees uniqueness across reload cycles since
    port numbers are assigned monotonically and never reused.
    """
    # catchall_deny=False: same reasoning as _write_legacy_config – global
    # deny rules fire before per-rule allow rules in rinetd's 4-pass ACL.
    g_allow, g_deny = _acl_yaml(rng, always_allow=["127.0.0.*"], catchall_deny=False)

    lines = [
        "global:",
        f"  log_file: {log_file}",
        f"  stats_log_interval: {STATS_LOG_INTERVAL}",
        f"  pool_min_free: {POOL_MIN_FREE}",
        f"  pool_max_free: {POOL_MAX_FREE}",
        f"  pool_trim_delay: {POOL_TRIM_DELAY}",
        "  status:",
        "    enabled: true",
        f"    file: {status_file}",
        f"    interval: {STATUS_INTERVAL}",
        "    format: json",
    ]

    if g_allow or g_deny:
        lines.append("  access:")
        if g_allow:
            lines.append("    allow:")
            for p in g_allow:
                lines.append(f'      - "{p}"')
        if g_deny:
            lines.append("    deny:")
            for p in g_deny:
                lines.append(f'      - "{p}"')

    lines.append("")
    lines.append("rules:")

    for listen_ip, listen_port, backend_ip, backend_port in pair_rules:
        ct = rng.randint(CONNECT_TIMEOUT_MIN, CONNECT_TIMEOUT_MAX)
        # catchall_deny=False: same independent-pass reasoning as legacy format.
        r_allow, r_deny = _acl_yaml(rng, always_allow=["127.0.0.*"], catchall_deny=False)
        lines += [
            f"  - name: pair-{listen_port}",
            f'    bind: "{listen_ip}:{listen_port}/tcp"',
            f'    connect: "{backend_ip}:{backend_port}/tcp"',
            f"    connect_timeout: {ct}",
        ]
        if r_allow or r_deny:
            lines.append("    access:")
            if r_allow:
                lines.append("      allow:")
                for p in r_allow:
                    lines.append(f'        - "{p}"')
            if r_deny:
                lines.append("      deny:")
                for p in r_deny:
                    lines.append(f'        - "{p}"')
        lines.append("")

    for listen_ip, listen_port, backend_ip, backend_port in extra_rules:
        ct = rng.randint(CONNECT_TIMEOUT_MIN, CONNECT_TIMEOUT_MAX)
        r_allow, r_deny = _acl_yaml(rng, always_allow=None)
        lines += [
            f"  - name: extra-{listen_port}",
            f'    bind: "{listen_ip}:{listen_port}/tcp"',
            f'    connect: "{backend_ip}:{backend_port}/tcp"',
            f"    connect_timeout: {ct}",
        ]
        if r_allow or r_deny:
            lines.append("    access:")
            if r_allow:
                lines.append("      allow:")
                for p in r_allow:
                    lines.append(f'        - "{p}"')
            if r_deny:
                lines.append("      deny:")
                for p in r_deny:
                    lines.append(f'        - "{p}"')
        lines.append("")

    with open(config_path, "w") as fh:
        fh.write("\n".join(lines) + "\n")


# ============================================================
# Reload thread
# ============================================================

def _reload_worker(
    proc: subprocess.Popen,
    config_path: str,
    write_fn,
    pair_rules: list,
    initial_extra_rules: list,
    status_file: str,
    log_file: str,
    stop_event: threading.Event,
) -> int:
    """
    Background thread body: every SIGHUP_INTERVAL seconds, mutate the extra
    rules pool, rewrite the config file with ``write_fn``, then send SIGHUP.

    pair_rules are never modified – they remain in every config revision.
    On each cycle exactly EXTRA_RULES_CHANGE decoy rules are removed at
    random and the same number of fresh ones (with new ports) are added.

    Returns the number of SIGHUP signals successfully delivered.
    """
    # Dedicated RNG: never shared with any other thread
    rng = random.Random(0xDEADBEEF)
    extra_rules = list(initial_extra_rules)
    # next_id starts after the initial pool; used to allocate new unique ports
    next_id = EXTRA_RULES_COUNT
    reload_count = 0

    while not stop_event.wait(timeout=SIGHUP_INTERVAL):
        if proc.poll() is not None:
            break

        # Remove a random subset of decoy rules
        for _ in range(min(EXTRA_RULES_CHANGE, len(extra_rules))):
            extra_rules.pop(rng.randrange(len(extra_rules)))

        # Add fresh decoy rules (ports keep increasing, so names stay unique)
        for _ in range(EXTRA_RULES_CHANGE):
            port = EXTRA_BASE_PORT + next_id
            extra_rules.append((EXTRA_LISTEN_IP, port, EXTRA_BACKEND_IP, port))
            next_id += 1

        try:
            write_fn(
                config_path,
                rng,
                pair_rules,
                extra_rules,
                status_file,
                log_file,
            )
            if proc.poll() is None:
                proc.send_signal(signal.SIGHUP)
                reload_count += 1
        except OSError:
            # Transient I/O error on config rewrite; retry next cycle
            pass

    return reload_count


# ============================================================
# Persistent-connection client worker
# ============================================================

def _client_worker(pair_id: int, listen_ip: str, listen_port: int, deadline: float) -> dict:
    """
    Establish ONE persistent TCP connection and run sequential echo transfers
    until ``deadline``.

    The connection is intentionally kept alive across all SIGHUP reload events
    to verify that rinetd does not disrupt existing TCP sessions.  Any
    connection failure is treated as a hard error (no retry logic), which
    would cause the test to fail.

    Each transfer sends a random payload and verifies the echo reply using
    ``SeededRandomStream`` for deterministic data generation and verification.
    """
    rng = random.Random(pair_id * 0x1337 + 7)
    ok = 0

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(DEFAULT_TIMEOUT)
            sock.connect((listen_ip, listen_port))

            while time.time() < deadline:
                size, chunk_size = random_transfer_params(
                    "tcp", rng, max_size=MAX_TRANSFER_SIZE
                )
                seed = rng.randint(0, 2**32 - 1)

                # Send the full transfer
                stream = SeededRandomStream(seed, size)
                bytes_sent = 0
                while bytes_sent < size:
                    chunk = stream.read(chunk_size)
                    if not chunk:
                        break
                    sock.sendall(chunk)
                    bytes_sent += len(chunk)

                # Receive and verify the echoed bytes
                verify = SeededRandomStream(seed, size)
                bytes_rcvd = 0
                while bytes_rcvd < size:
                    chunk = recv_all(sock, min(chunk_size, size - bytes_rcvd))
                    expected = verify.read(len(chunk))
                    if chunk != expected:
                        return {
                            "success": False,
                            "transfers_ok": ok,
                            "message": (
                                f"pair {pair_id}: data mismatch at"
                                f" byte {bytes_rcvd} of transfer {ok}"
                            ),
                        }
                    bytes_rcvd += len(chunk)

                ok += 1

    except socket.timeout:
        return {
            "success": False,
            "transfers_ok": ok,
            "message": f"pair {pair_id}: socket timeout after {ok} transfers",
        }
    except OSError as exc:
        return {
            "success": False,
            "transfers_ok": ok,
            "message": f"pair {pair_id}: OS error after {ok} transfers: {exc}",
        }

    return {"success": True, "transfers_ok": ok, "message": None}


# ============================================================
# Shared test body
# ============================================================

def _run_sighup_stress_test(
    rinetd_path: str,
    num_pairs: int,
    is_quick: bool,
    tmp_path,
    write_fn,
    config_ext: str,
) -> None:
    """
    Core SIGHUP stress test implementation shared by both config-format variants.

    ``write_fn`` is either ``_write_legacy_config`` or ``_write_yaml_config``.
    ``config_ext`` is ``"conf"`` or ``"yaml"`` (used to name the config file so
    rinetd picks the correct parser).
    """
    stress_duration = (
        QUICK_STRESS_DURATION
        if (is_quick or os.environ.get("STRESS_DURATION") is None and is_quick)
        else int(os.environ.get("STRESS_DURATION", DEFAULT_STRESS_DURATION))
    )
    # Allow env override for either variant
    if "STRESS_DURATION" in os.environ:
        stress_duration = int(os.environ["STRESS_DURATION"])

    soft, _ = get_file_limit()
    if num_pairs * 4 + 100 > soft * 0.8:
        pytest.skip(
            f"Insufficient file descriptors: need ~{num_pairs * 4 + 100},"
            f" have {soft}"
        )

    status_file = str(tmp_path / "status.json")
    log_file = str(tmp_path / "rinetd.log")
    config_file = str(tmp_path / f"rinetd_stress.{config_ext}")
    rng = random.Random(42)

    servers = []
    pair_rules = []
    proc = None

    try:
        # Phase 1: start one backend echo server per pair
        for i in range(num_pairs):
            port = PAIR_BASE_PORT + i
            srv = TcpEchoServer(host=BACKEND_IP, port=port)
            srv.start()
            if not srv.wait_ready(timeout=10):
                pytest.fail(f"Backend server {i} failed to start within 10s")
            servers.append(srv)
            pair_rules.append((LISTEN_IP, port, BACKEND_IP, port))

        # Phase 2: build initial decoy rule set
        initial_extra = [
            (EXTRA_LISTEN_IP, EXTRA_BASE_PORT + i, EXTRA_BACKEND_IP, EXTRA_BASE_PORT + i)
            for i in range(EXTRA_RULES_COUNT)
        ]

        # Phase 3: write config and start rinetd
        write_fn(config_file, rng, pair_rules, initial_extra, status_file, log_file)
        proc = subprocess.Popen(
            [rinetd_path, "-f", "-c", config_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        time.sleep(0.3)
        if proc.poll() is not None:
            _, stderr = proc.communicate()
            pytest.fail(f"rinetd failed to start:\n{stderr}")

        for listen_ip, listen_port, _, _ in pair_rules:
            if not wait_for_port(listen_port, host=listen_ip, timeout=15):
                pytest.fail(
                    f"rinetd listen port {listen_ip}:{listen_port}"
                    f" did not open within 15s"
                )

        # Phase 4: start SIGHUP reload thread
        stop_event = threading.Event()
        reload_count_box = [0]

        def _reload_body():
            reload_count_box[0] = _reload_worker(
                proc=proc,
                config_path=config_file,
                write_fn=write_fn,
                pair_rules=pair_rules,
                initial_extra_rules=initial_extra,
                status_file=status_file,
                log_file=log_file,
                stop_event=stop_event,
            )

        reload_thread = threading.Thread(target=_reload_body, daemon=True)
        reload_thread.start()

        # Phase 5: run persistent-connection clients in parallel
        deadline = time.time() + stress_duration

        print(f"\n{'='*70}")
        print(
            f"Stress SIGHUP ({config_ext}): {num_pairs} pairs,"
            f" {stress_duration}s, SIGHUP every {SIGHUP_INTERVAL}s"
        )
        print(
            f"  Extra decoy rules: {EXTRA_RULES_COUNT}"
            f" (±{EXTRA_RULES_CHANGE}/reload)"
        )
        print(
            f"  Pool: min_free={POOL_MIN_FREE} max_free={POOL_MAX_FREE}"
            f" trim_delay={POOL_TRIM_DELAY}ms"
        )
        print(
            f"  Connect timeout: {CONNECT_TIMEOUT_MIN}–{CONNECT_TIMEOUT_MAX}s"
            f" per rule"
        )
        print(f"{'='*70}")

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_pairs) as executor:
            futures = {
                executor.submit(
                    _client_worker, i, LISTEN_IP, PAIR_BASE_PORT + i, deadline
                ): i
                for i in range(num_pairs)
            }
            for future in concurrent.futures.as_completed(futures):
                pair_id = futures[future]
                try:
                    results.append(future.result())
                except Exception as exc:
                    results.append({
                        "success": False,
                        "transfers_ok": 0,
                        "message": f"pair {pair_id} raised exception: {exc}",
                    })

        # Phase 6: stop reload thread
        stop_event.set()
        reload_thread.join(timeout=SIGHUP_INTERVAL + 5)

        # Phase 7: rinetd must still be alive
        assert proc.poll() is None, "rinetd crashed during stress test"

        # Phase 8: status file must exist and be valid JSON (if interval has elapsed)
        if os.path.exists(status_file):
            with open(status_file, "r") as fh:
                status_data = json.load(fh)
            assert "connections" in status_data, "Status JSON missing 'connections'"
            assert "traffic" in status_data, "Status JSON missing 'traffic'"
        elif stress_duration >= STATUS_INTERVAL:
            pytest.fail(
                f"Status file not written after {stress_duration}s"
                f" (statusinterval={STATUS_INTERVAL}s)"
            )

        # Phase 9: report and validate
        total_ok = sum(r.get("transfers_ok", 0) for r in results)
        failed_pairs = [r for r in results if not r["success"]]

        print(f"\n{'='*70}")
        print(
            f"Results ({config_ext}): {num_pairs} pairs,"
            f" {reload_count_box[0]} SIGHUP reloads"
        )
        print(f"  Transfers completed: {total_ok}")
        print(f"  Failed pairs:        {len(failed_pairs)}/{num_pairs}")
        for fp in failed_pairs[:5]:
            print(f"    -> {fp['message']}")
        print(f"{'='*70}")

        assert total_ok > 0, "No transfers completed successfully"

        # Existing TCP connections must survive SIGHUP: zero pair failures allowed
        assert len(failed_pairs) == 0, (
            f"{len(failed_pairs)} pair(s) failed – persistent TCP connections"
            f" must not be disrupted by SIGHUP reload:\n"
            + "\n".join(f"  {r['message']}" for r in failed_pairs)
        )

    finally:
        if proc is not None:
            if proc.poll() is None:
                proc.terminate()
            try:
                stdout, stderr = proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()
            if stdout:
                print(f"\n[rinetd stdout]:\n{stdout}")
            if stderr:
                # Truncate to avoid overwhelming pytest output
                print(f"\n[rinetd stderr (first 4 KB)]:\n{stderr[:4096]}")

        for srv in servers:
            srv.stop()


# ============================================================
# Test functions – one per config format
# ============================================================

@pytest.mark.expect_rinetd_errors
@pytest.mark.reload
@pytest.mark.parametrize("num_pairs,is_quick", [
    pytest.param(10, True, marks=pytest.mark.quick),
    pytest.param(50, False),
    pytest.param(100, False),
    pytest.param(500, False, marks=pytest.mark.slow),
])
def test_stress_sighup_reload_legacy(rinetd_path, num_pairs, is_quick, tmp_path):
    """
    SIGHUP stress test using legacy .conf configuration format.

    See module docstring and _run_sighup_stress_test for full description.
    """
    _run_sighup_stress_test(
        rinetd_path, num_pairs, is_quick, tmp_path,
        _write_legacy_config, "conf",
    )


@pytest.mark.expect_rinetd_errors
@pytest.mark.reload
@pytest.mark.parametrize("num_pairs,is_quick", [
    pytest.param(10, True, marks=pytest.mark.quick),
    pytest.param(50, False),
    pytest.param(100, False),
    pytest.param(500, False, marks=pytest.mark.slow),
])
def test_stress_sighup_reload_yaml(rinetd_path, num_pairs, is_quick, tmp_path):
    """
    SIGHUP stress test using YAML configuration format.

    See module docstring and _run_sighup_stress_test for full description.
    """
    _run_sighup_stress_test(
        rinetd_path, num_pairs, is_quick, tmp_path,
        _write_yaml_config, "yaml",
    )
