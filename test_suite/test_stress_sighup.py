"""
Stress test with periodic SIGHUP reloads and dynamic config changes.

Tests two key properties of rinetd-uv under simultaneous load:
  1. Existing TCP connections are NOT disrupted by SIGHUP config reload.
     Permanent pair connections use a single persistent TCP connection for the
     full test duration; any mid-test connection drop is a hard failure.
  2. Every forwarding rule carries real traffic: each cycling rule has a
     dedicated backend echo server and a client running for a randomised
     duration that straddles the SIGHUP interval.  Roughly half of cycling
     transfers finish before the next reload (testing clean rule removal) and
     half survive across it (testing that active connections are not severed).

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

# Number of cycling rules in the initial config pool
EXTRA_RULES_COUNT = 20
# Rules added (and swept) per reload cycle
EXTRA_RULES_CHANGE = 2

# Transfer duration for cycling rules expressed as a fraction of SIGHUP_INTERVAL.
# The range straddles 1.0 so roughly half of cycling transfers finish before
# the next SIGHUP and half survive across it.
CYCLE_TRANSFER_MIN_RATIO = 0.6
CYCLE_TRANSFER_MAX_RATIO = 1.6

# Seconds to wait after all client sockets close before sending SIGTERM to
# rinetd.  Pair workers close their connections exactly at the test deadline;
# rinetd needs one or two event-loop iterations to detect the FINs and write
# the done-* log entries.  Without this window the opened==done check in
# _validate_event_log races against SIGTERM.
CONNECTION_DRAIN_TIME = 60

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
LISTEN_IP = "127.0.0.2"        # rinetd listeners for permanent pairs
BACKEND_IP = "127.0.0.3"       # backend echo servers for permanent pairs
EXTRA_LISTEN_IP = "127.0.0.5"  # rinetd listeners for cycling rules
EXTRA_BACKEND_IP = "127.0.0.6" # backend echo servers for cycling rules

# Port bases: actual port = base + pair_id / rule_id
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
# Cycling rule management
# ============================================================

class ActiveCycleRule:
    """
    A forwarding rule that carries real traffic throughout its lifetime.

    Each instance owns a TcpEchoServer backend and a concurrent.futures.Future
    for its client worker (_client_worker).  The rule stays in the rinetd
    config until the client worker completes; it is swept out on the next
    reload cycle after completion, so no active connection is ever severed
    by config removal.
    """
    __slots__ = ("rule_id", "listen_ip", "listen_port", "backend_ip",
                 "backend_port", "server", "future")

    def __init__(self, rule_id: int, listen_ip: str, listen_port: int,
                 backend_ip: str, backend_port: int):
        self.rule_id = rule_id
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.backend_ip = backend_ip
        self.backend_port = backend_port
        self.server = TcpEchoServer(host=backend_ip, port=backend_port)
        self.future = None

    @property
    def rule(self) -> tuple:
        return (self.listen_ip, self.listen_port, self.backend_ip, self.backend_port)


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
# Log validation
# ============================================================

def _parse_event_log(log_file: str) -> dict:
    """
    Parse a rinetd event log (tab-separated, non-common format) and return a
    dict with event type → count and a separate list of (bytesIn, event) tuples
    for every ``done-*`` entry.

    Log columns (9, tab-separated):
      timestamp  remote_addr  fromHost  fromPort  toHost  toPort  bytesIn  bytesOut  event
    """
    counts: dict = {}
    done_bytes: list = []
    with open(log_file) as fh:
        for line in fh:
            fields = line.rstrip("\n").split("\t")
            if len(fields) < 9:
                continue
            event = fields[8]
            counts[event] = counts.get(event, 0) + 1
            if event.startswith("done-"):
                try:
                    done_bytes.append(int(fields[6]))
                except ValueError:
                    pass
    return {"counts": counts, "done_bytes": done_bytes}


def _validate_event_log(log_file: str, min_data_connections: int) -> None:
    """
    Assert that the event log is internally consistent.

    Invariants checked:
    - ``opened`` == ``done``   (no leaked connections)
    - ``done`` with bytesIn > 0 >= min_data_connections
      (at least one real connection per permanent pair; cycling connections
      add more, so we only enforce a lower bound)
    - zero ``denied`` / ``not-allowed`` entries   (ACL must not block test clients)
    - zero ``local-connect-failed`` entries   (all backends were up)
    """
    if not os.path.exists(log_file):
        pytest.fail(f"Event log not written: {log_file}")

    parsed = _parse_event_log(log_file)
    counts = parsed["counts"]
    done_bytes = parsed["done_bytes"]

    opened = counts.get("opened", 0)
    done = counts.get("done-local-closed", 0) + counts.get("done-remote-closed", 0)
    failed = counts.get("local-connect-failed -", 0)
    denied = counts.get("denied", 0) + counts.get("not-allowed", 0)
    done_with_bytes = sum(1 for b in done_bytes if b > 0)

    errors = []
    if opened != done:
        errors.append(
            f"Unbalanced log entries: {opened} 'opened' but {done} 'done-*'"
            " (possible connection leak or incomplete shutdown)"
        )
    if done_with_bytes < min_data_connections:
        errors.append(
            f"Expected at least {min_data_connections} 'done-*' entries with"
            f" bytesIn > 0, got {done_with_bytes}"
        )
    if failed > 0:
        errors.append(
            f"{failed} 'local-connect-failed' entries: backends were unreachable"
        )
    if denied > 0:
        errors.append(
            f"{denied} 'denied/not-allowed' entries: ACL blocked test clients"
        )

    if errors:
        pytest.fail(
            "Event log validation failed:\n"
            + "\n".join(f"  {e}" for e in errors)
            + f"\n  Full event counts: {counts}"
        )


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

    pair_rules are permanent across reload cycles; extra_rules are the current
    set of active cycling rules (changes on each reload).  Both are lists of
    (listen_ip, listen_port, backend_ip, backend_port).

    Per-rule ACLs on pair rules always allow ``127.0.0.*`` first so test
    clients are never blocked.  Cycling rule ACLs are also client-permissive
    since they carry real traffic from the same address range.
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
        # Cycling rules also carry real traffic from 127.0.0.x clients.
        lines += _acl_legacy(rng, always_allow=["127.0.0.*"], catchall_deny=False)
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
        # Cycling rules carry real traffic; always allow test clients.
        r_allow, r_deny = _acl_yaml(rng, always_allow=["127.0.0.*"], catchall_deny=False)
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
# Persistent-connection client worker (used for both permanent pairs
# and cycling rules)
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
# Cycle manager – manages cycling rules with real traffic
# ============================================================

def _cycle_manager(
    proc: subprocess.Popen,
    config_path: str,
    write_fn,
    pair_rules: list,
    status_file: str,
    log_file: str,
    stop_event: threading.Event,
    active_cycling: list,
    executor: concurrent.futures.ThreadPoolExecutor,
    test_deadline: float,
    rng_seed: int = 0xDEADBEEF,
) -> tuple:
    """
    Background thread: on each SIGHUP_INTERVAL, sweep finished cycling rules,
    add fresh ones with real backend servers and client workers, then rewrite
    the config and send SIGHUP.

    active_cycling is a mutable list of ActiveCycleRule objects owned
    exclusively by this thread after handoff from the main thread.

    Rules are removed from the config only after their client finishes, so
    no active connection is ever severed by a reload.  Newly added rules have
    their client worker started only after wait_for_port confirms rinetd is
    listening on the new port, avoiding spurious connection failures.

    Returns (reload_count, cycling_results) where cycling_results is a list
    of result dicts (same format as _client_worker) from all completed cycling
    clients.
    """
    rng = random.Random(rng_seed)
    # IDs 0..EXTRA_RULES_COUNT-1 already used by the initial cycling pool
    next_id = EXTRA_RULES_COUNT
    reload_count = 0
    cycling_results = []

    while not stop_event.wait(timeout=SIGHUP_INTERVAL):
        if proc.poll() is not None:
            break

        # --- sweep: collect finished cycling rules ---
        done = [ar for ar in active_cycling
                if ar.future is not None and ar.future.done()]
        for ar in done:
            active_cycling.remove(ar)
            try:
                cycling_results.append(ar.future.result())
            except Exception as exc:
                cycling_results.append({
                    "success": False,
                    "transfers_ok": 0,
                    "message": f"rule {ar.rule_id}: exception: {exc}",
                })
            ar.server.stop()

        # --- grow: add EXTRA_RULES_CHANGE new cycling rules ---
        new_rules = []
        for _ in range(EXTRA_RULES_CHANGE):
            port = EXTRA_BASE_PORT + next_id
            ar = ActiveCycleRule(next_id, EXTRA_LISTEN_IP, port, EXTRA_BACKEND_IP, port)
            ar.server.start()
            if not ar.server.wait_ready(timeout=5):
                ar.server.stop()
                continue
            active_cycling.append(ar)
            new_rules.append(ar)
            next_id += 1

        # --- reload: rewrite config and send SIGHUP ---
        try:
            write_fn(
                config_path, rng, pair_rules,
                [ar.rule for ar in active_cycling],
                status_file, log_file,
            )
            if proc.poll() is None:
                proc.send_signal(signal.SIGHUP)
                reload_count += 1
        except OSError:
            pass

        # --- connect: wait for new listen ports, then start client workers ---
        for ar in new_rules:
            if not wait_for_port(ar.listen_port, host=ar.listen_ip, timeout=10):
                cycling_results.append({
                    "success": False,
                    "transfers_ok": 0,
                    "message": (
                        f"rule {ar.rule_id}: listen port {ar.listen_ip}:{ar.listen_port}"
                        f" never opened after SIGHUP"
                    ),
                })
                active_cycling.remove(ar)
                ar.server.stop()
                continue

            duration = SIGHUP_INTERVAL * rng.uniform(
                CYCLE_TRANSFER_MIN_RATIO, CYCLE_TRANSFER_MAX_RATIO
            )
            # Cap at test_deadline so workers don't outlive the test
            ar_deadline = min(time.time() + duration, test_deadline - 5)
            ar.future = executor.submit(
                _client_worker, ar.rule_id, ar.listen_ip, ar.listen_port, ar_deadline
            )

    # --- cleanup: drain remaining cycling workers ---
    for ar in list(active_cycling):
        if ar.future is not None:
            try:
                cycling_results.append(ar.future.result(timeout=DEFAULT_TIMEOUT))
            except concurrent.futures.TimeoutError:
                cycling_results.append({
                    "success": False,
                    "transfers_ok": 0,
                    "message": f"rule {ar.rule_id}: worker timed out during cleanup",
                })
            except Exception as exc:
                cycling_results.append({
                    "success": False,
                    "transfers_ok": 0,
                    "message": f"rule {ar.rule_id}: exception during cleanup: {exc}",
                })
        ar.server.stop()

    return reload_count, cycling_results


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
    # Each connection needs ~4 FDs; cycling backend servers add one listener each
    estimated_fds = (num_pairs + EXTRA_RULES_COUNT) * 5 + 100
    if estimated_fds > soft * 0.8:
        pytest.skip(
            f"Insufficient file descriptors: need ~{estimated_fds},"
            f" have {soft}"
        )

    status_file = str(tmp_path / "status.json")
    log_file = str(tmp_path / "rinetd.log")
    config_file = str(tmp_path / f"rinetd_stress.{config_ext}")
    rng = random.Random(42)

    # Permanent backend servers (one per pair); kept alive for the whole test
    servers = []
    pair_rules = []
    proc = None

    try:
        # Phase 1: start one permanent backend echo server per pair
        for i in range(num_pairs):
            port = PAIR_BASE_PORT + i
            srv = TcpEchoServer(host=BACKEND_IP, port=port)
            srv.start()
            if not srv.wait_ready(timeout=10):
                pytest.fail(f"Permanent backend server {i} failed to start within 10s")
            servers.append(srv)
            pair_rules.append((LISTEN_IP, port, BACKEND_IP, port))

        # Phase 2: create the initial cycling rule pool with real backend servers
        initial_cycling = []
        for i in range(EXTRA_RULES_COUNT):
            port = EXTRA_BASE_PORT + i
            ar = ActiveCycleRule(i, EXTRA_LISTEN_IP, port, EXTRA_BACKEND_IP, port)
            ar.server.start()
            if not ar.server.wait_ready(timeout=10):
                pytest.fail(f"Cycling backend server {i} failed to start within 10s")
            initial_cycling.append(ar)
            # Also register for finally-block cleanup (cycle manager stops them
            # too, but stop() is idempotent so double-stopping is harmless)
            servers.append(ar.server)

        # Phase 3: write initial config (pair rules + all initial cycling rules)
        write_fn(
            config_file, rng, pair_rules,
            [ar.rule for ar in initial_cycling],
            status_file, log_file,
        )
        proc = subprocess.Popen(
            [rinetd_path, "-f", "-c", config_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        rinetd_pid = proc.pid
        rinetd_stdout_path = str(tmp_path / f"rinetd-uv.{rinetd_pid}.stdout.txt")
        rinetd_stderr_path = str(tmp_path / f"rinetd-uv.{rinetd_pid}.stderr.txt")
        print(f"\n  rinetd PID {rinetd_pid}  stdout→{rinetd_stdout_path}  stderr→{rinetd_stderr_path}")
        time.sleep(0.3)
        if proc.poll() is not None:
            _, stderr = proc.communicate()
            pytest.fail(f"rinetd failed to start:\n{stderr}")

        # Phase 4: wait for all listen ports to open
        for listen_ip, listen_port, _, _ in pair_rules:
            if not wait_for_port(listen_port, host=listen_ip, timeout=15):
                pytest.fail(
                    f"rinetd listen port {listen_ip}:{listen_port}"
                    f" did not open within 15s"
                )
        for ar in initial_cycling:
            if not wait_for_port(ar.listen_port, host=ar.listen_ip, timeout=15):
                pytest.fail(
                    f"rinetd cycling port {ar.listen_ip}:{ar.listen_port}"
                    f" did not open within 15s"
                )

        # Phase 5: launch all client workers (permanent pairs + initial cycling)
        test_deadline = time.time() + stress_duration
        # Max concurrent workers: permanent pairs + initial cycling pool +
        # headroom for a couple of reload cycles worth of new workers
        max_workers = num_pairs + EXTRA_RULES_COUNT + EXTRA_RULES_CHANGE * 4

        print(f"\n{'='*70}")
        print(
            f"Stress SIGHUP ({config_ext}): {num_pairs} pairs"
            f" + {EXTRA_RULES_COUNT} cycling rules,"
            f" {stress_duration}s, SIGHUP every {SIGHUP_INTERVAL}s"
        )
        print(
            f"  Cycling transfer duration: "
            f"{CYCLE_TRANSFER_MIN_RATIO}–{CYCLE_TRANSFER_MAX_RATIO}"
            f" × {SIGHUP_INTERVAL}s"
            f" ({CYCLE_TRANSFER_MIN_RATIO * SIGHUP_INTERVAL:.0f}–"
            f"{CYCLE_TRANSFER_MAX_RATIO * SIGHUP_INTERVAL:.0f}s)"
        )
        print(
            f"  Cycling rules per reload: +{EXTRA_RULES_CHANGE} new"
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

        stop_event = threading.Event()
        cycle_result_box = [None]

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit permanent pair workers (run until overall test deadline)
            pair_futures = {
                executor.submit(
                    _client_worker, i, LISTEN_IP, PAIR_BASE_PORT + i, test_deadline
                ): i
                for i in range(num_pairs)
            }

            # Submit initial cycling workers (each with its own shorter deadline)
            rng_cycle = random.Random(0xCAFEBABE)
            for ar in initial_cycling:
                duration = SIGHUP_INTERVAL * rng_cycle.uniform(
                    CYCLE_TRANSFER_MIN_RATIO, CYCLE_TRANSFER_MAX_RATIO
                )
                ar_deadline = min(time.time() + duration, test_deadline - 5)
                ar.future = executor.submit(
                    _client_worker, ar.rule_id, ar.listen_ip, ar.listen_port, ar_deadline
                )

            # Phase 6: start cycle manager thread
            # It takes exclusive ownership of initial_cycling from this point
            def _cycle_body():
                cycle_result_box[0] = _cycle_manager(
                    proc=proc,
                    config_path=config_file,
                    write_fn=write_fn,
                    pair_rules=pair_rules,
                    status_file=status_file,
                    log_file=log_file,
                    stop_event=stop_event,
                    active_cycling=initial_cycling,
                    executor=executor,
                    test_deadline=test_deadline,
                )

            cycle_thread = threading.Thread(target=_cycle_body, daemon=True)
            cycle_thread.start()

            # Phase 7: collect permanent pair results
            pair_results = []
            for future in concurrent.futures.as_completed(pair_futures):
                pair_id = pair_futures[future]
                try:
                    pair_results.append(future.result())
                except Exception as exc:
                    pair_results.append({
                        "success": False,
                        "transfers_ok": 0,
                        "message": f"pair {pair_id} raised exception: {exc}",
                    })

            # Phase 8: stop cycle manager and wait for its cleanup to finish
            stop_event.set()
            cycle_thread.join(timeout=SIGHUP_INTERVAL + DEFAULT_TIMEOUT + 10)

        # executor.__exit__ waits for all submitted futures (cycling workers
        # that the cycle manager already drained in cleanup, so this is instant)

        # Phase 9: rinetd must still be alive before we terminate it
        assert proc.poll() is None, "rinetd crashed during stress test"

        # Pair workers just closed their sockets at test_deadline.  Give rinetd
        # time to process the incoming FINs and write done-* log entries before
        # SIGTERM halts the libuv loop mid-iteration (opened != done race).
        time.sleep(CONNECTION_DRAIN_TIME)

        # Phase 10: terminate rinetd so the event log is fully flushed
        proc.terminate()
        try:
            stdout, stderr = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
        proc = None

        with open(rinetd_stdout_path, "w") as fh:
            fh.write(stdout or "")
        with open(rinetd_stderr_path, "w") as fh:
            fh.write(stderr or "")
        if stdout:
            print(f"\n[rinetd stdout ({rinetd_stdout_path})]:\n{stdout}")
        if stderr:
            print(f"\n[rinetd stderr ({rinetd_stderr_path}, first 4 KB)]:\n{stderr[:4096]}")

        # Phase 11: extract cycling results
        reload_count, cycling_results = cycle_result_box[0] or (0, [])

        # Phase 12: status file must exist and be valid JSON (if interval has elapsed)
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

        # Phase 13: event log validation (rinetd is terminated, log is complete).
        # With cycling rules, done_with_bytes will be >= num_pairs (permanent
        # pairs always have one large connection; cycling connections add more).
        _validate_event_log(log_file, num_pairs)

        # Phase 14: report results
        pair_total_ok = sum(r.get("transfers_ok", 0) for r in pair_results)
        pair_failed = [r for r in pair_results if not r["success"]]
        cycling_total_ok = sum(r.get("transfers_ok", 0) for r in cycling_results)
        cycling_failed = [r for r in cycling_results if not r["success"]]

        print(f"\n{'='*70}")
        print(
            f"Results ({config_ext}): {num_pairs} permanent pairs,"
            f" {len(cycling_results)} cycling rules,"
            f" {reload_count} SIGHUP reloads"
        )
        print(f"  Permanent pair transfers:  {pair_total_ok}")
        print(f"  Cycling rule transfers:    {cycling_total_ok}")
        print(f"  Failed permanent pairs:    {len(pair_failed)}/{num_pairs}")
        print(f"  Failed cycling rules:      {len(cycling_failed)}/{len(cycling_results)}")
        for fp in (pair_failed + cycling_failed)[:5]:
            print(f"    -> {fp['message']}")
        print(f"{'='*70}")

        assert pair_total_ok > 0, "No permanent-pair transfers completed successfully"

        # Persistent connections must survive every SIGHUP
        assert len(pair_failed) == 0, (
            f"{len(pair_failed)} permanent pair(s) failed – persistent TCP connections"
            f" must not be disrupted by SIGHUP reload:\n"
            + "\n".join(f"  {r['message']}" for r in pair_failed)
        )

        # Cycling transfers must also succeed – both those that finish before a
        # SIGHUP and those that survive across one
        assert len(cycling_failed) == 0, (
            f"{len(cycling_failed)} cycling rule(s) failed:\n"
            + "\n".join(f"  {r['message']}" for r in cycling_failed)
        )

    finally:
        # Handles error paths where proc was not yet terminated above
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
