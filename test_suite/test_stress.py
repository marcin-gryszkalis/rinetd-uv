import pytest
import socket
import concurrent.futures
import time
import random
import os
from .utils import (
    get_free_port, wait_for_port, run_parallel_pairs,
    random_transfer_params, get_file_limit
)

INACTIVE_WAIT = 60

# Duration can be overridden via environment variable
DEFAULT_STRESS_DURATION = 120  # 1 minute default
QUICK_STRESS_DURATION = 10    # 10 seconds for quick tests

# Grace period after deadline for in-progress transfers to complete
COMPLETION_GRACE_PERIOD = 300


def get_stress_duration(is_quick=False):
    """Get stress duration from environment or use defaults."""
    env_duration = os.environ.get('STRESS_DURATION')
    if env_duration:
        return int(env_duration)
    return QUICK_STRESS_DURATION if is_quick else DEFAULT_STRESS_DURATION


def test_simple():
    print("Simple test running...")
    assert True


@pytest.mark.expect_rinetd_errors
@pytest.mark.parametrize("num_pairs,is_quick", [
    pytest.param(10, True, marks=pytest.mark.quick),
    pytest.param(50, False),
    pytest.param(100, False),
    pytest.param(500, False, marks=pytest.mark.slow),
    pytest.param(1000, False, marks=pytest.mark.slow),
])
def test_randomized_stress(rinetd, num_pairs, is_quick, tmp_path):
    """
    Multimodal stress test with fully randomized parameters per pair.

    Architecture: Each pair gets:
    - Its own dedicated backend server (no contention!)
    - Random protocol combination (tcp/udp/unix for both listen and connect)
    - Random transfer size and chunk size (log-scale distribution)
    - Random mode (echo, upload, download, upload_sha256, download_sha256)

    This tests rinetd's ability to multiplex many heterogeneous connections
    simultaneously - the real-world use case.

    Example with num_pairs=5:
        Pair 0: tcp->udp, 1KB, 512B chunks, echo mode
        Pair 1: udp->udp, 64KB, 16KB chunks, upload_sha256 mode
        Pair 2: unix->tcp, 1MB, 1KB chunks, download mode
        Pair 3: tcp->tcp, 100KB, 64KB chunks, echo mode
        Pair 4: unix->unix, 10KB, 1KB chunks, download_sha256 mode

    All run simultaneously for the stress duration.
    """
    # All protocol combinations supported by rinetd-uv with 1:1 architecture
    # Note: Mixed protocol forwarding (tcp->udp, unix->udp) is not supported
    ALL_PROTOCOLS = [
        ("tcp", "tcp"),
        ("tcp", "unix"),
        ("udp", "udp"),
        ("unix", "tcp"),
        ("unix", "unix"),
    ]

    # All transfer modes
    ALL_MODES = [
        "echo",
        "upload",
        "download",
        "upload_sha256",
        "download_sha256",
    ]

    # Check file descriptor limits
    # Estimate: each pair needs ~4 FDs (server listen, server accept, client, rinetd)
    soft, hard = get_file_limit()
    estimated_fds = num_pairs * 4
    if estimated_fds > soft * 0.8:  # Leave 20% margin
        pytest.skip(f"Insufficient file descriptors: need ~{estimated_fds}, have {soft}")

    stress_duration = get_stress_duration(is_quick)
    rng = random.Random(42)  # Reproducible randomization

    # Generate random configuration for each pair
    pairs_config = []
    for i in range(num_pairs):
        # Random protocol combination
        listen_proto, connect_proto = rng.choice(ALL_PROTOCOLS)

        # Random mode (filter based on BACKEND protocol compatibility)
        # Backend server determines what modes are available
        if connect_proto == "udp":
            # UDP backends only support echo and sha256 modes
            mode = rng.choice(["echo", "upload_sha256", "download_sha256"])
        else:
            # TCP/Unix backends support all modes
            mode = rng.choice(ALL_MODES)

        # Random transfer parameters
        # Pick the more restrictive protocol for size limits
        proto_for_limits = "udp" if (listen_proto == "udp" or connect_proto == "udp") else "tcp"
        size, chunk_size = random_transfer_params(proto_for_limits, rng)

        # UDP + SHA256: reserve 32 bytes for hash
        if (listen_proto == "udp" or connect_proto == "udp") and mode in ("upload_sha256", "download_sha256"):
            if chunk_size > 65507 - 32:
                chunk_size = 65507 - 32

        pairs_config.append({
            "listen_proto": listen_proto,
            "connect_proto": connect_proto,
            "mode": mode,
            "size": size,
            "chunk_size": chunk_size,
            "seed": i + int(time.time()),
        })

    print(f"\n{'='*70}")
    print(f"Stress test: {num_pairs} pairs, {stress_duration}s duration")
    print(f"Protocol distribution:")
    proto_counts = {}
    for cfg in pairs_config:
        key = f"{cfg['listen_proto']}->{cfg['connect_proto']}"
        proto_counts[key] = proto_counts.get(key, 0) + 1
    for proto, count in sorted(proto_counts.items()):
        print(f"  {proto}: {count}")
    print(f"Mode distribution:")
    mode_counts = {}
    for cfg in pairs_config:
        mode_counts[cfg['mode']] = mode_counts.get(cfg['mode'], 0) + 1
    for mode, count in sorted(mode_counts.items()):
        print(f"  {mode}: {count}")
    print(f"{'='*70}\n")

    # Run all pairs in parallel
    results = run_parallel_pairs(
        pairs_config=pairs_config,
        rinetd_starter=rinetd,
        duration=stress_duration,
        tmp_path=tmp_path,
    )

    # Check results
    failures = [r for r in results if not r["success"]]

    if failures:
        print(f"\n{'='*70}")
        print(f"FAILURES: {len(failures)}/{num_pairs}")
        for i, f in enumerate(failures[:10]):  # Show first 10
            print(f"  {i+1}. {f['message']}")
        print(f"{'='*70}\n")

    # Allow up to 1% failure rate for very large stress tests
    # (transient issues can occur at scale)
    max_failures = max(1, num_pairs // 100) if num_pairs >= 100 else 0

    assert len(failures) <= max_failures, \
        f"Too many failures: {len(failures)}/{num_pairs} (max {max_failures})"


@pytest.mark.quick
def test_randomization_sanity():
    """Verify that random_transfer_params produces sensible values."""
    rng = random.Random(42)

    for proto in ["tcp", "udp", "unix"]:
        sizes = []
        chunks = []
        for _ in range(100):
            size, chunk = random_transfer_params(proto, rng)
            sizes.append(size)
            chunks.append(chunk)

            # Verify constraints
            assert size >= 1, f"Size too small: {size}"
            assert chunk >= 1, f"Chunk too small: {chunk}"
            assert chunk <= size or size == 0, f"Chunk {chunk} > size {size}"

            if proto == "udp":
                assert size <= 65507, f"UDP size too large: {size}"
                assert chunk <= 65507, f"UDP chunk too large: {chunk}"

        # Verify we get a good distribution (not all same values)
        assert len(set(sizes)) > 10, f"Not enough size variety for {proto}"
        assert len(set(chunks)) > 10, f"Not enough chunk variety for {proto}"
