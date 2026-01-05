#!/usr/bin/env python3
"""
Test rinetd TCP forwarding with high number of parallel connections.
Tests concurrent HTTP requests and validates responses.

Usage:
    python3 test_parallel_connections.py [--host HOST] [--port PORT] [--connections N]
                                         [--resource URL:SHA256]

Examples:
    # Test with defaults (127.0.0.1:8080, 100 connections)
    python3 test_parallel_connections.py

    # Test with custom settings
    python3 test_parallel_connections.py --host 192.168.1.1 --port 9000 --connections 200

    # Stress test: keep connecting for 60 seconds with 50 parallel connections
    python3 test_parallel_connections.py --duration 60 --connections 50

    # Validate specific resource with SHA256 checksum
    python3 test_parallel_connections.py --resource /index.html:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

    # Test large file with appropriate timeout (1GB file needs longer timeout)
    python3 test_parallel_connections.py --resource /largefile:abc123... --timeout 300 --connections 5

Note: When testing large files:
  1. Timeout is per-request inactivity timeout (time between data chunks), not total download time
    - Small files (<1MB): default 10s is fine
    - Medium files (1-100MB): use --timeout 60
    - Large files (>100MB): use --timeout 300 or higher

  2. In duration mode, workers will complete their current download even after duration expires
    - With 10 workers and 1GB files, actual test time = duration + download_time
    - Use single batch mode (no --duration) for more predictable timing with large files
"""

import socket
import threading
import time
import sys
import argparse
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    print("Error: 'requests' library is required. Install it with: pip install requests")
    sys.exit(1)

# Default configuration
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
DEFAULT_CONNECTIONS = 100
DEFAULT_TIMEOUT = 10

# Test results
results = {
    'success': 0,
    'failed': 0,
    'errors': []
}
results_lock = threading.Lock()

# Debug: track active connections
active_connections = {}
active_connections_lock = threading.Lock()


def test_connection(conn_id, host, port, timeout, resource_path=None, expected_sha256=None):
    """Test a single HTTP connection through rinetd.

    Args:
        conn_id: Connection identifier
        host: Target host
        port: Target port
        timeout: Request timeout in seconds (socket inactivity timeout)
        resource_path: Optional resource path to fetch (e.g., '/index.html')
        expected_sha256: Optional expected SHA256 hash of the resource body
    """
    try:
        # Track this connection as active
        with active_connections_lock:
            active_connections[conn_id] = {'state': 'starting', 'time': time.time()}

        start_time = time.time()

        # Construct URL
        if resource_path:
            url = f"http://{host}:{port}{resource_path}"
        else:
            url = f"http://{host}:{port}/"

        with active_connections_lock:
            active_connections[conn_id]['state'] = 'requesting'

        # Make HTTP request using requests library
        # Note: timeout is socket inactivity timeout, not total request time
        # For chunked responses, this may hang if server doesn't close connection properly
        response = requests.get(url, timeout=timeout, stream=False)

        with active_connections_lock:
            active_connections[conn_id]['state'] = 'response_received'

        connect_time = time.time() - start_time

        # Check HTTP status
        if response.status_code != 200:
            error_msg = f"HTTP {response.status_code}"
            with results_lock:
                results['failed'] += 1
                results['errors'].append(error_msg)
            return {
                'id': conn_id,
                'success': False,
                'error': error_msg
            }

        # If resource validation is requested, verify SHA256
        if expected_sha256:
            with active_connections_lock:
                active_connections[conn_id]['state'] = 'hashing'

            actual_sha256 = hashlib.sha256(response.content).hexdigest()

            with active_connections_lock:
                active_connections[conn_id]['state'] = 'hash_complete'

            if actual_sha256 != expected_sha256:
                error_msg = f"SHA256 mismatch: expected {expected_sha256[:16]}..., got {actual_sha256[:16]}..."
                with results_lock:
                    results['failed'] += 1
                    results['errors'].append(error_msg)
                return {
                    'id': conn_id,
                    'success': False,
                    'error': error_msg
                }

        # Success
        with results_lock:
            results['success'] += 1

        with active_connections_lock:
            active_connections[conn_id]['state'] = 'completed'
            if conn_id in active_connections:
                del active_connections[conn_id]

        result = {
            'id': conn_id,
            'success': True,
            'connect_time': connect_time,
            'status_code': response.status_code,
            'response_length': len(response.content)
        }

        if expected_sha256:
            result['sha256_valid'] = True

        return result

    except requests.exceptions.Timeout:
        error_msg = 'Timeout'
        with results_lock:
            results['failed'] += 1
            results['errors'].append(error_msg)
        with active_connections_lock:
            if conn_id in active_connections:
                del active_connections[conn_id]
        return {
            'id': conn_id,
            'success': False,
            'error': error_msg
        }
    except requests.exceptions.ConnectionError as e:
        error_msg = f'Connection error: {str(e)}'
        with results_lock:
            results['failed'] += 1
            results['errors'].append(error_msg)
        with active_connections_lock:
            if conn_id in active_connections:
                del active_connections[conn_id]
        return {
            'id': conn_id,
            'success': False,
            'error': error_msg
        }
    except Exception as e:
        error_msg = f"{type(e).__name__}: {str(e)}"
        with results_lock:
            results['failed'] += 1
            results['errors'].append(error_msg)
        with active_connections_lock:
            if conn_id in active_connections:
                del active_connections[conn_id]
        return {
            'id': conn_id,
            'success': False,
            'error': error_msg
        }


def print_test_results(elapsed, extra_stats=None):
    """Print test results summary and return exit code.

    Args:
        elapsed: Time elapsed for the test
        extra_stats: Optional dict with extra stats to print (e.g., {'Per worker': 123.4})

    Returns:
        Exit code: 0 for success, 1 for failure
    """
    from collections import Counter

    total_connections = results['success'] + results['failed']

    print(f"Results:")
    print(f"=" * 60)

    if total_connections > 0:
        success_pct = results['success'] * 100 / total_connections
        failed_pct = results['failed'] * 100 / total_connections

        if extra_stats and 'total_label' in extra_stats:
            print(f"  Total connections: {total_connections}")

        print(f"  ✓ Successful: {results['success']}/{total_connections} ({success_pct:.1f}%)")
        print(f"  ✗ Failed:     {results['failed']}/{total_connections} ({failed_pct:.1f}%)")
        print(f"  Throughput:   {total_connections/elapsed:.1f} connections/second")

        if extra_stats:
            for key, value in extra_stats.items():
                if key != 'total_label':
                    print(f"  {key}: {value}")
    else:
        print(f"  No connections completed")

    print()

    # Show error summary if any
    if results['errors']:
        error_counts = Counter(results['errors'])

        print(f"Error summary ({len(results['errors'])} total errors):")
        # Sort by count (descending), then by error message
        for error_msg, count in sorted(error_counts.items(), key=lambda x: (-x[1], x[0])):
            print(f"  - {count}: {error_msg}")
        print()

    # Exit code based on success rate
    if total_connections > 0:
        success_rate = results['success'] * 100 / total_connections
        if success_rate == 100:
            print("✓ ALL TESTS PASSED!")
            return 0
        elif success_rate >= 90:
            print("⚠ MOSTLY PASSED (≥90%)")
            return 0
        else:
            print("✗ TESTS FAILED")
            return 1
    else:
        print("✗ NO CONNECTIONS COMPLETED")
        return 1


def continuous_worker(worker_id, host, port, timeout, end_time, conn_counter, conn_counter_lock,
                      resource_path=None, expected_sha256=None):
    """Worker thread that continuously makes connections until end_time.

    Note: Will complete the current connection even if end_time is reached during download.
    """
    while True:
        # Check time BEFORE starting new connection
        if time.time() >= end_time:
            break

        with conn_counter_lock:
            conn_id = conn_counter[0]
            conn_counter[0] += 1

        # Start connection - this may take longer than end_time for large files
        # We allow it to complete rather than aborting mid-transfer
        test_connection(conn_id, host, port, timeout, resource_path, expected_sha256)


def run_continuous_test(args):
    """Run continuous connections with N parallel workers for specified duration."""
    print(f"Starting continuous test for {args.duration} seconds...")
    print(f"{args.connections} parallel workers connecting repeatedly")
    print()

    global results, active_connections
    # Reset results for continuous test
    results['success'] = 0
    results['failed'] = 0
    results['errors'] = []
    active_connections.clear()

    start_time = time.time()
    end_time = start_time + args.duration
    last_report_time = start_time

    # Shared connection counter
    conn_counter = [0]
    conn_counter_lock = threading.Lock()

    # Parse resource if provided
    resource_path = None
    expected_sha256 = None
    if hasattr(args, 'resource') and args.resource:
        resource_path, expected_sha256 = args.resource

    # Start worker threads (non-daemon so they can complete their current download)
    workers = []
    try:
        for i in range(args.connections):
            worker = threading.Thread(
                target=continuous_worker,
                args=(i, args.host, args.port, args.timeout, end_time, conn_counter, conn_counter_lock,
                      resource_path, expected_sha256),
                daemon=False  # Non-daemon: allow workers to finish current download
            )
            worker.start()
            workers.append(worker)

        # Report progress while workers are running
        while time.time() < end_time:
            time.sleep(1.0)  # Report every second

            elapsed = time.time() - start_time
            remaining = end_time - time.time()
            total_conns = results['success'] + results['failed']

            if not args.quiet:
                if total_conns > 0:
                    success_rate = (results['success'] * 100 / total_conns)
                    throughput = total_conns / elapsed if elapsed > 0 else 0
                    print(f"[{elapsed:.1f}s] {total_conns} total, "
                          f"{results['success']} success ({success_rate:.1f}%), "
                          f"{throughput:.1f} conn/s, "
                          f"{remaining:.1f}s remaining")
                else:
                    # Show we're waiting even if no connections completed yet
                    print(f"[{elapsed:.1f}s] Waiting for downloads to finish... "
                          f"({remaining:.1f}s remaining)")

        # Duration expired - wait for workers to finish their current downloads
        print(f"\n⏱ Duration reached. Waiting for {len(workers)} workers to complete their current downloads...")

        # Wait for all workers to finish (they'll complete their current download)
        workers_alive = len(workers)
        while workers_alive > 0:
            time.sleep(1.0)
            workers_alive = sum(1 for w in workers if w.is_alive())
            if workers_alive > 0 and not args.quiet:
                total_conns = results['success'] + results['failed']
                # Show debug info about stuck connections
                with active_connections_lock:
                    active_count = len(active_connections)
                    if active_count > 0:
                        # Show state of stuck connections
                        states = {}
                        for conn_id, info in active_connections.items():
                            state = info['state']
                            elapsed = time.time() - info['time']
                            states[state] = states.get(state, 0) + 1
                        state_info = ", ".join(f"{count}×{state}" for state, count in states.items())
                        print(f"  {workers_alive} workers active, {total_conns} done, {active_count} in progress: {state_info}")
                    else:
                        print(f"  {workers_alive} workers still active, {total_conns} total connections...")

        print("✓ All workers finished")

    except KeyboardInterrupt:
        print("\n\n⚠ Test interrupted by user")
        print("  Waiting up to 10 seconds for workers to finish current downloads...")
        for worker in workers:
            worker.join(timeout=10.0)

    total_elapsed = time.time() - start_time
    print(f"\nCompleted continuous test in {total_elapsed:.2f} seconds")
    print()

    # Print results with per-worker stats
    total_connections = results['success'] + results['failed']
    per_worker = f"{total_connections/args.connections:.1f} connections/worker"
    return print_test_results(total_elapsed, {
        'total_label': True,
        'Per worker': per_worker
    })


def run_single_batch_test(args):
    """Run a single batch of parallel connections."""
    print(f"Starting {args.connections} parallel connections...")
    start_time = time.time()

    # Parse resource if provided
    resource_path = None
    expected_sha256 = None
    if hasattr(args, 'resource') and args.resource:
        resource_path, expected_sha256 = args.resource

    # Execute parallel connections
    with ThreadPoolExecutor(max_workers=args.connections) as executor:
        futures = [executor.submit(test_connection, i, args.host, args.port, args.timeout,
                                   resource_path, expected_sha256)
                   for i in range(args.connections)]

        # Progress indicator
        if not args.quiet:
            completed = 0
            for future in as_completed(futures):
                completed += 1
                if completed % 10 == 0 or completed == args.connections:
                    print(f"  Progress: {completed}/{args.connections}", end='\r')

    elapsed = time.time() - start_time
    print(f"\nCompleted in {elapsed:.2f} seconds")
    print()

    # Print results
    return print_test_results(elapsed)


def parse_resource(value):
    """Parse --resource argument in format 'url:sha256sum'."""
    if ':' not in value:
        raise argparse.ArgumentTypeError(
            "Resource must be in format 'url:sha256sum' (e.g., '/index.html:abc123...')"
        )

    parts = value.split(':', 1)
    url = parts[0]
    sha256sum = parts[1]

    # Validate SHA256 format (64 hex characters)
    if len(sha256sum) != 64 or not all(c in '0123456789abcdefABCDEF' for c in sha256sum):
        raise argparse.ArgumentTypeError(
            f"Invalid SHA256 hash: {sha256sum}. Must be 64 hexadecimal characters."
        )

    return (url, sha256sum.lower())


def main():
    """Main entry point for the test script."""
    parser = argparse.ArgumentParser(
        description='Test rinetd TCP forwarding with parallel connections',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument('--host', default=DEFAULT_HOST,
                        help=f'rinetd host (default: {DEFAULT_HOST})')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT,
                        help=f'rinetd port (default: {DEFAULT_PORT})')
    parser.add_argument('--connections', type=int, default=DEFAULT_CONNECTIONS,
                        help=f'number of parallel connections (default: {DEFAULT_CONNECTIONS})')
    parser.add_argument('--duration', type=int, default=0,
                        help='run continuously for N seconds (0 = single batch, default: 0)')
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT,
                        help=f'socket timeout in seconds (default: {DEFAULT_TIMEOUT})')
    parser.add_argument('--quiet', action='store_true',
                        help='suppress progress output')
    parser.add_argument('--resource', type=parse_resource, metavar='URL:SHA256',
                        help='validate resource: fetch URL and verify SHA256 hash '
                             '(e.g., /index.html:abc123...)')

    args = parser.parse_args()

    print(f"rinetd Parallel Connection Test")
    print(f"=" * 60)
    print(f"Target: {args.host}:{args.port}")
    print(f"Parallel connections: {args.connections}")
    if args.duration > 0:
        print(f"Duration: {args.duration}s (continuous mode)")
    print(f"Timeout: {args.timeout}s")
    if args.resource:
        resource_url, resource_sha256 = args.resource
        print(f"Resource validation: {resource_url}")
        print(f"Expected SHA256: {resource_sha256}")
    print(f"=" * 60)
    print()

    # Check if rinetd is reachable
    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.settimeout(2)
        test_sock.connect((args.host, args.port))
        test_sock.close()
        print("✓ rinetd is reachable")
        print()
    except Exception as e:
        print(f"✗ Cannot connect to rinetd: {e}")
        print(f"  Make sure rinetd is running on {args.host}:{args.port}")
        return 1

    if args.duration > 0:
        # Continuous mode: keep connecting for specified duration
        return run_continuous_test(args)
    else:
        # Single batch mode (original behavior)
        return run_single_batch_test(args)


if __name__ == '__main__':
    sys.exit(main())
