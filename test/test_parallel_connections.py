#!/usr/bin/env python3
"""
Test rinetd TCP forwarding with high number of parallel connections.
Tests concurrent HTTP requests and validates responses.

Usage:
    python3 test_parallel_connections.py [--host HOST] [--port PORT] [--connections N]

Examples:
    # Test with defaults (127.0.0.1:8080, 100 connections)
    python3 test_parallel_connections.py

    # Test with custom settings
    python3 test_parallel_connections.py --host 192.168.1.1 --port 9000 --connections 200

    # Stress test: keep connecting for 60 seconds with 50 parallel connections
    python3 test_parallel_connections.py --duration 60 --connections 50
"""

import socket
import threading
import time
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# Default configuration
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
DEFAULT_CONNECTIONS = 100
DEFAULT_TIMEOUT = 10

# HTTP request template
HTTP_REQUEST = b"GET / HTTP/1.0\r\nHost: test\r\n\r\n"

# Test results
results = {
    'success': 0,
    'failed': 0,
    'errors': []
}
results_lock = threading.Lock()


def test_connection(conn_id, host, port, timeout):
    """Test a single HTTP connection through rinetd."""
    try:
        # Create socket and connect
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        start_time = time.time()
        sock.connect((host, port))
        connect_time = time.time() - start_time

        # Send HTTP request
        sock.sendall(HTTP_REQUEST)

        # Read response - just the first line for validation
        response = b""
        while b"\r\n" not in response and len(response) < 1024:
            chunk = sock.recv(256)
            if not chunk:
                break
            response += chunk

        sock.close()

        # Validate response
        response_str = response.decode('utf-8', errors='ignore')
        first_line = response_str.split('\r\n')[0] if '\r\n' in response_str else response_str

        # Check if it's a valid HTTP response
        if first_line.startswith('HTTP/1.'):
            with results_lock:
                results['success'] += 1
            return {
                'id': conn_id,
                'success': True,
                'connect_time': connect_time,
                'first_line': first_line,
                'response_length': len(response)
            }
        else:
            with results_lock:
                results['failed'] += 1
                results['errors'].append(f"Connection #{conn_id}: Invalid HTTP response: {first_line[:50]}")
            return {
                'id': conn_id,
                'success': False,
                'error': f"Invalid HTTP response: {first_line[:50]}"
            }

    except socket.timeout:
        with results_lock:
            results['failed'] += 1
            results['errors'].append(f"Connection #{conn_id}: Timeout")
        return {
            'id': conn_id,
            'success': False,
            'error': 'Timeout'
        }
    except ConnectionRefusedError:
        with results_lock:
            results['failed'] += 1
            results['errors'].append(f"Connection #{conn_id}: Connection refused")
        return {
            'id': conn_id,
            'success': False,
            'error': 'Connection refused'
        }
    except Exception as e:
        with results_lock:
            results['failed'] += 1
            results['errors'].append(f"Connection #{conn_id}: {type(e).__name__}: {e}")
        return {
            'id': conn_id,
            'success': False,
            'error': f"{type(e).__name__}: {e}"
        }


def continuous_worker(worker_id, host, port, timeout, end_time, conn_counter, conn_counter_lock):
    """Worker thread that continuously makes connections until end_time."""
    while time.time() < end_time:
        with conn_counter_lock:
            conn_id = conn_counter[0]
            conn_counter[0] += 1

        test_connection(conn_id, host, port, timeout)


def run_continuous_test(args):
    """Run continuous connections with N parallel workers for specified duration."""
    print(f"Starting continuous test for {args.duration} seconds...")
    print(f"{args.connections} parallel workers connecting repeatedly")
    print()

    global results
    # Reset results for continuous test
    results['success'] = 0
    results['failed'] = 0
    results['errors'] = []

    start_time = time.time()
    end_time = start_time + args.duration
    last_report_time = start_time

    # Shared connection counter
    conn_counter = [0]
    conn_counter_lock = threading.Lock()

    # Start worker threads
    workers = []
    try:
        for i in range(args.connections):
            worker = threading.Thread(
                target=continuous_worker,
                args=(i, args.host, args.port, args.timeout, end_time, conn_counter, conn_counter_lock),
                daemon=True
            )
            worker.start()
            workers.append(worker)

        # Report progress while workers are running
        while time.time() < end_time:
            time.sleep(1.0)  # Report every second

            elapsed = time.time() - start_time
            remaining = end_time - time.time()
            total_conns = results['success'] + results['failed']

            if total_conns > 0:
                success_rate = (results['success'] * 100 / total_conns)
                throughput = total_conns / elapsed if elapsed > 0 else 0

                if not args.quiet:
                    print(f"[{elapsed:.1f}s] {total_conns} total, "
                          f"{results['success']} success ({success_rate:.1f}%), "
                          f"{throughput:.1f} conn/s, "
                          f"{remaining:.1f}s remaining")

        # Wait for all workers to finish
        for worker in workers:
            worker.join(timeout=2.0)

    except KeyboardInterrupt:
        print("\n\n⚠ Test interrupted by user")

    total_elapsed = time.time() - start_time
    print(f"\nCompleted continuous test in {total_elapsed:.2f} seconds")
    print()

    # Print final results
    total_connections = results['success'] + results['failed']
    print(f"Results:")
    print(f"=" * 60)
    print(f"  Total connections: {total_connections}")
    if total_connections > 0:
        print(f"  ✓ Successful: {results['success']}/{total_connections} ({results['success']*100/total_connections:.1f}%)")
        print(f"  ✗ Failed:     {results['failed']}/{total_connections} ({results['failed']*100/total_connections:.1f}%)")
        print(f"  Throughput:   {total_connections/total_elapsed:.1f} connections/second")
        print(f"  Per worker:   {total_connections/args.connections:.1f} connections/worker")
    else:
        print(f"  No connections completed")
    print()

    # Show sample errors if any
    if results['errors']:
        print(f"Errors (showing first 10):")
        for error in results['errors'][:10]:
            print(f"  - {error}")
        if len(results['errors']) > 10:
            print(f"  ... and {len(results['errors']) - 10} more")
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


def main():
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

    args = parser.parse_args()

    print(f"rinetd Parallel Connection Test")
    print(f"=" * 60)
    print(f"Target: {args.host}:{args.port}")
    print(f"Parallel connections: {args.connections}")
    if args.duration > 0:
        print(f"Duration: {args.duration}s (continuous mode)")
    print(f"Timeout: {args.timeout}s")
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


def run_single_batch_test(args):
    """Run a single batch of parallel connections."""
    print(f"Starting {args.connections} parallel connections...")
    start_time = time.time()

    # Execute parallel connections
    with ThreadPoolExecutor(max_workers=args.connections) as executor:
        futures = [executor.submit(test_connection, i, args.host, args.port, args.timeout)
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
    print(f"Results:")
    print(f"=" * 60)
    print(f"  ✓ Successful: {results['success']}/{args.connections} ({results['success']*100/args.connections:.1f}%)")
    print(f"  ✗ Failed:     {results['failed']}/{args.connections} ({results['failed']*100/args.connections:.1f}%)")
    print(f"  Throughput:   {args.connections/elapsed:.1f} connections/second")
    print()

    # Show sample errors if any
    if results['errors']:
        print(f"Errors (showing first 10):")
        for error in results['errors'][:10]:
            print(f"  - {error}")
        if len(results['errors']) > 10:
            print(f"  ... and {len(results['errors']) - 10} more")
        print()

    # Exit code
    if results['success'] == args.connections:
        print("✓ ALL TESTS PASSED!")
        return 0
    elif results['success'] > args.connections * 0.9:
        print("⚠ MOSTLY PASSED (>90%)")
        return 0
    else:
        print("✗ TESTS FAILED")
        return 1


if __name__ == '__main__':
    sys.exit(main())
