#!/usr/bin/env python3
"""
Test rinetd UDP forwarding with DNS queries.
Tests concurrent DNS queries and validates responses.

Usage:
    python3 test_dns_forwarding.py [--host HOST] [--port PORT] [--connections N]
                                   [--domain DOMAIN] [--record-type TYPE]

Examples:
    # Test with defaults (127.0.0.1:5353, 100 connections, query google.com)
    python3 test_dns_forwarding.py

    # Test with custom settings
    python3 test_dns_forwarding.py --host 192.168.137.2 --port 5353 --connections 200

    # Stress test: keep querying for 60 seconds with 50 parallel connections
    python3 test_dns_forwarding.py --duration 60 --connections 50

    # Query specific domain with different record type
    python3 test_dns_forwarding.py --domain example.com --record-type AAAA

    # Validate that response has expected number of answers
    python3 test_dns_forwarding.py --domain google.com --min-answers 1

    # Validate proxy response matches upstream (like TCP --resource option)
    python3 test_dns_forwarding.py --host 192.168.137.2 --port 5353 \
        --validate-upstream 192.168.137.1:53 --domain google.com --connections 100

Note: DNS responses typically have changing TTL values. Validation modes:
  - Basic mode: validates response format, code, type, and minimum answers
  - Upstream mode (--validate-upstream): compares proxy response against cached upstream query
    - First query fetches and caches the upstream response
    - Subsequent queries use the cached response for comparison (much faster)
    - Validates response codes match
    - Validates same number of answers
    - Validates same record data (ignoring TTL differences and record order)
    - This is analogous to TCP test's --resource option
"""

import socket
import threading
import time
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import dns.message
    import dns.query
    import dns.rdatatype
    import dns.rcode
except ImportError:
    print("Error: 'dnspython' library is required. Install it with: pip install dnspython")
    sys.exit(1)

# Default configuration
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5353
DEFAULT_CONNECTIONS = 100
DEFAULT_TIMEOUT = 5
DEFAULT_DOMAIN = "google.com"
DEFAULT_RECORD_TYPE = "A"

# Test results
results = {
    'success': 0,
    'failed': 0,
    'errors': []
}
results_lock = threading.Lock()

# Debug: track active connections
active_queries = {}
active_queries_lock = threading.Lock()

# Upstream response cache for --validate-upstream
# Key: (domain, record_type), Value: (response, timestamp)
upstream_cache = {}
upstream_cache_lock = threading.Lock()


def normalize_rrset(rrset):
    """Normalize an RRset for comparison (strip TTL, canonicalize data).

    Returns a tuple of (name, type, class, sorted_data_list) that can be compared.
    """
    # Extract record data as strings, ignoring TTL
    data_items = []
    for rdata in rrset:
        # Convert rdata to string (e.g., "142.250.185.46" for A record)
        data_items.append(str(rdata))

    # Sort data for consistent comparison (handles record order variations)
    data_items.sort()

    # Return canonical tuple: (name, type, class, sorted_data)
    return (str(rrset.name), rrset.rdtype, rrset.rdclass, tuple(data_items))


def get_cached_upstream_response(domain, record_type, upstream_host, upstream_port, timeout):
    """Get upstream response from cache, or query upstream and cache the result.

    Args:
        domain: Domain name to query
        record_type: DNS record type string (e.g., 'A', 'AAAA')
        upstream_host: Upstream DNS server host
        upstream_port: Upstream DNS server port
        timeout: Query timeout in seconds

    Returns:
        Cached or freshly-fetched upstream DNS response

    Raises:
        Exception if upstream query fails
    """
    cache_key = (domain, record_type)

    # Check cache first
    with upstream_cache_lock:
        if cache_key in upstream_cache:
            return upstream_cache[cache_key]

    # Not in cache - query upstream
    query = dns.message.make_query(domain, record_type)
    upstream_response = dns.query.udp(query, upstream_host, timeout=timeout, port=upstream_port)

    # Store in cache
    with upstream_cache_lock:
        # Double-check in case another thread populated it while we were querying
        if cache_key not in upstream_cache:
            upstream_cache[cache_key] = upstream_response

    return upstream_response


def compare_dns_responses(proxy_response, upstream_response):
    """Compare two DNS responses, ignoring TTL differences and record order.

    Returns (is_match, error_message). If is_match is True, error_message is None.
    """
    # 1. Compare response codes
    if proxy_response.rcode() != upstream_response.rcode():
        return (False, f"Response code mismatch: proxy={dns.rcode.to_text(proxy_response.rcode())}, "
                       f"upstream={dns.rcode.to_text(upstream_response.rcode())}")

    # 2. Compare number of answers
    proxy_answer_count = len(proxy_response.answer)
    upstream_answer_count = len(upstream_response.answer)
    if proxy_answer_count != upstream_answer_count:
        return (False, f"Answer count mismatch: proxy={proxy_answer_count}, upstream={upstream_answer_count}")

    # 3. Normalize and sort answer sections
    proxy_answers = sorted(normalize_rrset(rrset) for rrset in proxy_response.answer)
    upstream_answers = sorted(normalize_rrset(rrset) for rrset in upstream_response.answer)

    # 4. Compare canonical forms
    if proxy_answers != upstream_answers:
        # Build detailed error message
        error_lines = ["Answer data mismatch:"]
        error_lines.append(f"  Proxy answers: {proxy_answers}")
        error_lines.append(f"  Upstream answers: {upstream_answers}")
        return (False, "\n".join(error_lines))

    # All checks passed
    return (True, None)


def test_dns_query(query_id, host, port, timeout, domain, record_type, min_answers=1, expected_rcode=None,
                   upstream_host=None, upstream_port=None):
    """Test a single DNS query through rinetd.

    Args:
        query_id: Query identifier
        host: Target host (rinetd proxy)
        port: Target port (rinetd proxy port)
        timeout: Query timeout in seconds
        domain: Domain name to query
        record_type: DNS record type (A, AAAA, MX, etc.)
        min_answers: Minimum number of answers expected (ignored if upstream validation enabled)
        expected_rcode: Expected DNS response code (default: NOERROR, ignored if upstream validation enabled)
        upstream_host: Optional upstream DNS server host for validation
        upstream_port: Optional upstream DNS server port for validation
    """
    try:
        # Track this query as active
        with active_queries_lock:
            active_queries[query_id] = {'state': 'starting', 'time': time.time()}

        start_time = time.time()

        # Create DNS query
        with active_queries_lock:
            active_queries[query_id]['state'] = 'building_query'

        query = dns.message.make_query(domain, record_type)

        with active_queries_lock:
            active_queries[query_id]['state'] = 'sending'

        # Send DNS query via UDP to rinetd proxy
        response = dns.query.udp(query, host, timeout=timeout, port=port)

        with active_queries_lock:
            active_queries[query_id]['state'] = 'response_received'

        query_time = time.time() - start_time

        # Validate DNS response
        with active_queries_lock:
            active_queries[query_id]['state'] = 'validating'

        # If upstream validation is enabled, compare against cached upstream response
        if upstream_host is not None:
            with active_queries_lock:
                active_queries[query_id]['state'] = 'getting_upstream_response'

            # Get upstream response (cached or fresh)
            upstream_response = get_cached_upstream_response(
                domain, record_type, upstream_host, upstream_port, timeout)

            with active_queries_lock:
                active_queries[query_id]['state'] = 'comparing_responses'

            # Compare responses
            is_match, error_msg = compare_dns_responses(response, upstream_response)

            if not is_match:
                with results_lock:
                    results['failed'] += 1
                    results['errors'].append(f"Upstream validation failed: {error_msg}")
                return {
                    'id': query_id,
                    'success': False,
                    'error': f"Upstream validation failed: {error_msg}"
                }

            # Upstream validation passed - record success and return
            with results_lock:
                results['success'] += 1

            with active_queries_lock:
                active_queries[query_id]['state'] = 'completed'
                if query_id in active_queries:
                    del active_queries[query_id]

            return {
                'id': query_id,
                'success': True,
                'query_time': query_time,
                'rcode': dns.rcode.to_text(response.rcode()),
                'answer_count': len(response.answer),
                'upstream_validated': True
            }

        # Basic validation (when upstream validation is not enabled)
        # Check response code
        rcode = response.rcode()
        expected_rcode_val = expected_rcode if expected_rcode is not None else dns.rcode.NOERROR

        if rcode != expected_rcode_val:
            error_msg = f"DNS response code {dns.rcode.to_text(rcode)} (expected {dns.rcode.to_text(expected_rcode_val)})"
            with results_lock:
                results['failed'] += 1
                results['errors'].append(error_msg)
            return {
                'id': query_id,
                'success': False,
                'error': error_msg
            }

        # Check number of answers
        answer_count = len(response.answer)
        if answer_count < min_answers:
            error_msg = f"Only {answer_count} answer(s) (expected at least {min_answers})"
            with results_lock:
                results['failed'] += 1
                results['errors'].append(error_msg)
            return {
                'id': query_id,
                'success': False,
                'error': error_msg
            }

        # Verify response has expected record type (if answers exist)
        rdtype = dns.rdatatype.from_text(record_type)
        has_expected_type = False
        for rrset in response.answer:
            if rrset.rdtype == rdtype:
                has_expected_type = True
                break

        if answer_count > 0 and not has_expected_type:
            error_msg = f"No {record_type} records in response"
            with results_lock:
                results['failed'] += 1
                results['errors'].append(error_msg)
            return {
                'id': query_id,
                'success': False,
                'error': error_msg
            }

        # Success
        with results_lock:
            results['success'] += 1

        with active_queries_lock:
            active_queries[query_id]['state'] = 'completed'
            if query_id in active_queries:
                del active_queries[query_id]

        result = {
            'id': query_id,
            'success': True,
            'query_time': query_time,
            'rcode': dns.rcode.to_text(rcode),
            'answer_count': answer_count
        }

        return result

    except dns.exception.Timeout:
        error_msg = 'DNS query timeout'
        with results_lock:
            results['failed'] += 1
            results['errors'].append(error_msg)
        with active_queries_lock:
            if query_id in active_queries:
                del active_queries[query_id]
        return {
            'id': query_id,
            'success': False,
            'error': error_msg
        }
    except socket.error as e:
        error_msg = f'Socket error: {str(e)}'
        with results_lock:
            results['failed'] += 1
            results['errors'].append(error_msg)
        with active_queries_lock:
            if query_id in active_queries:
                del active_queries[query_id]
        return {
            'id': query_id,
            'success': False,
            'error': error_msg
        }
    except Exception as e:
        error_msg = f"{type(e).__name__}: {str(e)}"
        with results_lock:
            results['failed'] += 1
            results['errors'].append(error_msg)
        with active_queries_lock:
            if query_id in active_queries:
                del active_queries[query_id]
        return {
            'id': query_id,
            'success': False,
            'error': error_msg
        }


def print_test_results(elapsed, extra_stats=None):
    """Print test results summary and return exit code.

    Args:
        elapsed: Time elapsed for the test
        extra_stats: Optional dict with extra stats to print

    Returns:
        Exit code: 0 for success, 1 for failure
    """
    from collections import Counter

    total_queries = results['success'] + results['failed']

    print(f"Results:")
    print(f"=" * 60)

    if total_queries > 0:
        success_pct = results['success'] * 100 / total_queries
        failed_pct = results['failed'] * 100 / total_queries

        if extra_stats and 'total_label' in extra_stats:
            print(f"  Total queries: {total_queries}")

        print(f"  ✓ Successful: {results['success']}/{total_queries} ({success_pct:.1f}%)")
        print(f"  ✗ Failed:     {results['failed']}/{total_queries} ({failed_pct:.1f}%)")
        print(f"  Throughput:   {total_queries/elapsed:.1f} queries/second")

        if extra_stats:
            for key, value in extra_stats.items():
                if key != 'total_label':
                    print(f"  {key}: {value}")
    else:
        print(f"  No queries completed")

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
    if total_queries > 0:
        success_rate = results['success'] * 100 / total_queries
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
        print("✗ NO QUERIES COMPLETED")
        return 1


def continuous_worker(worker_id, host, port, timeout, end_time, query_counter, query_counter_lock,
                      domain, record_type, min_answers, expected_rcode, upstream_host, upstream_port):
    """Worker thread that continuously makes DNS queries until end_time."""
    while True:
        # Check time BEFORE starting new query
        if time.time() >= end_time:
            break

        with query_counter_lock:
            query_id = query_counter[0]
            query_counter[0] += 1

        # Start query
        test_dns_query(query_id, host, port, timeout, domain, record_type, min_answers, expected_rcode,
                       upstream_host, upstream_port)


def run_continuous_test(args):
    """Run continuous DNS queries with N parallel workers for specified duration."""
    print(f"Starting continuous test for {args.duration} seconds...")
    print(f"{args.connections} parallel workers querying repeatedly")
    print()

    global results, active_queries, upstream_cache
    # Reset results for continuous test
    results['success'] = 0
    results['failed'] = 0
    results['errors'] = []
    active_queries.clear()
    upstream_cache.clear()

    start_time = time.time()
    end_time = start_time + args.duration

    # Shared query counter
    query_counter = [0]
    query_counter_lock = threading.Lock()

    # Parse upstream server if provided
    upstream_host = None
    upstream_port = None
    if hasattr(args, 'upstream') and args.upstream:
        upstream_host, upstream_port = args.upstream

    # Start worker threads
    workers = []
    try:
        for i in range(args.connections):
            worker = threading.Thread(
                target=continuous_worker,
                args=(i, args.host, args.port, args.timeout, end_time, query_counter, query_counter_lock,
                      args.domain, args.record_type, args.min_answers, args.expected_rcode,
                      upstream_host, upstream_port),
                daemon=False
            )
            worker.start()
            workers.append(worker)

        # Report progress while workers are running
        while time.time() < end_time:
            time.sleep(1.0)  # Report every second

            elapsed = time.time() - start_time
            remaining = end_time - time.time()
            total_queries = results['success'] + results['failed']

            if not args.quiet:
                if total_queries > 0:
                    success_rate = (results['success'] * 100 / total_queries)
                    throughput = total_queries / elapsed if elapsed > 0 else 0
                    print(f"[{elapsed:.1f}s] {total_queries} total, "
                          f"{results['success']} success ({success_rate:.1f}%), "
                          f"{throughput:.1f} queries/s, "
                          f"{remaining:.1f}s remaining")
                else:
                    print(f"[{elapsed:.1f}s] Waiting for queries... "
                          f"({remaining:.1f}s remaining)")

        # Duration expired - wait for workers to finish
        print(f"\n⏱ Duration reached. Waiting for {len(workers)} workers to complete...")

        # Wait for all workers to finish
        workers_alive = len(workers)
        while workers_alive > 0:
            time.sleep(0.5)
            workers_alive = sum(1 for w in workers if w.is_alive())
            if workers_alive > 0 and not args.quiet:
                total_queries = results['success'] + results['failed']
                with active_queries_lock:
                    active_count = len(active_queries)
                    if active_count > 0:
                        states = {}
                        for query_id, info in active_queries.items():
                            state = info['state']
                            states[state] = states.get(state, 0) + 1
                        state_info = ", ".join(f"{count}×{state}" for state, count in states.items())
                        print(f"  {workers_alive} workers active, {total_queries} done, {active_count} in progress: {state_info}")
                    else:
                        print(f"  {workers_alive} workers still active, {total_queries} total queries...")

        print("✓ All workers finished")

    except KeyboardInterrupt:
        print("\n\n⚠ Test interrupted by user")
        print("  Waiting for workers to finish...")
        for worker in workers:
            worker.join(timeout=5.0)

    total_elapsed = time.time() - start_time
    print(f"\nCompleted continuous test in {total_elapsed:.2f} seconds")
    print()

    # Print results with per-worker stats
    total_queries = results['success'] + results['failed']
    per_worker = f"{total_queries/args.connections:.1f} queries/worker"
    return print_test_results(total_elapsed, {
        'total_label': True,
        'Per worker': per_worker
    })


def run_single_batch_test(args):
    """Run a single batch of parallel DNS queries."""
    global upstream_cache
    upstream_cache.clear()

    print(f"Starting {args.connections} parallel DNS queries...")
    start_time = time.time()

    # Parse upstream server if provided
    upstream_host = None
    upstream_port = None
    if hasattr(args, 'upstream') and args.upstream:
        upstream_host, upstream_port = args.upstream

    # Execute parallel queries
    with ThreadPoolExecutor(max_workers=args.connections) as executor:
        futures = [executor.submit(test_dns_query, i, args.host, args.port, args.timeout,
                                   args.domain, args.record_type, args.min_answers, args.expected_rcode,
                                   upstream_host, upstream_port)
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


def main():
    """Main entry point for the DNS test script."""
    parser = argparse.ArgumentParser(
        description='Test rinetd UDP forwarding with parallel DNS queries',
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
                        help=f'query timeout in seconds (default: {DEFAULT_TIMEOUT})')
    parser.add_argument('--quiet', action='store_true',
                        help='suppress progress output')
    parser.add_argument('--domain', default=DEFAULT_DOMAIN,
                        help=f'domain name to query (default: {DEFAULT_DOMAIN})')
    parser.add_argument('--record-type', default=DEFAULT_RECORD_TYPE,
                        help=f'DNS record type (A, AAAA, MX, TXT, etc.) (default: {DEFAULT_RECORD_TYPE})')
    parser.add_argument('--min-answers', type=int, default=1,
                        help='minimum number of answers expected (default: 1)')
    parser.add_argument('--expected-rcode', type=str, default=None,
                        help='expected DNS response code (default: NOERROR)')
    parser.add_argument('--validate-upstream', type=str, metavar='HOST:PORT', default=None,
                        help='validate proxy responses match upstream DNS server (e.g., 192.168.137.1:53). '
                             'Analogous to TCP test --resource option. Ignores --min-answers and --expected-rcode.')

    args = parser.parse_args()

    # Parse upstream server if provided
    if args.validate_upstream:
        try:
            if ':' not in args.validate_upstream:
                print(f"✗ Invalid --validate-upstream format. Expected HOST:PORT (e.g., 192.168.137.1:53)")
                return 1
            parts = args.validate_upstream.split(':', 1)
            upstream_host = parts[0]
            upstream_port = int(parts[1])
            args.upstream = (upstream_host, upstream_port)
        except ValueError:
            print(f"✗ Invalid port in --validate-upstream: {args.validate_upstream}")
            return 1
    else:
        args.upstream = None

    # Parse expected rcode if provided
    if args.expected_rcode:
        try:
            args.expected_rcode = dns.rcode.from_text(args.expected_rcode)
        except dns.rcode.UnknownRcode:
            print(f"✗ Unknown DNS response code: {args.expected_rcode}")
            return 1
    else:
        args.expected_rcode = None  # Will default to NOERROR in test_dns_query

    print(f"rinetd DNS Forwarding Test")
    print(f"=" * 60)
    print(f"Target: {args.host}:{args.port}")
    print(f"Parallel queries: {args.connections}")
    if args.duration > 0:
        print(f"Duration: {args.duration}s (continuous mode)")
    print(f"Timeout: {args.timeout}s")
    print(f"Query: {args.domain} ({args.record_type})")
    if args.upstream:
        upstream_host, upstream_port = args.upstream
        print(f"Validation: upstream comparison against {upstream_host}:{upstream_port} (cached)")
    else:
        print(f"Min answers: {args.min_answers}")
        if args.expected_rcode is not None:
            print(f"Expected rcode: {dns.rcode.to_text(args.expected_rcode)}")
    print(f"=" * 60)
    print()

    # Check if rinetd is reachable (UDP)
    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        test_sock.settimeout(2)
        # For UDP, we can't really "connect" and verify, but we can try to create the socket
        # The actual validation will happen when we send DNS queries
        test_sock.close()
        print("✓ UDP socket created successfully")
        print()
    except Exception as e:
        print(f"✗ Cannot create UDP socket: {e}")
        return 1

    if args.duration > 0:
        # Continuous mode: keep querying for specified duration
        return run_continuous_test(args)
    else:
        # Single batch mode (original behavior)
        return run_single_batch_test(args)


if __name__ == '__main__':
    sys.exit(main())
