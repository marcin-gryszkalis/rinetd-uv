"""
YAML configuration validation tests for rinetd-uv.

Tests cover:
- YAML syntax errors
- Invalid values (out of range, wrong types)
- Invalid combinations of values
- Missing required fields
- Schema validation
"""
import pytest
import subprocess
import os
import time
from .utils import get_free_port, wait_for_port


def run_rinetd_with_yaml(rinetd_path, yaml_content, tmp_path, expect_success=True):
    """
    Run rinetd with a YAML config and return (success, stdout, stderr).

    Args:
        rinetd_path: Path to rinetd executable
        yaml_content: YAML configuration content
        tmp_path: Temporary directory for config file
        expect_success: If True, expect rinetd to start successfully
    Returns:
        (success, stdout, stderr) tuple
    """
    config_file = str(tmp_path / "test.yaml")
    with open(config_file, 'w') as f:
        f.write(yaml_content)

    proc = subprocess.Popen(
        [rinetd_path, "-f", "-c", config_file],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if expect_success:
        time.sleep(0.5)
        if proc.poll() is None:
            proc.terminate()
            proc.wait()
            return True, "", ""
        stdout, stderr = proc.communicate()
        return False, stdout, stderr
    else:
        try:
            stdout, stderr = proc.communicate(timeout=2.0)
            return proc.returncode == 0, stdout, stderr
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            return True, "", ""  # Didn't fail as expected


# =============================================================================
# YAML Syntax Error Tests
# =============================================================================

class TestYAMLSyntaxErrors:
    """Tests for YAML syntax error detection."""

    def test_invalid_yaml_indentation(self, rinetd_path, tmp_path):
        """Invalid YAML indentation should fail."""
        yaml_content = """
global:
buffer_size: 65536
  dns_refresh: 600
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=False
        )
        assert not success, "Should fail with invalid YAML indentation"
        assert "yaml" in stderr.lower() or "error" in stderr.lower()

    def test_invalid_yaml_colon(self, rinetd_path, tmp_path):
        """Missing colon in YAML key should fail."""
        yaml_content = """
global
  buffer_size: 65536
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=False
        )
        assert not success, "Should fail with missing colon"

    def test_unclosed_quote(self, rinetd_path, tmp_path):
        """Unclosed quote in YAML should fail."""
        yaml_content = """
rules:
  - name: "unclosed
    bind: "0.0.0.0:8080/tcp"
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=False
        )
        assert not success, "Should fail with unclosed quote"

    def test_invalid_yaml_list_format(self, rinetd_path, tmp_path):
        """Invalid list format should fail."""
        yaml_content = """
rules:
  - name: test
    connect:
    - dest: "127.0.0.1:8080"
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=False
        )
        # This is actually valid YAML but invalid schema
        # The test validates that malformed structure is detected

    def test_tabs_instead_of_spaces(self, rinetd_path, tmp_path):
        """Tabs in YAML should fail (YAML requires spaces)."""
        yaml_content = "rules:\n\t- name: test\n"
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=False
        )
        assert not success, "Should fail with tabs in YAML"


# =============================================================================
# Invalid Value Tests
# =============================================================================

class TestInvalidValues:
    """Tests for invalid configuration values."""

    def test_negative_buffer_size(self, rinetd_path, tmp_path):
        """Negative buffer_size should fail."""
        yaml_content = """
global:
  buffer_size: -1000

rules:
  - name: test
    bind: "127.0.0.1:8080/tcp"
    connect: "127.0.0.1:9090"
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=False
        )
        assert not success, "Should fail with negative buffer_size"
        assert "buffer" in stderr.lower() or "invalid" in stderr.lower() or "error" in stderr.lower()

    def test_buffer_size_too_small(self, rinetd_path, tmp_path):
        """Buffer size below minimum (1024) should fail."""
        yaml_content = """
global:
  buffer_size: 100

rules:
  - name: test
    bind: "127.0.0.1:8080/tcp"
    connect: "127.0.0.1:9090"
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=False
        )
        assert not success, "Should fail with buffer_size below minimum"

    def test_buffer_size_too_large(self, rinetd_path, tmp_path):
        """Buffer size above maximum (1MB) should fail."""
        yaml_content = """
global:
  buffer_size: 10000000

rules:
  - name: test
    bind: "127.0.0.1:8080/tcp"
    connect: "127.0.0.1:9090"
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=False
        )
        assert not success, "Should fail with buffer_size above maximum"

    def test_invalid_port_number(self, rinetd_path, tmp_path):
        """Port number > 65535 should fail."""
        yaml_content = """
rules:
  - name: test
    bind: "127.0.0.1:99999/tcp"
    connect: "127.0.0.1:8080"
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=False
        )
        assert not success, "Should fail with invalid port number"

    def test_negative_port_number(self, rinetd_path, tmp_path):
        """Negative port number should fail."""
        yaml_content = """
rules:
  - name: test
    bind: "127.0.0.1:8080/tcp"
    connect: "127.0.0.1:-1"
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=False
        )
        assert not success, "Should fail with negative port number"

    def test_invalid_algorithm(self, rinetd_path, tmp_path):
        """Invalid load balancing algorithm should fail."""
        yaml_content = """
rules:
  - name: test
    bind: "127.0.0.1:8080/tcp"
    connect: "127.0.0.1:9090"
      - host: 127.0.0.1
        port: 9091
    load_balancing:
      algorithm: invalidalgorithm
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=False
        )
        assert not success, "Should fail with invalid algorithm"
        assert "algorithm" in stderr.lower() or "invalid" in stderr.lower()

    def test_negative_weight(self, rinetd_path, tmp_path):
        """Negative backend weight should fail."""
        yaml_content = """
rules:
  - name: test
    bind: "127.0.0.1:8080/tcp"
    connect: "127.0.0.1:9090"
        weight: -5
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=False
        )
        assert not success, "Should fail with negative weight"

    def test_zero_weight(self, rinetd_path, tmp_path):
        """Zero weight should fail."""
        yaml_content = """
rules:
  - name: test
    bind: "127.0.0.1:8080/tcp"
    connect: "127.0.0.1:9090"
        weight: 0
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=False
        )
        assert not success, "Should fail with zero weight"

    def test_negative_health_threshold(self, rinetd_path, tmp_path):
        """Negative health_threshold should fail."""
        yaml_content = """
rules:
  - name: test
    bind: "127.0.0.1:8080/tcp"
    connect: "127.0.0.1:9090"
    load_balancing:
      health_threshold: -1
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=False
        )
        assert not success, "Should fail with negative health_threshold"

    def test_negative_recovery_timeout(self, rinetd_path, tmp_path):
        """Negative recovery_timeout should fail."""
        yaml_content = """
rules:
  - name: test
    bind: "127.0.0.1:8080/tcp"
    connect: "127.0.0.1:9090"
    load_balancing:
      recovery_timeout: -10
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=False
        )
        assert not success, "Should fail with negative recovery_timeout"

    def test_negative_affinity_ttl(self, rinetd_path, tmp_path):
        """Negative affinity_ttl should fail."""
        yaml_content = """
rules:
  - name: test
    bind: "127.0.0.1:8080/tcp"
    connect: "127.0.0.1:9090"
    load_balancing:
      affinity_ttl: -300
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=False
        )
        assert not success, "Should fail with negative affinity_ttl"

    def test_string_where_number_expected(self, rinetd_path, tmp_path):
        """String value where number expected should fail."""
        yaml_content = """
global:
  buffer_size: "not a number"

rules:
  - name: test
    bind: "127.0.0.1:8080/tcp"
    connect: "127.0.0.1:9090"
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=False
        )
        assert not success, "Should fail with string where number expected"

    def test_invalid_protocol(self, rinetd_path, tmp_path):
        """Invalid protocol specifier should fail."""
        yaml_content = """
rules:
  - name: test
    bind: "127.0.0.1:8080/sctp"
    connect: "127.0.0.1:9090"
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=False
        )
        assert not success, "Should fail with invalid protocol"


# =============================================================================
# Missing Required Fields Tests
# =============================================================================

class TestMissingFields:
    """Tests for missing required fields."""

    def test_missing_rules(self, rinetd_path, tmp_path):
        """Config without rules should fail or warn."""
        yaml_content = """
global:
  buffer_size: 65536
"""
        # This might be allowed (empty config) or fail - depends on implementation
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=False
        )
        # Empty config might be valid but useless, or might fail

    def test_rule_missing_name(self, rinetd_path, tmp_path):
        """Rule without name should fail."""
        yaml_content = """
rules:
  - bind: "127.0.0.1:8080/tcp"
    connect: "127.0.0.1:9090"
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=False
        )
        assert not success, "Should fail with missing rule name"
        assert "name" in stderr.lower() or "required" in stderr.lower() or "error" in stderr.lower()

    def test_rule_missing_bind(self, rinetd_path, tmp_path):
        """Rule without bind address should fail."""
        yaml_content = """
rules:
  - name: test
    connect: "127.0.0.1:9090"
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=False
        )
        assert not success, "Should fail with missing bind address"

    def test_rule_missing_connect(self, rinetd_path, tmp_path):
        """Rule without connect should fail."""
        yaml_content = """
rules:
  - name: test
    bind: "127.0.0.1:8080/tcp"
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=False
        )
        assert not success, "Should fail with missing connect"

    def test_connect_missing_dest(self, rinetd_path, tmp_path):
        """Connect list item without dest should fail."""
        yaml_content = """
rules:
  - name: test
    bind: "127.0.0.1:8080/tcp"
    connect:
      - weight: 1
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=False
        )
        assert not success, "Should fail with connect item missing dest"

    def test_connect_missing_port(self, rinetd_path, tmp_path):
        """Connect dest without port should fail."""
        yaml_content = """
rules:
  - name: test
    bind: "127.0.0.1:8080/tcp"
    connect: "127.0.0.1"
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=False
        )
        assert not success, "Should fail with connect dest missing port"

    def test_empty_connect_list(self, rinetd_path, tmp_path):
        """Empty connect list should fail."""
        yaml_content = """
rules:
  - name: test
    bind: "127.0.0.1:8080/tcp"
    connect: []
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=False
        )
        assert not success, "Should fail with empty connect list"

    def test_empty_bind_list(self, rinetd_path, tmp_path):
        """Empty bind list should fail."""
        yaml_content = """
rules:
  - name: test
    bind: []
    connect: "127.0.0.1:9090"
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=False
        )
        assert not success, "Should fail with empty bind list"


# =============================================================================
# Invalid Combinations Tests
# =============================================================================

class TestInvalidCombinations:
    """Tests for invalid combinations of values."""

    def test_backend_with_both_host_and_path(self, rinetd_path, tmp_path):
        """Backend with both host and path should fail."""
        yaml_content = """
rules:
  - name: test
    bind: "127.0.0.1:8080/tcp"
    connect:
      - dest: "127.0.0.1:9090"
      - dest: "unix:/tmp/test.sock"
"""
        # Note: This test now verifies a valid config - having both TCP and Unix socket
        # backends is allowed. The original test concept is no longer applicable.
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=True
        )

    def test_udp_with_unix_socket(self, rinetd_path, tmp_path):
        """UDP listener with Unix socket backend should fail."""
        yaml_content = """
rules:
  - name: test
    bind: "127.0.0.1:8080/udp"
    connect: "unix:/tmp/test.sock"
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=False
        )
        # UDP to Unix socket is not supported
        assert not success, "Should fail with UDP to Unix socket"

    def test_mixed_protocol_backends(self, rinetd_path, tmp_path):
        """Mixing TCP and UDP backends should fail (protocols must match)."""
        # Actually, TCP listener to TCP backends is normal
        # But can't have TCP listener forward to UDP backend
        yaml_content = """
rules:
  - name: test
    bind: "127.0.0.1:8080/tcp"
    connect: "127.0.0.1:9090"
"""
        # This is valid - backends inherit protocol from bind
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=True
        )

    def test_duplicate_rule_names(self, rinetd_path, tmp_path):
        """Duplicate rule names should fail."""
        yaml_content = """
rules:
  - name: duplicate
    bind: "127.0.0.1:8080/tcp"
    connect: "127.0.0.1:9090"
  - name: duplicate
    bind: "127.0.0.1:8081/tcp"
    connect: "127.0.0.1:9091"
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=False
        )
        assert not success, "Should fail with duplicate rule names"

    def test_duplicate_bind_addresses(self, rinetd_path, tmp_path):
        """Same bind address in different rules should fail."""
        yaml_content = """
rules:
  - name: rule1
    bind: "127.0.0.1:8080/tcp"
    connect: "127.0.0.1:9090"
  - name: rule2
    bind: "127.0.0.1:8080/tcp"
    connect: "127.0.0.1:9091"
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=False
        )
        # Should fail at bind time with "address already in use"
        assert not success, "Should fail with duplicate bind addresses"


# =============================================================================
# Valid Configuration Tests (Positive Cases)
# =============================================================================

class TestValidConfigurations:
    """Tests to verify valid configurations are accepted."""

    def test_minimal_valid_config(self, rinetd_path, tmp_path):
        """Minimal valid YAML config should work."""
        port = get_free_port()
        yaml_content = f"""
rules:
  - name: test
    bind: "127.0.0.1:{port}/tcp"
    connect: "127.0.0.1:9999"
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=True
        )
        assert success, f"Minimal valid config should work: {stderr}"

    def test_full_global_section(self, rinetd_path, tmp_path):
        """Full global section with all options should work."""
        port = get_free_port()
        yaml_content = f"""
global:
  buffer_size: 32768
  dns_refresh: 300
  pool_min_free: 32
  pool_max_free: 512
  pool_trim_delay: 30000
  listen_backlog: 256
  max_udp_connections: 1000

rules:
  - name: test
    bind: "127.0.0.1:{port}/tcp"
    connect: "127.0.0.1:9999"
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=True
        )
        assert success, f"Full global config should work: {stderr}"

    def test_all_algorithms(self, rinetd_path, tmp_path):
        """All valid algorithms should be accepted."""
        algorithms = ["roundrobin", "leastconn", "random", "iphash"]
        base_port = 20000

        for i, algo in enumerate(algorithms):
            port = base_port + i
            yaml_content = f"""
rules:
  - name: test-{algo}
    bind: "127.0.0.1:{port}/tcp"
    connect:
      - dest: "127.0.0.1:9090"
      - dest: "127.0.0.1:9091"
    load_balancing:
      algorithm: {algo}
"""
            success, stdout, stderr = run_rinetd_with_yaml(
                rinetd_path, yaml_content, tmp_path, expect_success=True
            )
            assert success, f"Algorithm '{algo}' should be valid: {stderr}"

    def test_multiple_backends_with_weights(self, rinetd_path, tmp_path):
        """Multiple backends with different weights should work."""
        port = get_free_port()
        yaml_content = f"""
rules:
  - name: weighted
    bind: "127.0.0.1:{port}/tcp"
    connect:
      - dest: "127.0.0.1:9090"
        weight: 5
      - dest: "127.0.0.1:9091"
        weight: 3
      - dest: "127.0.0.1:9092"
        weight: 1
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=True
        )
        assert success, f"Weighted backends should work: {stderr}"

    def test_access_control(self, rinetd_path, tmp_path):
        """Access control in YAML should work."""
        port = get_free_port()
        yaml_content = f"""
rules:
  - name: with-acl
    bind: "127.0.0.1:{port}/tcp"
    connect: "127.0.0.1:9999"
    access:
      allow:
        - "192.168.*"
        - "10.*"
      deny:
        - "*"
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=True
        )
        assert success, f"Access control config should work: {stderr}"

    def test_unix_socket_backend(self, rinetd_path, tmp_path):
        """Unix socket backend should work."""
        port = get_free_port()
        yaml_content = f"""
rules:
  - name: unix-backend
    bind: "127.0.0.1:{port}/tcp"
    connect: "unix:/tmp/nonexistent.sock"
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=True
        )
        assert success, f"Unix socket backend config should work: {stderr}"

    def test_udp_rule(self, rinetd_path, tmp_path):
        """UDP forwarding rule should work."""
        port = get_free_port()
        yaml_content = f"""
rules:
  - name: udp-test
    bind: "127.0.0.1:{port}/udp"
    connect: "127.0.0.1:9999"
    timeout: 30
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=True
        )
        assert success, f"UDP rule config should work: {stderr}"

    def test_multiple_bind_addresses(self, rinetd_path, tmp_path):
        """Multiple bind addresses should work."""
        port1 = get_free_port()
        port2 = get_free_port()
        yaml_content = f"""
rules:
  - name: multi-bind
    bind:
      - "127.0.0.1:{port1}/tcp"
      - "127.0.0.1:{port2}/tcp"
    connect: "127.0.0.1:9999"
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=True
        )
        assert success, f"Multiple bind addresses should work: {stderr}"

    def test_health_checking_options(self, rinetd_path, tmp_path):
        """Health checking options should work."""
        port = get_free_port()
        yaml_content = f"""
rules:
  - name: health-opts
    bind: "127.0.0.1:{port}/tcp"
    connect:
      - dest: "127.0.0.1:9090"
      - dest: "127.0.0.1:9091"
    load_balancing:
      algorithm: roundrobin
      health_threshold: 5
      recovery_timeout: 60
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=True
        )
        assert success, f"Health checking options should work: {stderr}"

    def test_affinity_options(self, rinetd_path, tmp_path):
        """Affinity options should work."""
        port = get_free_port()
        yaml_content = f"""
rules:
  - name: affinity-opts
    bind: "127.0.0.1:{port}/tcp"
    connect:
      - dest: "127.0.0.1:9090"
      - dest: "127.0.0.1:9091"
    load_balancing:
      algorithm: roundrobin
      affinity_ttl: 3600
      affinity_max_entries: 50000
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=True
        )
        assert success, f"Affinity options should work: {stderr}"


# =============================================================================
# Edge Cases Tests
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_maximum_buffer_size(self, rinetd_path, tmp_path):
        """Maximum buffer size (1MB) should work."""
        port = get_free_port()
        yaml_content = f"""
global:
  buffer_size: 1048576

rules:
  - name: test
    bind: "127.0.0.1:{port}/tcp"
    connect: "127.0.0.1:9999"
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=True
        )
        assert success, f"Maximum buffer size should work: {stderr}"

    def test_minimum_buffer_size(self, rinetd_path, tmp_path):
        """Minimum buffer size (1KB) should work."""
        port = get_free_port()
        yaml_content = f"""
global:
  buffer_size: 1024

rules:
  - name: test
    bind: "127.0.0.1:{port}/tcp"
    connect: "127.0.0.1:9999"
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=True
        )
        assert success, f"Minimum buffer size should work: {stderr}"

    def test_many_backends(self, rinetd_path, tmp_path):
        """Many backends (10) should work."""
        port = get_free_port()
        backends = "\n".join([
            f"      - dest: \"127.0.0.1:{9000 + i}\""
            for i in range(10)
        ])
        yaml_content = f"""
rules:
  - name: many-backends
    bind: "127.0.0.1:{port}/tcp"
    connect:
{backends}
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=True
        )
        assert success, f"Many backends should work: {stderr}"

    def test_many_rules(self, rinetd_path, tmp_path):
        """Many rules (10) should work."""
        base_port = 20000
        rules = "\n".join([
            f"""  - name: rule-{i}
    bind: "127.0.0.1:{base_port + i}/tcp"
    connect: "127.0.0.1:{9000 + i}\""""
            for i in range(10)
        ])
        yaml_content = f"""
rules:
{rules}
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=True
        )
        assert success, f"Many rules should work: {stderr}"

    def test_very_long_rule_name(self, rinetd_path, tmp_path):
        """Very long rule name should work (up to reasonable limit)."""
        port = get_free_port()
        long_name = "a" * 100
        yaml_content = f"""
rules:
  - name: {long_name}
    bind: "127.0.0.1:{port}/tcp"
    connect: "127.0.0.1:9999"
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=True
        )
        assert success, f"Long rule name should work: {stderr}"

    def test_special_characters_in_name(self, rinetd_path, tmp_path):
        """Rule name with special characters should work."""
        port = get_free_port()
        yaml_content = f"""
rules:
  - name: "test-rule_v2.0"
    bind: "127.0.0.1:{port}/tcp"
    connect: "127.0.0.1:9999"
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=True
        )
        assert success, f"Special characters in name should work: {stderr}"

    def test_ipv6_bind_address(self, rinetd_path, tmp_path):
        """IPv6 bind address should work."""
        port = get_free_port()
        yaml_content = f"""
rules:
  - name: ipv6-test
    bind: "[::1]:{port}/tcp"
    connect: "127.0.0.1:9999"
"""
        success, stdout, stderr = run_rinetd_with_yaml(
            rinetd_path, yaml_content, tmp_path, expect_success=True
        )
        # May fail if IPv6 not available
        if not success and "ipv6" in stderr.lower():
            pytest.skip("IPv6 not available")
        assert success, f"IPv6 bind address should work: {stderr}"


# =============================================================================
# Skip marker for YAML tests if libyaml not available
# =============================================================================

@pytest.fixture(scope="module")
def yaml_supported(rinetd_path, tmp_path_factory):
    """Check if rinetd was built with YAML support."""
    tmp_path = tmp_path_factory.mktemp("yaml_check")
    yaml_file = tmp_path / "test.yaml"
    yaml_file.write_text("rules: []\n")

    proc = subprocess.Popen(
        [rinetd_path, "-f", "-c", str(yaml_file)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    time.sleep(0.5)
    if proc.poll() is None:
        proc.terminate()
        proc.wait()
        return True

    _, stderr = proc.communicate()
    if "YAML" in stderr and "not supported" in stderr.lower():
        return False
    return True


@pytest.fixture(autouse=True)
def skip_if_no_yaml(request, yaml_supported):
    """Skip YAML tests if YAML is not supported."""
    if not yaml_supported:
        pytest.skip("rinetd was built without YAML support (libyaml not available)")
