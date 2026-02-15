#!/usr/bin/env python3
"""
Convert legacy rinetd-uv.conf configuration to YAML format.

Usage:
    python3 conf2yaml.py [input.conf] > output.yaml
    python3 conf2yaml.py < input.conf > output.yaml

This script parses the legacy configuration format and outputs
equivalent YAML configuration with load balancing support.
"""

import sys
import re
import argparse
from collections import OrderedDict


class LegacyConfigParser:
    """Parse legacy rinetd configuration format."""

    def __init__(self):
        self.global_options = {}
        self.rules = []
        self.current_rule = None
        self.global_allow = []
        self.global_deny = []
        self.warnings = []

    def parse_line(self, line):
        """Parse a single configuration line."""
        # Remove comments
        line = re.sub(r'#.*$', '', line).strip()
        if not line:
            return

        # Parse global options
        if line.startswith('logfile'):
            match = re.match(r'logfile\s+(\S+)', line)
            if match:
                self.global_options['log_file'] = match.group(1)
            return

        if line.startswith('pidfile'):
            match = re.match(r'pidfile\s+(\S+)', line)
            if match:
                self.global_options['pid_file'] = match.group(1)
            return

        if line.startswith('logcommon'):
            self.global_options['log_common'] = True
            return

        if line.startswith('buffersize'):
            match = re.match(r'buffersize\s+(\d+)', line)
            if match:
                self.global_options['buffer_size'] = int(match.group(1))
            return

        if line.startswith('dns-refresh'):
            match = re.match(r'dns-refresh\s+(\d+)', line)
            if match:
                self.global_options['dns_refresh'] = int(match.group(1))
            return

        if line.startswith('dns-multi-ip-expand'):
            match = re.match(r'dns-multi-ip-expand\s+(\S+)', line)
            if match:
                val = match.group(1).lower()
                self.global_options['dns_multi_ip_expand'] = val in ('on', 'true', '1', 'yes')
            return

        if line.startswith('dns-multi-ip-proto'):
            match = re.match(r'dns-multi-ip-proto\s+(\S+)', line)
            if match:
                self.global_options['dns_multi_ip_proto'] = match.group(1).lower()
            return

        if line.startswith('listen-backlog'):
            match = re.match(r'listen-backlog\s+(\d+)', line)
            if match:
                self.global_options['listen_backlog'] = int(match.group(1))
            return

        if line.startswith('max-udp-connections'):
            match = re.match(r'max-udp-connections\s+(\d+)', line)
            if match:
                self.global_options['max_udp_connections'] = int(match.group(1))
            return

        if line.startswith('pool-min-free'):
            match = re.match(r'pool-min-free\s+(\d+)', line)
            if match:
                self.global_options['pool_min_free'] = int(match.group(1))
            return

        if line.startswith('pool-max-free'):
            match = re.match(r'pool-max-free\s+(\d+)', line)
            if match:
                self.global_options['pool_max_free'] = int(match.group(1))
            return

        if line.startswith('pool-trim-delay'):
            match = re.match(r'pool-trim-delay\s+(\d+)', line)
            if match:
                self.global_options['pool_trim_delay'] = int(match.group(1))
            return

        # Status reporting options
        if line.startswith('statusfile'):
            match = re.match(r'statusfile\s+(\S+)', line)
            if match:
                if 'status' not in self.global_options:
                    self.global_options['status'] = {}
                self.global_options['status']['file'] = match.group(1).strip('"')
                self.global_options['status']['enabled'] = True
            return

        if line.startswith('statusinterval'):
            match = re.match(r'statusinterval\s+(\d+)', line)
            if match:
                if 'status' not in self.global_options:
                    self.global_options['status'] = {}
                self.global_options['status']['interval'] = int(match.group(1))
            return

        if line.startswith('statusformat'):
            match = re.match(r'statusformat\s+(\S+)', line)
            if match:
                if 'status' not in self.global_options:
                    self.global_options['status'] = {}
                self.global_options['status']['format'] = match.group(1)
            return

        if line.startswith('statsloginterval'):
            match = re.match(r'statsloginterval\s+(\d+)', line)
            if match:
                self.global_options['stats_log_interval'] = int(match.group(1))
            return

        # Include directive - not supported in YAML, warn user
        if line.startswith('include'):
            match = re.match(r'include\s+(.+)', line)
            if match:
                pattern = match.group(1).strip().strip('"')
                self.warnings.append(
                    f"WARNING: 'include {pattern}' directive cannot be converted. "
                    f"YAML format does not support includes. "
                    f"Merge included files manually."
                )
            return

        # Parse allow/deny rules
        if line.startswith('allow'):
            match = re.match(r'allow\s+(.+)', line)
            if match:
                pattern = match.group(1).strip()
                if self.current_rule:
                    if 'access' not in self.current_rule:
                        self.current_rule['access'] = {'allow': [], 'deny': []}
                    self.current_rule['access']['allow'].append(pattern)
                else:
                    self.global_allow.append(pattern)
            return

        if line.startswith('deny'):
            match = re.match(r'deny\s+(.+)', line)
            if match:
                pattern = match.group(1).strip()
                if self.current_rule:
                    if 'access' not in self.current_rule:
                        self.current_rule['access'] = {'allow': [], 'deny': []}
                    self.current_rule['access']['deny'].append(pattern)
                else:
                    self.global_deny.append(pattern)
            return

        # Parse server rule: bind_addr bind_port connect_addr connect_port [options]
        self.parse_server_rule(line)

    def parse_options(self, options_str):
        """Parse options from a bracket-enclosed, comma-separated string."""
        options = {}
        for opt in options_str.split(','):
            opt = opt.strip()
            if '=' not in opt:
                continue
            key, value = opt.split('=', 1)
            key = key.strip()
            value = value.strip()
            if key == 'timeout':
                options['timeout'] = int(value)
            elif key == 'src':
                options['src'] = value
            elif key == 'keepalive':
                options['keepalive'] = value.lower() in ('on', 'true', '1', 'yes')
            elif key == 'dns-refresh':
                options['dns_refresh'] = int(value)
            elif key == 'mode':
                options['mode'] = value
        return options

    def parse_server_rule(self, line):
        """Parse a server forwarding rule."""
        # Extract bracketed options first
        options_str = ''
        options_match = re.search(r'\[([^\]]*)\]', line)
        if options_match:
            options_str = options_match.group(1)
            line = line[:options_match.start()].strip()

        options = self.parse_options(options_str)

        parts = line.split()
        if len(parts) < 2:
            return

        # Determine bind address and port based on unix: prefix
        bind_addr = parts[0]
        if bind_addr.startswith('unix:'):
            bind_port = None
            remaining = parts[1:]
        else:
            if len(parts) < 3:
                return
            bind_port = parts[1]
            remaining = parts[2:]

        # Determine connect address and port
        if not remaining:
            return
        connect_addr = remaining[0]
        if connect_addr.startswith('unix:'):
            connect_port = None
        else:
            if len(remaining) < 2:
                return
            connect_port = remaining[1]

        # Determine protocol from port (default tcp)
        protocol = 'tcp'
        if bind_port and '/' in bind_port:
            bind_port, protocol = bind_port.rsplit('/', 1)

        # Format bind address
        if bind_addr.startswith('unix:'):
            bind_str = bind_addr
        elif ':' in bind_addr and not bind_addr.startswith('['):
            bind_str = f"[{bind_addr}]:{bind_port}/{protocol}"
        else:
            bind_str = f"{bind_addr}:{bind_port}/{protocol}"

        # Create rule
        rule = OrderedDict()
        rule['name'] = f"rule-{len(self.rules) + 1}"
        rule['bind'] = bind_str

        # Create backend destination
        connect_protocol = protocol
        if connect_port and '/' in connect_port:
            connect_port, connect_protocol = connect_port.rsplit('/', 1)

        if connect_addr.startswith('unix:'):
            dest_str = connect_addr
        elif ':' in connect_addr and not connect_addr.startswith('['):
            dest_str = f"[{connect_addr}]:{connect_port}/{connect_protocol}"
        else:
            dest_str = f"{connect_addr}:{connect_port}/{connect_protocol}"

        backend = OrderedDict()
        backend['dest'] = dest_str

        if 'src' in options:
            backend['src'] = options['src']
        if 'dns_refresh' in options:
            backend['dns_refresh'] = options['dns_refresh']

        rule['connect'] = [backend]

        # Add other options
        if 'timeout' in options:
            rule['timeout'] = options['timeout']
        if 'keepalive' in options:
            rule['keepalive'] = options['keepalive']
        if 'mode' in options:
            rule['mode'] = options['mode']

        self.rules.append(rule)
        self.current_rule = rule

    def parse_file(self, f):
        """Parse a configuration file."""
        for line in f:
            self.parse_line(line)


def quote_if_needed(s):
    """Quote a string if it contains special YAML characters."""
    if any(c in s for c in ':{}[]&*#?|-><!%@`"\''):
        return f'"{s}"'
    return s


def generate_yaml(parser):
    """Generate YAML output from parsed configuration."""
    lines = []
    lines.append("# rinetd-uv YAML configuration")
    lines.append("# Converted from legacy format")
    lines.append("")

    # Print warnings as comments
    for warning in parser.warnings:
        lines.append(f"# {warning}")
    if parser.warnings:
        lines.append("")

    # Global section
    if parser.global_options or parser.global_allow or parser.global_deny:
        lines.append("global:")
        for key, value in parser.global_options.items():
            # Handle status block separately
            if key == 'status':
                lines.append("  status:")
                if 'enabled' in value:
                    lines.append(f"    enabled: {str(value['enabled']).lower()}")
                if 'file' in value:
                    lines.append(f"    file: {quote_if_needed(value['file'])}")
                if 'interval' in value:
                    lines.append(f"    interval: {value['interval']}")
                if 'format' in value:
                    lines.append(f"    format: {value['format']}")
            elif isinstance(value, bool):
                lines.append(f"  {key}: {str(value).lower()}")
            elif isinstance(value, int):
                lines.append(f"  {key}: {value}")
            else:
                lines.append(f"  {key}: {quote_if_needed(value)}")

        # Note: Global allow/deny not directly supported in YAML format
        # They should be added to each rule
        if parser.global_allow or parser.global_deny:
            lines.append("  # Note: Global access rules should be added to each rule's access section")
            for pattern in parser.global_allow:
                lines.append(f"  # global allow: {pattern}")
            for pattern in parser.global_deny:
                lines.append(f"  # global deny: {pattern}")

        lines.append("")

    # Rules section
    if parser.rules:
        lines.append("rules:")
        for rule in parser.rules:
            lines.append(f"  - name: {quote_if_needed(rule['name'])}")
            lines.append(f"    bind: {quote_if_needed(rule['bind'])}")

            if 'connect' in rule:
                backends = rule['connect']
                if len(backends) == 1 and 'src' not in backends[0] and 'dns_refresh' not in backends[0]:
                    # Simple single backend with no options - use scalar form
                    lines.append(f"    connect: {quote_if_needed(backends[0]['dest'])}")
                else:
                    # Multiple backends or with options - use list form
                    lines.append("    connect:")
                    for backend in backends:
                        lines.append(f"      - dest: {quote_if_needed(backend['dest'])}")
                        if 'src' in backend:
                            lines.append(f"        src: {quote_if_needed(backend['src'])}")
                        if 'dns_refresh' in backend:
                            lines.append(f"        dns_refresh: {backend['dns_refresh']}")

            if 'timeout' in rule:
                lines.append(f"    timeout: {rule['timeout']}")
            if 'keepalive' in rule:
                lines.append(f"    keepalive: {str(rule['keepalive']).lower()}")
            if 'mode' in rule:
                lines.append(f"    mode: \"{rule['mode']}\"")

            if 'access' in rule:
                access = rule['access']
                if access['allow'] or access['deny']:
                    lines.append("    access:")
                    if access['allow']:
                        lines.append("      allow:")
                        for pattern in access['allow']:
                            lines.append(f"        - {quote_if_needed(pattern)}")
                    if access['deny']:
                        lines.append("      deny:")
                        for pattern in access['deny']:
                            lines.append(f"        - {quote_if_needed(pattern)}")

            lines.append("")

    return '\n'.join(lines)


def main():
    parser_arg = argparse.ArgumentParser(
        description='Convert legacy rinetd-uv.conf to YAML format'
    )
    parser_arg.add_argument(
        'input',
        nargs='?',
        type=argparse.FileType('r'),
        default=sys.stdin,
        help='Input configuration file (default: stdin)'
    )
    args = parser_arg.parse_args()

    config_parser = LegacyConfigParser()
    config_parser.parse_file(args.input)

    if args.input != sys.stdin:
        args.input.close()

    # Print warnings to stderr
    for warning in config_parser.warnings:
        print(warning, file=sys.stderr)

    print(generate_yaml(config_parser))


if __name__ == '__main__':
    main()
