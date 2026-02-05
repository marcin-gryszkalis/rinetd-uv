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

    def parse_line(self, line):
        """Parse a single configuration line."""
        # Remove comments
        line = re.sub(r'#.*$', '', line).strip()
        if not line:
            return

        # Parse options
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

    def parse_server_rule(self, line):
        """Parse a server forwarding rule."""
        # Handle Unix socket format: unix:/path - bind_port connect_port [options]
        # Handle IP format: addr port addr port [options]

        parts = line.split()
        if len(parts) < 4:
            return

        bind_addr = parts[0]
        bind_port = parts[1]
        connect_addr = parts[2]
        connect_port = parts[3]

        # Parse options
        options = {}
        i = 4
        while i < len(parts):
            opt = parts[i]
            if opt.startswith('timeout='):
                options['timeout'] = int(opt.split('=')[1])
            elif opt.startswith('src='):
                options['src'] = opt.split('=')[1]
            elif opt.startswith('keepalive='):
                val = opt.split('=')[1]
                options['keepalive'] = val.lower() in ('on', 'true', '1', 'yes')
            elif opt.startswith('dns-refresh='):
                options['dns_refresh'] = int(opt.split('=')[1])
            elif opt.startswith('mode='):
                options['mode'] = opt.split('=')[1]
            i += 1

        # Determine protocol from port (default tcp)
        protocol = 'tcp'
        if '/' in bind_port:
            bind_port, protocol = bind_port.rsplit('/', 1)

        # Format bind address
        if bind_addr.startswith('unix:'):
            bind_str = bind_addr
        elif ':' in bind_addr and not bind_addr.startswith('['):
            # IPv6 without brackets
            bind_str = f"[{bind_addr}]:{bind_port}/{protocol}"
        else:
            bind_str = f"{bind_addr}:{bind_port}/{protocol}"

        # Create rule
        rule = OrderedDict()
        rule['name'] = f"rule-{len(self.rules) + 1}"
        rule['bind'] = bind_str

        # Create backend destination
        connect_protocol = protocol  # Use same protocol as bind
        if '/' in connect_port:
            connect_port, connect_protocol = connect_port.rsplit('/', 1)

        if connect_addr.startswith('unix:'):
            dest_str = connect_addr
        elif ':' in connect_addr and not connect_addr.startswith('['):
            # IPv6 without brackets
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

    print(generate_yaml(config_parser))


if __name__ == '__main__':
    main()
