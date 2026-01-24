# rinetd-uv - Internet Redirection Server

**rinetd-uv** is a modernized implementation of the rinetd internet redirection server, rewritten to use the [libuv](https://libuv.org/) event loop library.

Originally by Thomas Boutell and Sam Hocevar. Rewritten to libuv by Marcin Gryszkalis with help from contributors and LLMs.

This implementation maintains backward compatibility with the original rinetd configuration format while providing significantly improved performance through modern event-driven I/O.

Released under the terms of the GNU General Public License, version 2 or later.

### Note

**Windows** build fails at the moment, pull requests fixing this would be appreciated.

## About

This program efficiently redirects (proxy) TCP and UDP connections from one IP address/port combination to another. It is useful when operating virtual servers, firewalls, and similar network infrastructure.

### Key Features
- Event-driven I/O using libuv (high performance, low overhead)
- Configurable buffer sizes for memory optimization
- Zero-copy buffer forwarding
- Both TCP and UDP support
- UNIX domain sockets support
- IPv4 and IPv6 support
- Allow/deny rules for access control
- Periodic DNS refresh for dynamic backend addresses

## Documentation

- [DOCUMENTATION.md](DOCUMENTATION.md) - Complete user documentation
- [BUILD.md](BUILD.md) - Build requirements and instructions
- [CHANGES.md](CHANGES.md) - Changelog
- [SECURITY.md](CHANGES.md) - Security
- **Man page**: `man rinetd-uv` (after installation)

## Differences from Original rinetd

For detailed discussion of incompatibilities check [appriopriate section of DOCUMENTATION.md](DOCUMENTATION.md#incompatibilities) or in the manual.

Original rinetd: [https://github.com/samhocevar/rinetd]

