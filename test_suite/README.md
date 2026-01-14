# Rinetd-uv Test Suite

This directory contains a comprehensive test suite for `rinetd-uv`.

## Prerequisites

- Python 3.13+
- Valgrind (optional, for leak detection)
- `rinetd-uv` binary (built in `src/` or available in PATH)

## Setup

1. Create a virtual environment:
   ```bash
   python3 -m venv venv
   ```

2. Install dependencies:
   ```bash
   ./venv/bin/pip install -r requirements.txt
   ```

## Running Tests

Run all tests:
```bash
./venv/bin/pytest -v
```

Run only quick tests:
```bash
./venv/bin/pytest -v -m quick
```

Run with Valgrind leak detection:
```bash
./venv/bin/pytest -v --valgrind
```

Specify custom path to `rinetd-uv`:
```bash
./venv/bin/pytest -v --rinetd-path /path/to/rinetd-uv
```

## Test Structure

- `conftest.py`: Pytest fixtures for managing `rinetd-uv` and echo servers.
- `servers.py`: Upstream echo servers (TCP, UDP, Unix).
- `utils.py`: Helper functions for data generation, checksums, and config creation.
- `test_transfer.py`: Functional tests for data forwarding.
- `test_config.py`: Tests for configuration directives.
- `test_stress.py`: Concurrency and stress tests.
- `test_leaks.py`: Memory and descriptor leak tests.
