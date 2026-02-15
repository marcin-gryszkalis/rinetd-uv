# Building rinetd-uv

This document describes how to build and install rinetd-uv from source.

## Quick Build

```bash
autoreconf -fiv && ./configure && make
sudo make install
```

## Build Requirements

### Required Dependencies

- **C Compiler**: GCC, LLVM or other compatible C compiler
- **GNU Autotools**:
  - autoconf (version 2.52 or later)
  - automake (version 1.18 or later recommended)
- **pkg-config**: For detecting library dependencies
- **libuv**: Event loop library (tested with version 1.51.0)
  - Development headers required (libuv-dev or libuv1-dev package)
- **libyaml**: YAML parser library (version 0.1 or later)
  - Development headers required (libyaml-dev package)

### Optional Dependencies

- **peg/leg**: PEG parser generator (only needed if modifying `src/parse.peg`)
- **roffit**: Man page to HTML converter (only needed for regenerating `index.html`)
- **pandoc**: Universal document converter (for generating documentation from Markdown)

### Test Scripts Dependencies

Python 3 and common python libraries are required to run scripts int `test/`:
- **dnspython**
- **requests**

## Installing Dependencies

### Debian/Ubuntu

```bash
sudo apt-get update
sudo apt-get install build-essential autoconf automake pkg-config libuv1-dev libyaml-dev
```

### Fedora/RHEL/CentOS

```bash
sudo dnf install gcc autoconf automake pkgconfig libuv-devel libyaml-devel
```

### macOS (Homebrew)

```bash
brew install autoconf automake pkg-config libuv libyaml
```

### Arch Linux

```bash
sudo pacman -S base-devel autoconf automake pkgconf libuv libyaml
```

### FreeBSD

```bash
pkg install autoconf automake pkgconf libuv libyaml
```

### OpenBSD

```bash
pkg_add autoconf automake libuv libyaml
```

## Build Instructions

### 1. Generate Configuration Files

Run the `autoreconf` to generate the autotools infrastructure:

```bash
autoreconf -fiv
```

#### Alternative

If `autoreconf` causes problems on your system, consider using old-style `./bootstrap` script that runs applicable autotools.

```bash
./bootstrap
```

### 2. Configure the Build

Run the configure script to detect system capabilities and create Makefiles:

```bash
./configure
```

**Common configure options:**

- `--prefix=/path/to/install` - Installation prefix (default: `/usr/local`)
- `--sysconfdir=/etc` - System configuration directory (default: `$prefix/etc`)
- `--mandir=/usr/share/man` - Man page directory (default: `$prefix/share/man`)
- `CC=compiler` - Specify C compiler
- `CFLAGS=flags` - Additional compiler flags

**Example with custom prefix:**

```bash
./configure --prefix=/opt/rinetd-uv --sysconfdir=/etc
```

**Example with debug flags:**

```bash
./configure CFLAGS="-g -O0 -DDEBUG"
```

### 3. Build

Compile rinetd-uv:

```bash
make
```

The compiled binary will be in `src/rinetd-uv`.

### 4. Install

Install rinetd-uv system-wide (requires root privileges):

```bash
sudo make install
```

This installs (assuming default prefix (`/usr/local`) is used):
- `/usr/local/sbin/rinetd-uv` - Main executable
- `/usr/local/share/man/man8/rinetd-uv.8` - Man page
- `/usr/local/etc/rinetd-uv.conf` - Example configuration file

## Development Build

If you're modifying the source code, you may need additional steps:

### Regenerating the Parser

If you modify `src/parse.peg`, you must regenerate `src/parse.c`. It should happen automatically on `make` - but one can force regeneration manually as well:

```bash
leg -o src/parse.c src/parse.peg
```

### Debug Build

For debugging with gdb:

```bash
./configure CFLAGS="-g -O0 -DDEBUG -Wall -Wextra"
make
```

### Release Build

For optimized production build:

```bash
./configure CFLAGS="-O2 -DNDEBUG"
make
```

### Cleanup

If you work on sources from GitHub, you can easily cleanup all generated files (ignored by `.gitignore`) with

```bash
git clean -Xf
```

## Testing

See: [test_suite/README.md].

## Troubleshooting

### libuv Not Found

**Error:**
```
configure: error: libuv >= 1.0 not found
```

**Solution:**
Install libuv development headers:

```bash
# Debian/Ubuntu
sudo apt-get install libuv1-dev

# Fedora/RHEL
sudo dnf install libuv-devel

# macOS
brew install libuv
```

### libyaml Not Found

**Error:**
```
configure: error: libyaml not found
```

**Solution:**
Install libyaml development headers:

```bash
# Debian/Ubuntu
sudo apt-get install libyaml-dev

# Fedora/RHEL
sudo dnf install libyaml-devel

# macOS
brew install libyaml

# Arch Linux
sudo pacman -S libyaml

# FreeBSD
pkg install libyaml
```

### peg/leg Not Found

**Error:**
```
leg: command not found
```

**Solution:**
This is only needed if you're modifying `src/parse.peg`. Install the peg parser generator:

```bash
# Debian/Ubuntu
sudo apt-get install peg

# Arch Linux
sudo pacman -S peg
```

## Uninstalling

To remove rinetd-uv from your system:

```bash
sudo make uninstall
```

## Building Distribution Packages

### Creating a Tarball

```bash
make dist
```

This creates `rinetd-uv-{VERSION}.tar.gz` and `rinetd-uv-{VERSION}.tar.zst`.

### Distribution Check

Verify the distribution tarball is complete and builds correctly:

```bash
make distcheck
```

This unpacks the tarball, builds it in a separate directory, runs tests, and verifies installation/uninstallation works correctly.

## Cross-Compilation

rinetd-uv supports cross-compilation using autotools:

### Example: Cross-Compiling for ARM

```bash
./configure --host=arm-linux-gnueabihf \
            CC=arm-linux-gnueabihf-gcc \
            PKG_CONFIG_PATH=/path/to/arm/pkgconfig
make
```

### Example: Cross-Compiling for Windows (MinGW)

```bash
./configure --host=x86_64-w64-mingw32 \
            CC=x86_64-w64-mingw32-gcc
make
```

## Platform-Specific Notes

### Linux

No special requirements. libuv is available in all major distribution repositories.

### macOS

Install dependencies via Homebrew. The build process is identical to Linux.

### FreeBSD, OpenBSD

Install dependencies with `pkg`, `portmaster` etc. The build process is identical to Linux.

### Windows

Native build support on Windows is limited, see: https://github.com/marcin-gryszkalis/rinetd-uv/issues/2
rinetd-uv can be built on Windows using:
- **MinGW/MSYS2**: follows Unix build process
- **WSL**: builds as if on Linux

## Further Information

- **Documentation**: See `DOCUMENTATION.md` for complete usage documentation
- **Man Page**: `man rinetd-uv` (after installation)
- **Changes**: See `CHANGES.md` for version history
- **Original rinetd**: https://github.com/samhocevar/rinetd
