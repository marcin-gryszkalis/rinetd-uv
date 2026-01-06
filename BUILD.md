# Building rinetd-uv

This document describes how to build and install rinetd-uv from source.

## Build Requirements

### Required Dependencies

- **C Compiler**: GCC, LLVM or other compatible C compiler
- **GNU Autotools**:
  - autoconf (version 2.52 or later)
  - automake (version 1.18 or later recommended)
- **pkg-config**: For detecting library dependencies
- **libuv**: Event loop library (version 1.0 or later)
  - Development headers required (libuv-dev or libuv1-dev package)

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
sudo apt-get install build-essential autoconf automake pkg-config libuv1-dev
```

### Fedora/RHEL/CentOS

```bash
sudo dnf install gcc autoconf automake pkgconfig libuv-devel
```

### macOS (Homebrew)

```bash
brew install autoconf automake pkg-config libuv
```

### Arch Linux

```bash
sudo pacman -S base-devel autoconf automake pkgconf libuv
```

## Build Instructions

### Quick Build

For most users, the following commands will build and install rinetd-uv:

```bash
./bootstrap
./configure
make
sudo make install
```

### Step-by-Step Build Process

#### 1. Generate Configuration Files

Run the bootstrap script to generate the autotools infrastructure:

```bash
./bootstrap
```

This creates:
- `configure` script
- `Makefile.in` templates
- `aclocal.m4` and related files

#### 2. Configure the Build

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
./configure --prefix=/opt/rinetd --sysconfdir=/etc
```

**Example with debug flags:**

```bash
./configure CFLAGS="-g -O0 -DDEBUG"
```

#### 3. Build

Compile rinetd-uv:

```bash
make
```

The compiled binary will be in `src/rinetd-uv`.

**Parallel build** (faster on multi-core systems):

```bash
make -j$(nproc)
```

#### 4. Install

Install rinetd-uv system-wide (requires root privileges):

```bash
sudo make install
```

This installs:
- `/usr/local/sbin/rinetd-uv` - Main executable
- `/usr/local/share/man/man8/rinetd-uv.8` - Man page
- `/usr/local/etc/rinetd-uv.conf` - Example configuration file

## Development Build

If you're modifying the source code, you may need additional steps:

### Regenerating the Parser

If you modify `src/parse.peg`, you must regenerate `src/parse.c`:

```bash
# Install peg/leg parser generator (if not already installed)
# Debian/Ubuntu: sudo apt-get install peg
# Arch Linux: sudo pacman -S peg

# Regenerate parser
cd src
leg -o parse.c parse.peg
cd ..
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

## Testing

rinetd-uv includes test scripts in the `test/` directory.

### Running Tests

**TCP tests:**

```bash
cd test
./test_tcp.sh
```

**UDP tests:**

```bash
cd test
./test_udp.sh
```

### Manual Testing

1. Create a test configuration file (e.g., `test.conf`):

```
0.0.0.0 8080 127.0.0.1 80
```

2. Run rinetd-uv in foreground mode:

```bash
./src/rinetd-uv -f -c test.conf
```

3. Test the forwarding:

```bash
curl http://localhost:8080
```

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

# From source
git clone https://github.com/westes/peg.git
cd peg
make
sudo make install
```

### Permission Denied During Install

**Error:**
```
Permission denied
```

**Solution:**
Use sudo for installation:

```bash
sudo make install
```

### Bootstrap Script Fails

**Error:**
```
./bootstrap: autoreconf: command not found
```

**Solution:**
Install autotools:

```bash
# Debian/Ubuntu
sudo apt-get install autoconf automake

# Fedora/RHEL
sudo dnf install autoconf automake
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

This creates `rinetd-uv-2.0.tar.gz` and `rinetd-uv-2.0.tar.bz2`.

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

### Windows

rinetd-uv can be built on Windows using:
- **MinGW/MSYS2**: Recommended, follows Unix build process
- **Visual Studio**: Use `rinetd.vcxproj` project file (included)
- **WSL**: Build as if on Linux

### BSD Systems

FreeBSD and OpenBSD support rinetd-uv. Install dependencies via pkg/ports:

```bash
# FreeBSD
pkg install autoconf automake pkgconf libuv

# OpenBSD
pkg_add autoconf automake libuv
```

## Memory and Performance Optimization

### Buffer Size Configuration

rinetd-uv's memory usage depends on buffer size and concurrent connections:

```
Total Memory ≈ bufferSize × concurrent_connections
```

You can configure buffer size in `rinetd-uv.conf`:

```
buffersize 32768  # 32 KB per connection
```

See `BUFFER_OPTIMIZATION.md` for detailed tuning recommendations.

## Further Information

- **Documentation**: See `DOCUMENTATION.md` for complete usage documentation
- **Man Page**: `man rinetd-uv` (after installation)
- **Performance**: See `BUFFER_OPTIMIZATION.md` for optimization tips
- **Changes**: See `CHANGES.md` for version history
- **Original rinetd**: https://github.com/samhocevar/rinetd
