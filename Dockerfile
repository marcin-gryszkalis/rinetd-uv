# Dockerfile for rinetd-uv
# https://github.com/marcin-gryszkalis/rinetd-uv

# Multi-stage build: build stage + minimal runtime stage
#
# Build:
#   docker build -t rinetd-uv .
#
# Run:
#   docker run -d --name rinetd-uv --user nobody --ulimit nofile=65000 --publish 8080:8080 --publish 5353:5353/udp --volume ./rinetd-uv.conf:/etc/rinetd-uv.conf:ro rinetd-uv
#

# =============================================================================
# Build stage
# =============================================================================
FROM debian:trixie AS builder

# Install build dependencies
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    build-essential \
    autoconf \
    automake \
    pkg-config \
    libuv1-dev \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Clone and build rinetd-uv from GitHub HEAD
WORKDIR /build
RUN git clone --depth 1 https://github.com/marcin-gryszkalis/rinetd-uv.git . \
    && autoreconf -fiv \
    && ./configure --prefix=/usr --sysconfdir=/etc CFLAGS="-O2 -DNDEBUG" \
    && make

# =============================================================================
# Runtime stage
# =============================================================================
FROM debian:trixie-slim

# Install runtime dependencies only
# netbase provides /etc/services for resolving service names (http, https, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libuv1 \
    netbase \
    && rm -rf /var/lib/apt/lists/*

# Copy built binary from builder stage
COPY --from=builder /build/src/rinetd-uv /usr/sbin/rinetd-uv

# Optional: create user for running rinetd-uv
# one can specify --user option to docker run
# RUN useradd -r -s /bin/false rinetd-uv
# USER rinetd-uv

# Optional: expose ports
# one can specify --publish option to docker run
# EXPOSE 8080

# Optional: health check
# HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
#     CMD nc -z localhost 8080 || exit 1

# Default configuration file location
VOLUME ["/etc/rinetd-uv.conf"]

# Run rinetd-uv in foreground mode
ENTRYPOINT ["/usr/sbin/rinetd-uv"]
CMD ["-f", "-c", "/etc/rinetd-uv.conf"]

# Labels
LABEL org.opencontainers.image.title="rinetd-uv"
LABEL org.opencontainers.image.description="TCP/UDP port redirector using libuv"
LABEL org.opencontainers.image.source="https://github.com/marcin-gryszkalis/rinetd-uv"
