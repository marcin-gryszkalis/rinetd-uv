# Dockerfile for rinetd-uv
# https://github.com/marcin-gryszkalis/rinetd-uv

# Multi-stage build: build stage + minimal runtime stage
#
# Build:
#   docker build --build-arg VERSION=$(cat VERSION) -t rinetd-uv .
#
# Run:
#   docker run --rm --name rinetd-uv --ulimit nofile=65000 --publish 127.0.0.1:8080:8080 --publish 127.0.0.1:5353:5353/udp --volume ./rinetd-uv.conf:/etc/rinetd-uv.conf:ro rinetd-uv
#

# =============================================================================
# Build stage
# =============================================================================
FROM debian:trixie-slim AS base
FROM base AS builder

# Install build dependencies
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    build-essential \
    autoconf \
    automake \
    pkg-config \
    libuv1-dev \
    peg \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .
RUN autoreconf -fiv \
    && ./configure --prefix=/usr --sysconfdir=/etc CFLAGS="-O2 -DNDEBUG -Wall -Wextra -Werror" LDFLAGS="-s" \
    && make

# =============================================================================
# Runtime stage
# =============================================================================
FROM base
ARG VERSION=2.0.0

# Install runtime dependencies only
# netbase provides /etc/services for resolving service names (http, https, etc.)
# Prepare runtime files to be modified by nobody
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    libuv1 \
    netbase \
 && rm -rf /var/lib/apt/lists/* \
 && touch /var/log/rinetd-uv.log /var/run/rinetd-uv.pid \
 && chown nobody:nogroup /var/log/rinetd-uv.log /var/run/rinetd-uv.pid

# Copy built binary from builder stage
COPY --from=builder /build/src/rinetd-uv /usr/sbin/rinetd-uv
# Copy documentation
COPY --from=builder /build/LICENSE /build/*.md /

# Run as nobody:nogroup (uid=gid=65534)
USER nobody

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
LABEL org.opencontainers.image.authors="Marcin Gryszkalis <mg@fork.pl>"
LABEL org.opencontainers.image.title="rinetd-uv"
LABEL org.opencontainers.image.description="TCP/UDP port redirector using libuv"
LABEL org.opencontainers.image.source="https://github.com/marcin-gryszkalis/rinetd-uv"
LABEL org.opencontainers.image.licenses="GPL-2.0-only"
LABEL org.opencontainers.image.version="$VERSION"
