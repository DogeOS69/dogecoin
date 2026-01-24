# Dockerfile for Dogecoin Testnet Node
# Multi-stage build: compiles dogecoind in container for library compatibility
#
# Build from repo root:
#   docker build -f contrib/docker/testnet-node/Dockerfile -t dogecoin-testnet .
#
# Run:
#   docker run -v testnet-data:/data -p 44555:44555 -p 44556:44556 dogecoin-testnet

# =============================================================================
# Stage 1: Build dogecoind from source
# =============================================================================
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
# Note: libboost-all-dev ensures complete Boost installation with all linking deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libtool \
    autotools-dev \
    automake \
    pkg-config \
    bsdmainutils \
    python3 \
    libssl-dev \
    libevent-dev \
    libboost-all-dev \
    libdb5.3++-dev \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy source code
WORKDIR /dogecoin
COPY . .

# Build dogecoind with wallet support (needed for generatetoaddress mining).
# --with-incompatible-bdb: accept system BDB 5.3 (matches libdb5.3++-dev above).
# Strip binaries to reduce image size.
RUN ./autogen.sh \
    && ./configure \
        --disable-tests \
        --disable-bench \
        --without-gui \
        --with-incompatible-bdb \
    && make -j$(nproc) \
    && strip src/dogecoind src/dogecoin-cli

# =============================================================================
# Stage 2: Runtime image (slim Debian for smaller footprint)
# =============================================================================
FROM debian:bookworm-slim AS runtime

ENV DEBIAN_FRONTEND=noninteractive

# Runtime dependencies (Boost 1.74 matches Ubuntu 22.04 builder)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    libssl3 \
    libevent-2.1-7 \
    libevent-core-2.1-7 \
    libevent-pthreads-2.1-7 \
    libboost-system1.74.0 \
    libboost-filesystem1.74.0 \
    libboost-chrono1.74.0 \
    libboost-thread1.74.0 \
    libboost-program-options1.74.0 \
    libboost-atomic1.74.0 \
    libboost-container1.74.0 \
    libboost-date-time1.74.0 \
    libdb5.3++ \
    && rm -rf /var/lib/apt/lists/*

# Create dogecoin user
RUN useradd -r -m -d /home/dogecoin dogecoin

# Create directories
RUN mkdir -p /data /config /usr/local/bin \
    && chown -R dogecoin:dogecoin /data /config

# Copy stripped binaries from builder
COPY --from=builder /dogecoin/src/dogecoind /usr/local/bin/
COPY --from=builder /dogecoin/src/dogecoin-cli /usr/local/bin/

# Copy entrypoint script (make world-readable and executable)
COPY contrib/docker/testnet-node/scripts/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

# Default environment
ENV DOGECOIN_DATA=/data
ENV DOGECOIN_CONF=/config/dogecoin.conf

# Expose testnet ports (P2P: 44556, RPC: 44555)
EXPOSE 44555 44556

# Health check via RPC
HEALTHCHECK --interval=30s --timeout=10s --start-period=120s --retries=3 \
    CMD curl -sf --user "${RPC_USER:-test}:${RPC_PASS:-test}" \
        -d '{"jsonrpc":"1.0","method":"getblockchaininfo","params":[]}' \
        -H 'content-type: text/plain;' \
        http://127.0.0.1:44555/ || exit 1

USER dogecoin
WORKDIR /home/dogecoin

ENTRYPOINT ["/entrypoint.sh"]
CMD ["dogecoind"]
