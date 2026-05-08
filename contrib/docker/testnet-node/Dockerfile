# Dockerfile for Dogecoin Node (supports mainnet and testnet via NETWORK env var)
# Multi-stage build: compiles dogecoind in container for library compatibility
#
# Build from repo root:
#   docker build -f contrib/docker/testnet-node/Dockerfile -t dogecoin:latest-shadowfork .
#
# Run (testnet, default):
#   docker run -v testnet-data:/data -p 44555:44555 -p 44556:44556 dogecoin:latest-shadowfork
# Run (mainnet):
#   docker run -e NETWORK=mainnet -v mainnet-data:/data -p 22555:22555 -p 22556:22556 dogecoin:latest-shadowfork

# =============================================================================
# Stage 1: Build dogecoind from source
# =============================================================================
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive
ARG UBUNTU_APT_MIRROR=
ARG UBUNTU_SECURITY_MIRROR=

# Install build dependencies
# Note: libboost-all-dev ensures complete Boost installation with all linking deps
RUN if [ -n "$UBUNTU_APT_MIRROR" ]; then \
        sed -i "s|http://archive.ubuntu.com/ubuntu|$UBUNTU_APT_MIRROR|g" /etc/apt/sources.list; \
    fi \
    && if [ -n "$UBUNTU_SECURITY_MIRROR" ]; then \
        sed -i "s|http://security.ubuntu.com/ubuntu|$UBUNTU_SECURITY_MIRROR|g" /etc/apt/sources.list; \
    fi \
    && sed -i '/jammy-backports/d' /etc/apt/sources.list \
    && apt-get -o Acquire::ForceIPv4=true update && apt-get install -y --no-install-recommends \
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

# Worktrees checked out from Windows can carry CRLF endings. Normalize only
# build-control text files inside the image so shell/autotools scripts execute.
RUN find . -type f \( \
        -name '*.sh' -o \
        -name '*.ac' -o \
        -name '*.am' -o \
        -name '*.m4' -o \
        -name '*.mk' -o \
        -name '*.in' -o \
        -name 'Makefile*' -o \
        -path './build-aux/*' -o \
        -path './depends/config.*' -o \
        -path './src/secp256k1/build-aux/*' -o \
        -path './src/univalue/build-aux/*' \
    \) -exec sed -i 's/\r$//' {} +

ARG STRIP_BINARIES=1

# Build dogecoind with wallet support (needed for generatetoaddress mining).
# --with-incompatible-bdb: accept system BDB 5.3 (matches libdb5.3++-dev above).
# Strip binaries by default to reduce image size.
RUN ./autogen.sh \
    && ./configure \
        --disable-tests \
        --disable-bench \
        --without-gui \
        --with-incompatible-bdb \
    && make -j$(nproc) \
    && if [ "$STRIP_BINARIES" = "1" ]; then strip src/dogecoind src/dogecoin-cli; fi

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
RUN sed -i 's/\r$//' /entrypoint.sh && chmod 755 /entrypoint.sh

# Default environment
ENV DOGECOIN_DATA=/data
# Leave DOGECOIN_CONF unset by default so the entrypoint can choose a
# network-appropriate config path unless the caller explicitly overrides it.

# Expose both mainnet (22555/22556) and testnet (44555/44556) ports
EXPOSE 22555 22556 44555 44556

# Health check via RPC (port depends on NETWORK: mainnet=22555, testnet=44555)
HEALTHCHECK --interval=30s --timeout=10s --start-period=120s --retries=3 \
    CMD RPC_PORT="${RPC_PORT:-$(if [ "${NETWORK:-testnet}" = "mainnet" ]; then echo 22555; else echo 44555; fi)}" \
        && curl -sf --user "${RPC_USER:-shadowfork}:${RPC_PASS:-shadowfork_testnet_password}" \
            -d '{"jsonrpc":"1.0","method":"getblockchaininfo","params":[]}' \
            -H 'content-type: text/plain;' \
            "http://127.0.0.1:${RPC_PORT}/" || exit 1

USER dogecoin
WORKDIR /home/dogecoin

ENTRYPOINT ["/entrypoint.sh"]
CMD ["dogecoind"]
