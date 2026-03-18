#!/bin/bash
set -e

# Entrypoint for Dogecoin testnet node
# Supports both built-in binaries (multi-stage) and mounted binaries

# Find dogecoind binary
if [ -x "/usr/local/bin/dogecoind" ]; then
    DOGECOIND="/usr/local/bin/dogecoind"
elif [ -x "/opt/dogecoin/bin/dogecoind" ]; then
    DOGECOIND="/opt/dogecoin/bin/dogecoind"
elif command -v dogecoind &> /dev/null; then
    DOGECOIND="dogecoind"
else
    echo "ERROR: dogecoind binary not found"
    echo "Expected at /usr/local/bin/dogecoind (multi-stage build)"
    echo "Or mount to /opt/dogecoin/bin/dogecoind"
    exit 1
fi

DATA_DIR="${DOGECOIN_DATA:-/data}"
CONF_FILE="${DOGECOIN_CONF:-/config/dogecoin.conf}"

echo "=== Dogecoin Testnet Node ==="
echo "Binary: $DOGECOIND"
echo "Data: $DATA_DIR"
echo "Config: $CONF_FILE"

# Ensure testnet3 subdirectory exists (dogecoind creates it, but we verify)
mkdir -p "$DATA_DIR/testnet3"

# Build command as an argv array so extra args are passed safely.
CMD=(
    "$DOGECOIND"
    "-datadir=$DATA_DIR"
    "-testnet"  # Must be on CLI - conf file testnet=1 doesn't set datadir path correctly
    "-printtoconsole"  # Log to stdout for docker logs
    "-rpcbind=0.0.0.0"  # Must be on CLI for docker port forwarding
    "-rpcallowip=0.0.0.0/0"  # Allow RPC from any IP (docker network)
    "-rpcuser=${RPC_USER:-shadowfork}"
    "-rpcpassword=${RPC_PASS:-shadowfork_testnet_password}"
)

if [ -f "$CONF_FILE" ]; then
    CMD+=("-conf=$CONF_FILE")
else
    echo "WARNING: Config file not found at $CONF_FILE"
fi

# Skip a redundant dogecoind executable passed in via docker-compose `command`.
if [ $# -gt 0 ]; then
    first_arg="${1##*/}"
    if [ "$first_arg" = "dogecoind" ]; then
        shift
    fi
fi

if [ $# -gt 0 ]; then
    CMD+=("$@")
fi

echo "Starting: ${CMD[*]}"
echo "==========================="
exec "${CMD[@]}"
