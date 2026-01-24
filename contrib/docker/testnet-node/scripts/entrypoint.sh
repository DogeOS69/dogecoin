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

# Build command
CMD="$DOGECOIND"
CMD="$CMD -datadir=$DATA_DIR"
CMD="$CMD -testnet"  # Must be on CLI - conf file testnet=1 doesn't set datadir path correctly
CMD="$CMD -printtoconsole"  # Log to stdout for docker logs
CMD="$CMD -rpcbind=0.0.0.0"  # Must be on CLI for docker port forwarding
CMD="$CMD -rpcallowip=0.0.0.0/0"  # Allow RPC from any IP (docker network)
CMD="$CMD -rpcuser=${RPC_USER:-shadowfork}"
CMD="$CMD -rpcpassword=${RPC_PASS:-shadowfork_testnet_password}"

if [ -f "$CONF_FILE" ]; then
    CMD="$CMD -conf=$CONF_FILE"
else
    echo "WARNING: Config file not found at $CONF_FILE"
fi

# Add any extra arguments passed to the container
if [ "$1" != "dogecoind" ]; then
    # If first arg is not 'dogecoind', add all args
    CMD="$CMD $@"
elif [ $# -gt 1 ]; then
    # Skip 'dogecoind' and add remaining args
    shift
    CMD="$CMD $@"
fi

echo "Starting: $CMD"
echo "==========================="
exec $CMD
