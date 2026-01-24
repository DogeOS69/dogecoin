#!/bin/bash
# Create a blockchain snapshot for bootstrapping new nodes
#
# Usage: ./create-snapshot.sh [output_file]
#
# This creates a tarball of blocks/ and chainstate/ that can be used
# to quickly bootstrap new testnet nodes without syncing from scratch.

set -e

DATADIR="${DOGECOIN_DATADIR:-$HOME/.dogecoin-testnet/testnet3}"
OUTPUT="${1:-testnet-snapshot-$(date +%Y%m%d).tar.gz}"

if [ ! -d "$DATADIR/blocks" ] || [ ! -d "$DATADIR/chainstate" ]; then
    echo "ERROR: blocks/ or chainstate/ not found in $DATADIR"
    echo "Make sure the node has synced some blocks first."
    exit 1
fi

# Check if node is running (optional safety check)
if pgrep -f "dogecoind.*testnet" > /dev/null; then
    echo "WARNING: dogecoind appears to be running."
    echo "For a consistent snapshot, stop the node first:"
    echo "  dogecoin-cli -testnet stop"
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Get current height for metadata
HEIGHT_FILE="$DATADIR/../height.txt"
if command -v dogecoin-cli &> /dev/null; then
    dogecoin-cli -testnet getblockchaininfo 2>/dev/null | grep '"blocks"' | grep -o '[0-9]*' > "$HEIGHT_FILE" || true
fi

echo "Creating snapshot from: $DATADIR"
echo "Output: $OUTPUT"

# Calculate size
BLOCKS_SIZE=$(du -sh "$DATADIR/blocks" 2>/dev/null | cut -f1)
CHAINSTATE_SIZE=$(du -sh "$DATADIR/chainstate" 2>/dev/null | cut -f1)
echo "  blocks/: $BLOCKS_SIZE"
echo "  chainstate/: $CHAINSTATE_SIZE"

# Create tarball
echo "Compressing (this may take a while)..."
cd "$DATADIR"
tar -czvf "$OUTPUT" blocks/ chainstate/

# Show result
OUTPUT_SIZE=$(du -sh "$OUTPUT" | cut -f1)
echo ""
echo "Snapshot created: $OUTPUT ($OUTPUT_SIZE)"
echo ""
echo "To restore on another machine:"
echo "  tar -xzvf $OUTPUT -C ~/.dogecoin-testnet/testnet3/"
