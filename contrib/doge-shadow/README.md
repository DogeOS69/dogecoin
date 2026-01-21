# doge-shadow: Shadow Fork CLI for Dogecoin

A CLI tool for orchestrating shadow fork instances of Dogecoin Core for local development and testing.

## Overview

Shadow fork mode allows you to fork from mainnet or testnet at a specific block height and run a local, isolated instance with:

- **Trivial mining**: Bypass AuxPoW, mine blocks instantly
- **Sentinel signatures**: Bypass ECDSA verification with a magic signature
- **Fast coinbase maturity**: Default 1 block instead of 240
- **Network isolation**: No P2P connections

## Building

```bash
cd contrib/doge-shadow
cargo build --release
```

## Usage

### Start a Shadow Fork

```bash
# Fork from mainnet at height 5000000
doge-shadow start --height 5000000 --chain main

# Fork from testnet with custom maturity
doge-shadow start --height 1000000 --chain test --maturity 10
```

### Mine Blocks

```bash
# Mine a single block
doge-shadow mine-block --address <your-address>

# Mine blocks at regular intervals
doge-shadow mine-interval --interval 10 --address <your-address>
```

### Stop the Instance

```bash
doge-shadow stop
```

### Step Through Canonical Blocks

Replay blocks from a running mainnet/testnet node to advance the shadow chain:

```bash
# Step forward 1 block from source mainnet node
doge-shadow step --source-rpcport 22555 --rpcport 32555

# Step forward 10 blocks
doge-shadow step --source-rpcport 22555 --count 10

# Step to a specific height
doge-shadow step --source-rpcport 22555 --to-height 5000100

# With datadirs for cookie auth (required for temp datadirs)
doge-shadow step --source-rpcport 22555 \
                 --source-datadir ~/.dogecoin \
                 --rpcport 32555 \
                 --datadir /tmp/shadow-datadir
```

**Important**: Once you mine a local block on the shadow chain, the chain diverges from the canonical chain and stepping is disabled. This ensures you can only step while following the exact mainnet/testnet history.

**Prerequisites**:
- Source node (mainnet/testnet) running with RPC enabled
- Shadow fork node running
- If using cookie auth with temp datadirs, specify `--datadir` for each node

### Get Sentinel Signature

```bash
# Print the magic signature that bypasses CHECKSIG
doge-shadow sentinel-sig
```

## Sentinel Signature

The sentinel signature is a minimal DER-encoded signature with r=1, s=1:

```
30 06 02 01 01 02 01 01 [hashtype]
```

Use this signature to spend any UTXO in shadow fork mode without needing the private key. This enables:

- Testing transaction flows with real mainnet/testnet UTXOs
- CI testing without managing test keys
- Rapid protocol development iteration

## Configuration

Options can be set via command-line arguments, environment variables, or a TOML config file. Precedence: CLI > environment > config file.

### Environment Variables

Common options can be set via `DOGE_SHADOW_*` environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `DOGE_SHADOW_CHAIN` | Source chain: main/test | main |
| `DOGE_SHADOW_MATURITY` | Coinbase maturity | 1 |
| `DOGE_SHADOW_RPCPORT` | Shadow node RPC port | 32555 |
| `DOGE_SHADOW_DATADIR` | Shadow node datadir | (auto) |
| `DOGE_SHADOW_SOURCE_RPCPORT` | Source node RPC port | (required for step) |
| `DOGE_SHADOW_SOURCE_DATADIR` | Source node datadir | (auto) |
| `DOGE_SHADOW_CLI` | Path to dogecoin-cli | dogecoin-cli |
| `DOGE_SHADOW_DOGECOIND` | Path to dogecoind | dogecoind |
| `DOGE_SHADOW_ADDRESS` | Mining address | (required for mining) |
| `DOGE_SHADOW_INTERVAL` | Mining interval (seconds) | 10 |

**Additional env vars** (supported but typically set via CLI):
- `DOGE_SHADOW_HEIGHT`: Fork height for start command (usually varies per instance)

**CLI-only options** (no env/config support):
- `--count` (mine-interval, step): Block counts vary per invocation
- `--to-height` (step): Target height varies per invocation
- `--hashtype` (sentinel-sig): Rarely changed from default

Example:

```bash
export DOGE_SHADOW_CHAIN=main
export DOGE_SHADOW_ADDRESS=D6...abc
export DOGE_SHADOW_SOURCE_RPCPORT=22555

doge-shadow start --height 5000000  # --height required on CLI
doge-shadow mine-block              # Uses DOGE_SHADOW_ADDRESS
doge-shadow step                    # Uses DOGE_SHADOW_SOURCE_RPCPORT
```

### Config File

Config files are loaded from (in order, later overrides earlier):

1. `/etc/doge-shadow/config.toml` (system-wide)
2. `~/.config/doge-shadow/config.toml` (user config)
3. `~/.doge-shadow.toml` (home directory)
4. `./doge-shadow.toml` (current directory)

Example config file:

```toml
# ~/.config/doge-shadow/config.toml

# Default chain to fork from
chain = "main"

# Shadow node RPC port
rpcport = 32555

# Source node for stepping
source_rpcport = 22555
source_datadir = "/home/user/.dogecoin"

# Mining settings
address = "D6abc123..."
interval = 10

# Binary paths (if not in PATH)
# cli = "/opt/dogecoin/bin/dogecoin-cli"
# dogecoind = "/opt/dogecoin/bin/dogecoind"
```

## Direct dogecoind Usage

You can also use shadow fork mode directly with dogecoind:

```bash
dogecoind -shadowfork=5000000 \
          -shadowforkchain=main \
          -shadowforkmaturity=1 \
          -listen=0 \
          -dnsseed=0
```

## Architecture

Shadow fork mode is implemented as a new chain type in Dogecoin Core:

1. **CShadowForkParams**: Chain params that inherit from mainnet/testnet
2. **SentinelSignatureChecker**: Wrapper that bypasses CHECKSIG for magic signatures
3. **Trivial PoW**: powLimit set to maximum, fPowNoRetargeting enabled
4. **Network isolation**: Unique magic bytes prevent accidental P2P connections

## Security Considerations

Shadow fork mode is intended for **development and testing only**. The sentinel signature bypass means anyone can spend any UTXO, making it completely unsuitable for real value transfer.

The implementation ensures:
- Shadow fork mode cannot be accidentally enabled
- Network isolation prevents contamination of real networks
- Clear logging when shadow fork mode is active
