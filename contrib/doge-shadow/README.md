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
