# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
# Full build (generates dogecoind, dogecoin-cli, dogecoin-qt)
./autogen.sh
./configure
make

# Build with GUI support
./configure --with-gui

# Build without wallet (P2P node only)
./configure --disable-wallet

# Debug build
./configure --enable-debug
# or with custom flags:
./configure CXXFLAGS="-g -ggdb -O0"

# Deadlock detection build
./configure CXXFLAGS="-DDEBUG_LOCKORDER -g"
```

## Testing

```bash
# Run all unit tests
make check

# Run unit tests directly
src/test/test_bitcoin

# Run single unit test suite
src/test/test_bitcoin --run_test=getarg_tests

# Run specific test case
src/test/test_bitcoin --run_test=getarg_tests/doubledash

# Run Qt tests
src/qt/test/test_bitcoin-qt

# Run RPC/integration tests (requires python3-zmq and ltc_scrypt)
qa/pull-tester/rpc-tests.py

# Run single RPC test
qa/pull-tester/rpc-tests.py <testname>

# Run all extended tests
qa/pull-tester/rpc-tests.py -extended

# Debug RPC tests
PYTHON_DEBUG=1 qa/pull-tester/rpc-tests.py <testname>
```

## Architecture Overview

Dogecoin Core is forked from Bitcoin Core with Dogecoin-specific modifications. Key differences:

- **Scrypt PoW**: Uses Scrypt hashing instead of SHA-256
- **AuxPoW**: Auxiliary proof-of-work for merged mining (`src/auxpow.cpp`, `src/auxpow.h`)
- **Dogecoin fees**: Custom fee logic in `src/dogecoin-fees.cpp`
- **Dogecoin-specific logic**: `src/dogecoin.cpp` contains Dogecoin block reward schedule and other customizations

### Core Components

- `src/validation.cpp` - Block and transaction validation (largest file, ~199K)
- `src/net_processing.cpp` - P2P message handling (~159K)
- `src/net.cpp` - Network layer, peer connections
- `src/init.cpp` - Node initialization and startup
- `src/txmempool.cpp` - Transaction memory pool
- `src/miner.cpp` - Block template creation and mining
- `src/chainparams.cpp` - Network parameters (mainnet/testnet/regtest)

### Key Subsystems

- `src/wallet/` - Wallet functionality (optional, requires BerkeleyDB 5.3)
- `src/rpc/` - JSON-RPC interface
- `src/script/` - Script interpreter and validation
- `src/consensus/` - Consensus-critical code
- `src/primitives/` - Basic data structures (block, transaction)
- `src/qt/` - Qt GUI application
- `src/crypto/` - Cryptographic primitives
- `src/secp256k1/` - Elliptic curve library (subtree)
- `src/leveldb/` - Database storage (subtree)
- `src/univalue/` - JSON parsing (subtree)

### Network Ports

| Network | P2P Port | RPC Port |
|---------|----------|----------|
| Mainnet | 22556    | 22555    |
| Testnet | 44556    | 44555    |
| Regtest | 18444    | 18332    |

## Code Style

Uses clang-format (config in `src/.clang-format`). Key rules:
- 4-space indentation, no tabs
- Braces on new lines for namespaces/classes/functions, same line for everything else
- No namespace indentation
- Prefer `++i` over `i++`
- Use `std::` prefix (no `using namespace`)

Run `contrib/devtools/clang-format-diff.py` to format patches before submitting.

## Development Notes

- PRs should target `master` branch
- New features should be exposed via RPC first, then GUI
- Run with `-regtest` for local testing, `-testnet` for network testing
- Debug output goes to `debug.log` in data directory; use `-debug=<category>` flags
- Test with `-disablewallet` to ensure code works without wallet

## Subtrees

These directories are maintained upstream - prefer sending fixes upstream:
- `src/leveldb` - Google LevelDB
- `src/secp256k1` - Bitcoin Core secp256k1
- `src/crypto/ctaes` - Bitcoin Core ctaes
- `src/univalue` - JSON library

## Shadow Fork Mode

Shadow fork mode allows forking from mainnet/testnet state for isolated testing. Key features:

- **Trivial PoW**: Mining difficulty set to minimum (instant block generation)
- **Sentinel signatures**: Bypass signature verification to spend any UTXO
- **Chain stepping**: Import canonical blocks from source chain
- **Isolated mining**: `getblocktemplate` works without peers or during IBD

### Configuration

```bash
# Start in shadow fork mode (fork at height 1000 from testnet)
dogecoind -shadowfork=1000 -shadowforkchain=test -shadowforkmaturity=1
```

| Flag | Description |
|------|-------------|
| `-shadowfork=<height>` | Fork height (0 = genesis) |
| `-shadowforkchain=<chain>` | Source chain: `main`, `test`, or `regtest` |
| `-shadowforkmaturity=<n>` | Coinbase maturity (default: 1 for fast testing) |

### Sentinel Signatures

In shadow fork mode, a "sentinel signature" (DER-encoded r=1, s=1) bypasses CHECKSIG:

```python
# Sentinel signature bytes
SENTINEL_SIG = bytes.fromhex("3006020101020101") + bytes([0x01])  # + SIGHASH_ALL
```

This allows spending ANY UTXO without the private key - useful for testing scenarios involving real mainnet/testnet UTXOs.

### Key Files

| File | Purpose |
|------|---------|
| `src/script/interpreter.h:183-223` | SentinelSignatureChecker implementation |
| `src/chainparams.cpp` | Shadow fork chain parameters |
| `src/rpc/mining.cpp:504-516` | getblocktemplate peer/IBD bypass |
| `qa/rpc-tests/shadowfork_integration.py` | Integration tests |
| `qa/rpc-tests/test_framework/shadowfork_util.py` | Test utilities |
| `contrib/doge-shadow/` | CLI tool for shadow fork operations |

### Testing Shadow Fork

```bash
# Run standalone tests (no external dependencies)
qa/rpc-tests/shadowfork_integration.py --srcdir=src

# Run with testnet RPC source
TESTNET_RPC_URL=127.0.0.1:44555 \
TESTNET_RPC_USER=user \
TESTNET_RPC_PASS=pass \
qa/rpc-tests/shadowfork_integration.py --srcdir=src
```

### doge-shadow CLI

```bash
# Build
cd contrib/doge-shadow && cargo build --release

# Commands
doge-shadow start          # Start shadow fork instance
doge-shadow step           # Import blocks from source chain
doge-shadow mine-block     # Mine a block
doge-shadow sentinel-sig   # Get sentinel signature hex
doge-shadow info           # Get blockchain info
```

### Docker Infrastructure

See `contrib/docker/testnet-node/` for containerized testnet node setup used as shadow fork source.
