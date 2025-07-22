# Dogecoin OP_CHECKZKP Implementation Documentation

## Overview

This document summarizes the integration of zero-knowledge proof verification capabilities into Dogecoin Core through the new `OP_CHECKZKP` opcode. This implementation leverages Rust's memory-safe cryptographic libraries while maintaining seamless compatibility with Dogecoin's C++ codebase.

The implementation follows DIP-XXXX, supporting two verification modes:
- **Mode 0**: Groth16 proofs on the BLS12-381 curve
- **Mode 1**: PLONK proofs with Halo2/KZG on the BN256 curve

## 1. Technical Architecture

### 1.1 Component Overview

The ZK-SNARK verification system was implemented with three main components:

1. **Rust ZKP Verification Library** (`src/zkp-verifier/`)
   - Implemented as a standalone Rust crate
   - Uses `snark-verifier` and `halo2curves` for cryptographic operations
   - Exposes a C-compatible FFI interface for the C++ code to call

2. **C++ Integration Layer** (`src/zkp_stub.cpp`)
   - Provides weak symbol implementations of verification functions
   - Ensures Dogecoin can still compile and run without the Rust library
   - Loads the Rust library at runtime when available

3. **Script Interpreter Modifications** (`src/script/interpreter.cpp`)
   - Implements the `OP_CHECKZKP` opcode (reusing the unused `OP_NOP10` opcode 0xB9)
   - Parses the script stack according to DIP-XXXX specification
   - Calls the appropriate verification function based on the mode

### 1.2 Verification Flow

The implementation handles transactions containing `OP_CHECKZKP` as follows:

1. When a transaction containing `OP_CHECKZKP` is validated:
   - The script interpreter extracts the proof, verification key, and public inputs from the stack
   - The mode parameter (0 or 1) determines the verification algorithm
   - The interpreter calls the appropriate C++ function that interfaces with the Rust library
   - The Rust library performs the cryptographic verification and returns success/failure
   - The transaction is accepted only if verification succeeds

2. FFI Integration:
   - The Rust library exports C-compatible functions that can be called from C++
   - The C++ code dynamically loads these functions at runtime
   - If the Rust library isn't available, the weak symbol implementations return failure

## 2. Changed Files and Their Purpose

### 2.1 New Files

- **`src/zkp-verifier/`** - The Rust ZKP verification library
  - `Cargo.toml`: Dependencies and build configuration
  - `src/lib.rs`: Main entry point and FFI exports
  - `src/verifier.rs`: Verification implementations for both proof systems

- **`src/zkp_stub.cpp`** - Provides weak symbol implementations of verification functions

- **`build-zkp-rust.sh`** - Helper script to build the Rust library and set up the integration

### 2.2 Modified Files

- **`configure.ac`** - Added Rust toolchain detection
  - Checks for Rust and Cargo availability
  - Defines a conditional `HAVE_RUST` for the build system

- **`src/Makefile.am`** - Integrated ZKP verification library into the build system
  - Adds compilation flags and include paths
  - Links the Rust library to Dogecoin binaries
  - Provides fallback paths when Rust is unavailable

- **`src/script/interpreter.cpp`** - Implemented the `OP_CHECKZKP` opcode
  - Added case handling for both verification modes
  - Implemented stack parsing according to DIP-XXXX
  - Added error codes for ZKP verification failures

- **`src/script/script.h`** and **`src/script/script.cpp`** - Updated opcode definitions
  - Redefined `OP_NOP10` (0xB9) as `OP_CHECKZKP`
  - Added opcode names and handling

- **`src/script/script_error.h`** and **`src/script/script_error.cpp`** - Added ZKP-specific error codes
  - `SCRIPT_ERR_ZKP_VERIFY_FAILED`
  - `SCRIPT_ERR_ZKP_DESERIALIZE_FAILED`
  - `SCRIPT_ERR_ZKP_UNKNOWN_MODE`
  - And others for specific error conditions

- **`src/bitcoin-tx.cpp`** - Added support for the `-allowallopcodes` flag
  - Allows creating test transactions with `OP_CHECKZKP` opcode

- **`src/core_io.h`** and **`src/core_read.cpp`** - Enhanced script parsing
  - Added support for parsing `OP_CHECKZKP` in scripts
  - Added option to allow all opcodes when creating test transactions

- **`qa/rpc-tests/test_framework/script.py`** - Updated script opcode definitions
  - Changed `OP_NOP10` to `OP_CHECKZKP` for Python-based tests

## 3. Building and Running

### 3.1 Prerequisites

- Rust toolchain (1.70.0+)
- Standard Dogecoin build requirements (C++ compiler, autotools, etc.)

### 3.2 Build Process

The integration was designed to work with the following build process:

1. **Install Rust** (if not already installed):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source $HOME/.cargo/env
   ```

2. **Build the Rust ZKP verification library**:
   ```bash
   ./build-zkp-rust.sh
   ```
   This script compiles the Rust library and generates the necessary C++ header files.

3. **Generate the build system**:
   ```bash
   ./autogen.sh
   ```

4. **Configure the build**:
   ```bash
   ./configure --enable-c++17
   ```
   Using C++17 is recommended for compatibility with the Rust FFI integration.

5. **Compile Dogecoin**:
   ```bash
   make -j$(nproc)
   ```

## 4. Impact on Development Workflow

### 4.1 For Core Dogecoin Development

The ZKP integration was designed to have minimal impact on standard Dogecoin development:

- If Rust is not available, compilation proceeds using stub implementations
- All ZKP-related code is isolated in dedicated files
- No changes to core consensus rules beyond the new opcode
- Tests automatically skip ZKP verification when Rust is unavailable

### 4.2 For ZKP-Related Development

When working on the ZKP verification functionality:

1. Make changes to the Rust code in `src/zkp-verifier/`
2. Run `./build-zkp-rust.sh` to rebuild the Rust library
3. Run `make` to rebuild the C++ integration

## 5. References

- [DIP-XXXX: OP_CHECKZKP](https://github.com/DogeOS69/DIP-OP_CHECKZKP/blob/main/dip-xxxx.mediawiki)