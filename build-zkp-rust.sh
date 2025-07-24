#!/bin/bash
# filepath: /home/work/dogecoin/build-zkp-rust.sh

set -e

# Define colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Display colored information
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Check required tools
command -v cargo >/dev/null 2>&1 || { error "cargo is required, please install Rust toolchain"; }

# Set paths
DOGECOIN_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZKP_DIR="${DOGECOIN_ROOT}/src/zkp-verifier"

# Determine build architecture
TARGET_ARCH="${CARGO_BUILD_TARGET:-native}"
info "Build architecture: ${TARGET_ARCH}"

# Set cargo target directory
if [ "$TARGET_ARCH" = "native" ]; then
    CARGO_TARGET_DIR="${DOGECOIN_ROOT}/depends/native/cargo-target"
else
    CARGO_TARGET_DIR="${DOGECOIN_ROOT}/depends/${TARGET_ARCH}/cargo-target"
fi
info "Cargo target directory: ${CARGO_TARGET_DIR}"

# Ensure the target directory exists
mkdir -p "$CARGO_TARGET_DIR"

# Build the Rust library
info "Building Rust ZKP verification library..."
cd "${ZKP_DIR}"
if [ "$TARGET_ARCH" != "native" ]; then
    cargo build --release --target "${TARGET_ARCH}" --target-dir "$CARGO_TARGET_DIR" || error "Rust cross-compilation failed"
else
    cargo build --release --target-dir "$CARGO_TARGET_DIR" || error "Rust build failed"
fi

# Check if library was generated
if [ "$TARGET_ARCH" = "native" ]; then
    case "$(uname -s)" in
        Darwin)
            ZKP_LIB_PATH="${CARGO_TARGET_DIR}/release/libzkp_verifier.dylib"
            ;;
        *)
            ZKP_LIB_PATH="${CARGO_TARGET_DIR}/release/libzkp_verifier.so"
            ;;
    esac
else
    case "${TARGET_ARCH}" in
        *-apple-darwin)
            ZKP_LIB_PATH="${CARGO_TARGET_DIR}/${TARGET_ARCH}/release/libzkp_verifier.dylib"
            ;;
        *-windows-*)
            ZKP_LIB_PATH="${CARGO_TARGET_DIR}/${TARGET_ARCH}/release/libzkp_verifier.a"
            ;;
        *)
            ZKP_LIB_PATH="${CARGO_TARGET_DIR}/${TARGET_ARCH}/release/libzkp_verifier.so"
            ;;
    esac
fi

if [ ! -f "${ZKP_LIB_PATH}" ]; then
    error "Library not generated: ${ZKP_LIB_PATH}"
fi

# Create wrapper header file for simplified C++ interface
mkdir -p "${ZKP_DIR}/include"

cat > "${ZKP_DIR}/include/zkp_verifier_wrapper.h" << 'EOF'
// Generated wrapper header file for Rust ZKP verifier
#pragma once

#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

// ZKP verification function implemented in Rust, called from C++
bool verify_plonk_halo2_kzg_bn256_simple(
    const uint8_t* proof_data, size_t proof_len,
    const uint8_t* vk_data, size_t vk_len,
    const uint8_t* const* public_inputs,
    const size_t* input_lengths,
    size_t input_count
);

#ifdef __cplusplus
} // extern "C"
#endif
EOF

success "ZKP library built successfully"