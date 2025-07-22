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
ZKP_LIB="${ZKP_DIR}/target/release/libzkp_verifier.a"
CXX_INCLUDE="${ZKP_DIR}/target/cxxbridge"

# Check if zkp-verifier directory exists
if [ ! -d "${ZKP_DIR}" ]; then
  error "zkp-verifier directory not found: ${ZKP_DIR}"
fi

info "Building Rust ZKP verification library..."

# Build Rust library
cd "${ZKP_DIR}"
if [ -n "${CARGO_BUILD_TARGET}" ]; then
  info "Cross-compiling for target: ${CARGO_BUILD_TARGET}"
  cargo build --release --target "${CARGO_BUILD_TARGET}" || error "Rust cross-compilation failed"
  # Update library path for cross-compilation with correct extension
  case "${CARGO_BUILD_TARGET}" in
    *-apple-darwin)
      ZKP_LIB="${ZKP_DIR}/target/${CARGO_BUILD_TARGET}/release/libzkp_verifier.dylib"
      ;;
    *-windows-*)
      ZKP_LIB="${ZKP_DIR}/target/${CARGO_BUILD_TARGET}/release/zkp_verifier.dll"
      ;;
    *)
      ZKP_LIB="${ZKP_DIR}/target/${CARGO_BUILD_TARGET}/release/libzkp_verifier.so"
      ;;
  esac
else
  cargo build --release || error "Rust build failed"
fi

# Check if library was generated
if [ ! -f "${ZKP_LIB}" ]; then
  error "Library not generated: ${ZKP_LIB}"
fi

# For cross-compilation, create symlinks so Makefile can find libraries at expected paths
if [ -n "${CARGO_BUILD_TARGET}" ]; then
  NATIVE_DIR="${ZKP_DIR}/target/release"
  mkdir -p "${NATIVE_DIR}"

  case "${CARGO_BUILD_TARGET}" in
    *-apple-darwin)
      ln -sf "../${CARGO_BUILD_TARGET}/release/libzkp_verifier.dylib" "${NATIVE_DIR}/libzkp_verifier.dylib"
      ;;
    *-windows-*)
      ln -sf "../${CARGO_BUILD_TARGET}/release/zkp_verifier.dll" "${NATIVE_DIR}/zkp_verifier.dll"
      ;;
    *)
      ln -sf "../${CARGO_BUILD_TARGET}/release/libzkp_verifier.so" "${NATIVE_DIR}/libzkp_verifier.so"
      ;;
  esac
  info "Created symlink for cross-compiled library"
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