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
