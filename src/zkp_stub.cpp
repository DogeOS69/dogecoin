#include <cstdint>
#include <cstddef>
#include <vector>
#include <iostream>

#ifdef HAVE_RUST
#include "zkp-verifier/target/cxxbridge/zkp-verifier/src/lib.rs.h"
#include "zkp-verifier/target/cxxbridge/rust/cxx.h"
#endif

extern "C" bool __attribute__((weak)) verify_plonk_halo2_kzg_bn256_simple(
    const uint8_t* proof_data, size_t proof_len,
    const uint8_t* vk_data, size_t vk_len,
    const uint8_t* const* public_inputs, 
    const size_t* input_lengths, 
    size_t input_count
) {
    if (!proof_data || proof_len == 0 || proof_len > 4096 ||
        !vk_data || vk_len == 0 || vk_len > 8192 ||
        (input_count > 0 && (!public_inputs || !input_lengths))) {
        std::cerr << "ZKP验证器: 无效参数" << std::endl;
        return false;
    }

#ifdef HAVE_RUST
    try {
        std::vector<uint8_t> proof_vec(proof_data, proof_data + proof_len);
        std::vector<uint8_t> vk_vec(vk_data, vk_data + vk_len);
        
        std::vector<std::vector<uint8_t>> inputs_vec;
        inputs_vec.reserve(input_count);
        
        for (size_t i = 0; i < input_count; i++) {
            if (!public_inputs[i] || input_lengths[i] == 0 || input_lengths[i] > 1024) {
                std::cerr << "ZKP验证器: 无效的公共输入 #" << i << std::endl;
                return false;
            }
            inputs_vec.emplace_back(
                public_inputs[i], 
                public_inputs[i] + input_lengths[i]
            );
        }
        
        return ::zkp_verifier::verify_plonk_halo2_kzg_bn256(
            proof_vec, 
            vk_vec, 
            inputs_vec
        );
    } catch (const std::exception& e) {
        std::cerr << "ZKP验证器异常: " << e.what() << std::endl;
        return false;
    } catch (...) {
        std::cerr << "ZKP验证器: 未知异常" << std::endl;
        return false;
    }
#else
    return true;
#endif
}