#include "zkp-verifier/src/lib.rs.h"
#include <iostream>
#include <vector>

// ----- Forward declaration of the generated C++ function -----
// Must exactly match the signature in the generated header
// (out/cxxbridge/include/zkp-verifier/src/lib.rs.h),
// including the noexcept specifier and C++ linkage.
extern "C++" bool verify_plonk_halo2_kzg_bn256_simple(
    const uint8_t* proof_data,
    size_t proof_len,
    const uint8_t* vk_data,
    size_t vk_len,
    const uint8_t* const* public_inputs,
    const size_t* input_lengths,
    size_t input_count
) noexcept;

// Remaining code unchanged
namespace zkp_verifier {
    bool verifyPlonkProof(
        const uint8_t* proof_data,
        size_t proof_len,
        const uint8_t* vk_data,
        size_t vk_len,
        const uint8_t* const* public_inputs,
        const size_t* input_lengths,
        size_t input_count
    ) {
        return verify_plonk_halo2_kzg_bn256_simple(
            proof_data, proof_len,
            vk_data, vk_len,
            public_inputs, input_lengths, input_count
        );
    }

    bool verifyPlonkProofVector(
        const std::vector<uint8_t>& proof,
        const std::vector<uint8_t>& vk,
        const std::vector<std::vector<uint8_t>>& inputs
    ) {
        std::vector<const uint8_t*> ptrs;
        std::vector<size_t> lens;
        for (auto &v: inputs) {
            ptrs.push_back(v.data());
            lens.push_back(v.size());
        }
        return verifyPlonkProof(
            proof.data(), proof.size(),
            vk.data(), vk.size(),
            ptrs.data(), lens.data(), inputs.size()
        );
    }
}

extern "C" bool test_zkp_verification() {
    std::cout<<"Testing ZKP..."<<std::endl;
    std::vector<uint8_t> p(1024,1), k(2048,2);
    std::vector<std::vector<uint8_t>> in{{32,3}};
    bool ok = zkp_verifier::verifyPlonkProofVector(p,k,in);
    std::cout<<"Result="<<(ok?"T":"F")<<std::endl;
    return ok;
}