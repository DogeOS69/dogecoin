#pragma once
#include <groth16/vkey.hpp>
#include <bls12-381/bls12-381.hpp>

namespace bls12_381_groth16 {
    typedef struct
    {
        bls12_381::g1 pi_1; // [π₁]₁
        bls12_381::g2 pi_2; // [π₂]₂
        bls12_381::g1 pi_3; // [π₃]₁
        std::array<uint64_t, 4> public_input_0; // public_input_0
        std::array<uint64_t, 4> public_input_1; // public_input_1
    } Groth16ProofWith2PublicInputs;

    int deserializeProofWith2PublicInputs(
        Groth16ProofWith2PublicInputs *proof,
        const std::vector<unsigned char> *pi_1,
        const std::vector<unsigned char> *pi_2_0,
        const std::vector<unsigned char> *pi_2_1,
        const std::vector<unsigned char> *pi_3,
        const std::vector<unsigned char> *public_input_0,
        const std::vector<unsigned char> *public_input_1
    );

    int verifyProofWith2PublicInputs(
        const Groth16ProofWith2PublicInputs *proof,
        const Groth16VerifierKeyInput *vk,
        const Groth16VerifierKeyPrecomputedValues *precomputed
    );

}