#pragma once
#include <bls12-381/bls12-381.hpp>

namespace bls12_381_groth16 {
    typedef struct
    {
        bls12_381::g1 alpha; // [α]₁
        bls12_381::g1 k[3];  // [Kᵥ]₁ (3 => because we have two public inputs)
        bls12_381::g2 beta;  // [β]₂
        bls12_381::g2 delta; // [δ]₂
        bls12_381::g2 gamma; // [γ]₂
    } Groth16VerifierKeyInput;

    // Verifier Key Precomputed Values
    typedef struct
    {
        bls12_381::g2 deltaNeg;   // -[δ]₂
        bls12_381::g2 gammaNeg;   // -[γ]₂
        bls12_381::fp12 eAlphaBeta; // e(α, β)
    } Groth16VerifierKeyPrecomputedValues;

    int deserializeVerifierKeyInput(
        Groth16VerifierKeyInput *vk,
        const std::vector<unsigned char> *a,
        const std::vector<unsigned char> *b,
        const std::vector<unsigned char> *c,
        const std::vector<unsigned char> *d,
        const std::vector<unsigned char> *e,
        const std::vector<unsigned char> *f
    );
    
    int precomputeVerifierKey(Groth16VerifierKeyPrecomputedValues *precomputed, const Groth16VerifierKeyInput *vk);
}