#include <groth16/groth16.hpp>
using namespace bls12_381;

namespace bls12_381_groth16
{

    bool deserializeG1FromVector(bls12_381::g1 *out, const std::vector<unsigned char> *v, size_t startIndex)
    {
        if (v->size() < (48 + startIndex))
        {
            return false;
        }
        std::array<unsigned char, 48> s1;
        std::copy(v->begin() + startIndex, v->begin() + startIndex + 48, s1.begin());
        auto g1Option = g1::fromCompressedMCLBytesLE(s1);
        if (!g1Option.has_value())
        {
            return false;
        }
        else
        {
            *out = g1Option.value();
            return true;
        }
    }
    bool deserializeScalarFromVector(std::array<uint64_t, 4> &out, const std::vector<unsigned char> *v, size_t startIndex)
    {
        if (v->size() < (32 + startIndex))
        {
            return false;
        }
        auto x = (v->data() + startIndex);
        const tcb::span<const unsigned char, 32> s(x, 32);
        auto k = scalar::fromBytesLE<4>(s);
        out[0] = k[0];
        out[1] = k[1];
        out[2] = k[2];
        out[3] = k[3];
        return true;
    }
    int deserializeProofWith2PublicInputs(
        Groth16ProofWith2PublicInputs *proof,
        const std::vector<unsigned char> *pi_1,
        const std::vector<unsigned char> *pi_2_0,
        const std::vector<unsigned char> *pi_2_1,
        const std::vector<unsigned char> *pi_3,
        const std::vector<unsigned char> *public_input_0,
        const std::vector<unsigned char> *public_input_1)
    {
        if (pi_1->size() != 48 || pi_2_0->size() != 48 || pi_2_1->size() != 48 || pi_3->size() != 48 || public_input_0->size() != 32 || public_input_1->size() != 32)
        {
            return 0;
        }
        if (!deserializeG1FromVector(&proof->pi_1, (const std::vector<unsigned char> *)pi_1, 0))
        {
            return 0;
        }

        std::array<unsigned char, 96> pi_2_data;
        std::copy(pi_2_0->begin(), pi_2_0->end(), pi_2_data.begin());
        std::copy(pi_2_1->begin(), pi_2_1->end(), pi_2_data.begin() + 48);
        auto pi_2_v = g2::fromCompressedMCLBytesLE(pi_2_data);
        if (!pi_2_v.has_value())
        {
            return 0;
        }
        proof->pi_2 = pi_2_v.value();
        if (!deserializeG1FromVector(&proof->pi_3, (const std::vector<unsigned char> *)pi_3, 0))
        {
            return 0;
        }
        if (!deserializeScalarFromVector(proof->public_input_0, (const std::vector<unsigned char> *)public_input_0, 0))
        {
            return 0;
        }
        if (!deserializeScalarFromVector(proof->public_input_1, (const std::vector<unsigned char> *)public_input_1, 0))
        {
            return 0;
        }
        return 1;
    }

    int deserializeVerifierKeyInput(
        Groth16VerifierKeyInput *vk,
        const std::vector<unsigned char> *a,
        const std::vector<unsigned char> *b,
        const std::vector<unsigned char> *c,
        const std::vector<unsigned char> *d,
        const std::vector<unsigned char> *e,
        const std::vector<unsigned char> *f)
    {
        if (a->size() != 80 || b->size() != 80 || c->size() != 80 || d->size() != 80 || e->size() != 80 || f->size() != 80)
        {
            return 0;
        }
        std::array<unsigned char, 480> vkey_tmp_data;
        std::copy(a->begin(), a->end(), vkey_tmp_data.begin());
        std::copy(b->begin(), b->end(), vkey_tmp_data.begin() + 80);
        std::copy(c->begin(), c->end(), vkey_tmp_data.begin() + 160);
        std::copy(d->begin(), d->end(), vkey_tmp_data.begin() + 240);
        std::copy(e->begin(), e->end(), vkey_tmp_data.begin() + 320);
        std::copy(f->begin(), f->end(), vkey_tmp_data.begin() + 400);

        std::array<unsigned char, 48> g1_data;
        size_t ptr = 0;
        std::copy(vkey_tmp_data.begin(), vkey_tmp_data.begin() + 48, g1_data.begin());
        auto g1_option = g1::fromCompressedMCLBytesLE(g1_data);
        if (!g1_option.has_value())
        {
            return 0;
        }
        vk->alpha = g1_option.value();
        ptr += 48;

        std::copy(vkey_tmp_data.begin() + ptr, vkey_tmp_data.begin() + ptr + 48, g1_data.begin());
        g1_option = g1::fromCompressedMCLBytesLE(g1_data);
        if (!g1_option.has_value())
        {
            return 0;
        }
        vk->k[0] = g1_option.value();
        ptr += 48;

        std::copy(vkey_tmp_data.begin() + ptr, vkey_tmp_data.begin() + ptr + 48, g1_data.begin());
        g1_option = g1::fromCompressedMCLBytesLE(g1_data);
        if (!g1_option.has_value())
        {
            return 0;
        }
        vk->k[1] = g1_option.value();
        ptr += 48;

        std::copy(vkey_tmp_data.begin() + ptr, vkey_tmp_data.begin() + ptr + 48, g1_data.begin());
        g1_option = g1::fromCompressedMCLBytesLE(g1_data);
        if (!g1_option.has_value())
        {
            return 0;
        }
        vk->k[2] = g1_option.value();
        ptr += 48;

        std::array<unsigned char, 96> g2_data;
        std::copy(vkey_tmp_data.begin() + ptr, vkey_tmp_data.begin() + ptr + 96, g2_data.begin());
        auto g2_option = g2::fromCompressedMCLBytesLE(g2_data);
        if (!g2_option.has_value())
        {
            return 0;
        }
        vk->beta = g2_option.value();
        ptr += 96;

        std::copy(vkey_tmp_data.begin() + ptr, vkey_tmp_data.begin() + ptr + 96, g2_data.begin());
        g2_option = g2::fromCompressedMCLBytesLE(g2_data);
        if (!g2_option.has_value())
        {
            return 0;
        }
        vk->delta = g2_option.value();
        ptr += 96;


        std::copy(vkey_tmp_data.begin() + ptr, vkey_tmp_data.begin() + ptr + 96, g2_data.begin());
        g2_option = g2::fromCompressedMCLBytesLE(g2_data);
        if (!g2_option.has_value())
        {
            return 0;
        }
        vk->gamma = g2_option.value();
        ptr += 96;
        return 1;
    }
    int precomputeVerifierKey(Groth16VerifierKeyPrecomputedValues *precomputed, const Groth16VerifierKeyInput *vk)
    {
        std::vector<std::tuple<g1, g2>> v;
        pairing::add_pair(v, vk->alpha, vk->beta);
        // pre-compute e(α, β)
        precomputed->eAlphaBeta = pairing::calculate(v);
        precomputed->deltaNeg = vk->delta.negate();
        precomputed->gammaNeg = vk->gamma.negate();
        return 1;
    }
    int verifyProofWith2PublicInputs(
        const Groth16ProofWith2PublicInputs *proof,
        const Groth16VerifierKeyInput *vk,
        const Groth16VerifierKeyPrecomputedValues *precomputed)
    {
        // [Σᵥ (Kᵥ₊₁ * publicInputs[v])]₁
        g1 sumKTimesPub = vk->k[0];


        //  sumKTimesPub += K₁ * publicInputs[0]
        sumKTimesPub.addAssign(vk->k[1].scale(proof->public_input_0));


        //  sumKTimesPub += K₂ * publicInputs[1]
        sumKTimesPub.addAssign(vk->k[2].scale(proof->public_input_1));


        std::vector<std::tuple<g1, g2>> v;
        pairing::add_pair(v, proof->pi_1, proof->pi_2);
        pairing::add_pair(v, sumKTimesPub, precomputed->gammaNeg);
        pairing::add_pair(v, proof->pi_3, precomputed->deltaNeg);

        fp12 z = pairing::miller_loop(v, std::function<void()>());
        pairing::final_exponentiation(z);
        if(z.equal(precomputed->eAlphaBeta)){
            return 1;
        }else{
            return 0;
        }
    }

}