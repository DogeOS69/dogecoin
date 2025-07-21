// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bench.h"
#include "key.h"
#if defined(HAVE_CONSENSUS_LIB)
#include "script/bitcoinconsensus.h"
#endif
#include "script/script.h"
#include "script/sign.h"
#include "streams.h"
#include <core_io.h>

// FIXME: Dedup with BuildCreditingTransaction in test/script_tests.cpp.
static CMutableTransaction BuildCreditingTransaction(const CScript& scriptPubKey)
{
    CMutableTransaction txCredit;
    txCredit.nVersion = 1;
    txCredit.nLockTime = 0;
    txCredit.vin.resize(1);
    txCredit.vout.resize(1);
    txCredit.vin[0].prevout.SetNull();
    txCredit.vin[0].scriptSig = CScript() << CScriptNum(0) << CScriptNum(0);
    txCredit.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    txCredit.vout[0].scriptPubKey = scriptPubKey;
    txCredit.vout[0].nValue = 1;

    return txCredit;
}

// FIXME: Dedup with BuildSpendingTransaction in test/script_tests.cpp.
static CMutableTransaction BuildSpendingTransaction(const CScript& scriptSig, const CMutableTransaction& txCredit)
{
    CMutableTransaction txSpend;
    txSpend.nVersion = 1;
    txSpend.nLockTime = 0;
    txSpend.vin.resize(1);
    txSpend.vout.resize(1);
    txSpend.vin[0].prevout.hash = txCredit.GetHash();
    txSpend.vin[0].prevout.n = 0;
    txSpend.vin[0].scriptSig = scriptSig;
    txSpend.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    txSpend.vout[0].scriptPubKey = CScript();
    txSpend.vout[0].nValue = txCredit.vout[0].nValue;

    return txSpend;
}

// Microbenchmark for verification of a basic P2WPKH script. Can be easily
// modified to measure performance of other types of scripts.
static void VerifyScriptBench(benchmark::State& state)
{
    const int flags = SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH;
    const int witnessversion = 0;

    // Keypair.
    CKey key;
    const unsigned char vchKey[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    key.Set(vchKey, vchKey + 32, false);
    CPubKey pubkey = key.GetPubKey();
    uint160 pubkeyHash;
    CHash160().Write(pubkey.begin(), pubkey.size()).Finalize(pubkeyHash.begin());

    // Script.
    CScript scriptPubKey = CScript() << witnessversion << ToByteVector(pubkeyHash);
    CScript scriptSig;
    CScript witScriptPubkey = CScript() << OP_DUP << OP_HASH160 << ToByteVector(pubkeyHash) << OP_EQUALVERIFY << OP_CHECKSIG;
    CTransaction txCredit = BuildCreditingTransaction(scriptPubKey);
    CMutableTransaction txSpend = BuildSpendingTransaction(scriptSig, txCredit);
    CScriptWitness& witness = txSpend.vin[0].scriptWitness;
    witness.stack.emplace_back();
    key.Sign(SignatureHash(witScriptPubkey, txSpend, 0, SIGHASH_ALL, txCredit.vout[0].nValue, SIGVERSION_WITNESS_V0), witness.stack.back(), 0);
    witness.stack.back().push_back(static_cast<unsigned char>(SIGHASH_ALL));
    witness.stack.push_back(ToByteVector(pubkey));

    // Benchmark.
    while (state.KeepRunning()) {
        ScriptError err;
        bool success = VerifyScript(
            txSpend.vin[0].scriptSig,
            txCredit.vout[0].scriptPubKey,
            &txSpend.vin[0].scriptWitness,
            flags,
            MutableTransactionSignatureChecker(&txSpend, 0, txCredit.vout[0].nValue),
            &err);
        assert(err == SCRIPT_ERR_OK);
        assert(success);

#if defined(HAVE_CONSENSUS_LIB)
        CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
        stream << txSpend;
        int csuccess = bitcoinconsensus_verify_script_with_amount(
            txCredit.vout[0].scriptPubKey.data(),
            txCredit.vout[0].scriptPubKey.size(),
            txCredit.vout[0].nValue,
            (const unsigned char*)stream.data(), stream.size(), 0, flags, nullptr);
        assert(csuccess == 1);
#endif
    }
}

static void VerifyGROTH16ScriptBench(benchmark::State& state)
{
    const int flags =  SCRIPT_VERIFY_P2SH;

    CMutableTransaction txCredit;
    DecodeHexTx(txCredit, "0200000001d5258a4fd597edc59d3a9166557c078f05bb992c926d90a0f18c75302d93f99000000000fd0203307f4e6a794e3317a1a2f06a8163ebd70a4a714a5f712d4259a9387d6589615bf63e95bb9233b844f47f5e2a0a312cb300308ddb1235bf6f33189982611ce46edbf62762cf1bda4e245c28c9622452e579078384c4a7c83b00b9b5cb96eaca9abe1130a882ef4edc6a154f1f62d53bf8bf55daeabdf528bbdc9fc7935f37449bafd302aaf19156548ba8b28d29a278ea92f094302882cbef8b8e4f89687f9e8eedc70e8400b0293c05e41c29252683855ecab667100996bda1d61091ccec5c61db9508814c50b9d96fecdd99ff136355dc90772a2ef7788afe1f8a332b34e8a30402477f8e38e874eba3946f6f4ba8c794a09d266507dd66ecb824f911036f2b6bf63ee7a5feb52105bdf466dac06ca427711d5b52c24de90120caec89bedcab3ce707981a6fa86d27b87b2c0a732feee3717aaddd6728877c007c76a82081c202329a17f5756142a72734f6832f7784e22b1e17260901039f504f9098a3884c5090c10d96e70d136fac9a3634428f3792e9b8d02eb903783f71fc8e6937f7f8b1360c8bee9146041a79251614eee9689073af20af273a280e841b078837e65a862279849c1251e1761bb6ac35f2649ea34c50fe63d02ab4af4ab3448fe5e8d4fff135d510a38558c9daee4ae190303c18368ce2ba9fd21e8d1ab0f617a9d249621b56f224b69f6c3a3e008a40b3aea5a5ab77eed73711e93c896023475b27e3a4f6124c50189647ab2c8de2fc37ef189f803704cc55087bfe1c56dcabbb2f343dc145a0470d18317696e1023a7574e8745e0ea301cc6cd679a61133a1c560d5aa3d38d91a999a8f666109495402c553bd7c82056b4c50bf358e5097046487c370c1dd6781dc11d6518717e23b334d4b09892a9763f09059687a7c136f6189568edd6d6f357c1c199a39fa0f723d2218762766f67fa8171b10e8b7e5dd88155651d37ca6b59c754c50092d3dfea8804a69cab1f76133032b85ee7e850977dd1fe578f3d9663bb43a08502a8fd7cb8c7f79c39fbe49f9cee082bf68dfd65e70ccdbfb4c6f834d5dcb3e4619bc44de9ca8aca12b502e74b7b50451b36d6d6d6d6d6d51ffffffff0100113d550200000017a914fda635e6bc2ef7efa82521342c1e3ab932153c628700000000");
    CMutableTransaction txSpend;
    DecodeHexTx(txSpend, "0200000002952da86dd9c8e4f2587be7adfa9ebe531cc05a8e733f7bd6c02c7ac9f03503b300000000fd020330a1cf4fd86ec455bbe8b983c0dd64abe78ef065724960fecce845873a9df15e10e16c60e948fddd722bd68ed469cca20e30a9cb9215f93c6d926a22367fab2e95d54560a06412ca51304da82d2ee75521a6f58996298c14fe566795d2f654efda0130f23b6a58474bfc3e89499bce8bf7b280b2d84707ffa7f86bc9c94a8174b99f7df7be7e531e8ea759f60abdb4864ad7023016e9e0aa1e58d75831dd90aef95657a5a5e96e9196e6a02f6cb8c6371d311d5654dda6dfd522626f4c90aa0861b067024c50b9d96fecdd99ff136355dc90772a2ef7788afe1f8a332b34e8a30402477f8e38e874eba3946f6f4ba8c794a09d266507dd66ecb824f911036f2b6bf63ee7a5feb52105bdf466dac06ca427711d5b52c24de9012000f3a40258113d7544ec3a1c548047ab9a14e5488320414a311d8de59b7414007c76a82081c202329a17f5756142a72734f6832f7784e22b1e17260901039f504f9098a3884c5090c10d96e70d136fac9a3634428f3792e9b8d02eb903783f71fc8e6937f7f8b1360c8bee9146041a79251614eee9689073af20af273a280e841b078837e65a862279849c1251e1761bb6ac35f2649ea34c50fe63d02ab4af4ab3448fe5e8d4fff135d510a38558c9daee4ae190303c18368ce2ba9fd21e8d1ab0f617a9d249621b56f224b69f6c3a3e008a40b3aea5a5ab77eed73711e93c896023475b27e3a4f6124c50189647ab2c8de2fc37ef189f803704cc55087bfe1c56dcabbb2f343dc145a0470d18317696e1023a7574e8745e0ea301cc6cd679a61133a1c560d5aa3d38d91a999a8f666109495402c553bd7c82056b4c50bf358e5097046487c370c1dd6781dc11d6518717e23b334d4b09892a9763f09059687a7c136f6189568edd6d6f357c1c199a39fa0f723d2218762766f67fa8171b10e8b7e5dd88155651d37ca6b59c754c50092d3dfea8804a69cab1f76133032b85ee7e850977dd1fe578f3d9663bb43a08502a8fd7cb8c7f79c39fbe49f9cee082bf68dfd65e70ccdbfb4c6f834d5dcb3e4619bc44de9ca8aca12b502e74b7b50451b36d6d6d6d6d6d51ffffffffa75fe7d127ffba6a51a6aa750aec49d6861b7e3cc809f259cfcf3d95c71574b900000000fd02033091d0f9aff7bd3da433eb5706a7914bc49d19ea781a9b8eee183929cdfc7a79773a244992d5afd3e9ddc61d70f73b0194300739ce49ac859b19f03d3c0c2bbb7ffb24e64c32e4e632fe74e3a53f5e5aa10ee3551061b3818aa3e126d960cb593f163035c36460f49449043c7892acebd0518122551501a7abd5a00df0962ce1f6977399a5ef4762c0d80ceec2c9833891c617301120658e06a7ede8415aded94c242e8a6d661732a1b8826114814421aff13fec59f847961ae3181b7a533d40f4aa3a924c50b9d96fecdd99ff136355dc90772a2ef7788afe1f8a332b34e8a30402477f8e38e874eba3946f6f4ba8c794a09d266507dd66ecb824f911036f2b6bf63ee7a5feb52105bdf466dac06ca427711d5b52c24de9012000f3a40258113d7544ec3a1c548047ab9a14e5488320414a311d8de59b7414007c76a82081c202329a17f5756142a72734f6832f7784e22b1e17260901039f504f9098a3884c5090c10d96e70d136fac9a3634428f3792e9b8d02eb903783f71fc8e6937f7f8b1360c8bee9146041a79251614eee9689073af20af273a280e841b078837e65a862279849c1251e1761bb6ac35f2649ea34c50fe63d02ab4af4ab3448fe5e8d4fff135d510a38558c9daee4ae190303c18368ce2ba9fd21e8d1ab0f617a9d249621b56f224b69f6c3a3e008a40b3aea5a5ab77eed73711e93c896023475b27e3a4f6124c50189647ab2c8de2fc37ef189f803704cc55087bfe1c56dcabbb2f343dc145a0470d18317696e1023a7574e8745e0ea301cc6cd679a61133a1c560d5aa3d38d91a999a8f666109495402c553bd7c82056b4c50bf358e5097046487c370c1dd6781dc11d6518717e23b334d4b09892a9763f09059687a7c136f6189568edd6d6f357c1c199a39fa0f723d2218762766f67fa8171b10e8b7e5dd88155651d37ca6b59c754c50092d3dfea8804a69cab1f76133032b85ee7e850977dd1fe578f3d9663bb43a08502a8fd7cb8c7f79c39fbe49f9cee082bf68dfd65e70ccdbfb4c6f834d5dcb3e4619bc44de9ca8aca12b502e74b7b50451b36d6d6d6d6d6d51ffffffff01003e6e560200000017a9149faff0ec8c48761a48a8023ed8fd7b8af103c0888700000000");

    // Benchmark.
    while (state.KeepRunning()) {
        ScriptError err;
        bool success = VerifyScript(
            txSpend.vin[0].scriptSig,
            txCredit.vout[0].scriptPubKey,
            &txSpend.vin[0].scriptWitness,
            flags,
            MutableTransactionSignatureChecker(&txSpend, 0, txCredit.vout[0].nValue),
            &err);
        assert(err == SCRIPT_ERR_OK);
        assert(success);

// #if defined(HAVE_CONSENSUS_LIB)
//         CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
//         stream << txSpend;
//         int csuccess = bitcoinconsensus_verify_script_with_amount(
//             txCredit.vout[0].scriptPubKey.data(),
//             txCredit.vout[0].scriptPubKey.size(),
//             txCredit.vout[0].nValue,
//             (const unsigned char*)stream.data(), stream.size(), 0, flags, nullptr);
//         assert(csuccess == 1);
// #endif
    }
}


BENCHMARK(VerifyGROTH16ScriptBench);
BENCHMARK(VerifyScriptBench);
