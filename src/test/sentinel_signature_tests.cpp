// Copyright (c) 2024 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/interpreter.h"
#include "script/script.h"
#include "test/test_bitcoin.h"

#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(sentinel_signature_tests, BasicTestingSetup)

// Mock checker that always returns false for signatures
class MockSignatureChecker : public BaseSignatureChecker
{
public:
    bool CheckSig(const std::vector<unsigned char>& scriptSig,
                  const std::vector<unsigned char>& vchPubKey,
                  const CScript& scriptCode,
                  SigVersion sigversion) const override
    {
        return false; // Always fail
    }

    bool CheckLockTime(const CScriptNum& nLockTime) const override
    {
        return true;
    }

    bool CheckSequence(const CScriptNum& nSequence) const override
    {
        return true;
    }
};

// Mock checker that always returns true for signatures
class PassingSignatureChecker : public BaseSignatureChecker
{
public:
    bool CheckSig(const std::vector<unsigned char>& scriptSig,
                  const std::vector<unsigned char>& vchPubKey,
                  const CScript& scriptCode,
                  SigVersion sigversion) const override
    {
        return true; // Always pass
    }

    bool CheckLockTime(const CScriptNum& nLockTime) const override
    {
        return true;
    }

    bool CheckSequence(const CScriptNum& nSequence) const override
    {
        return true;
    }
};

BOOST_AUTO_TEST_CASE(sentinel_signature_detection)
{
    // Test that sentinel signature is correctly detected
    // Sentinel: 30 06 02 01 01 02 01 01 [hashtype]
    std::vector<unsigned char> sentinel = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01}; // SIGHASH_ALL

    MockSignatureChecker mockChecker;
    SentinelSignatureChecker sentinelChecker(mockChecker, true);

    // Sentinel signature should pass even though mock checker always fails
    std::vector<unsigned char> dummyPubKey(33, 0x02);
    CScript dummyScript;
    BOOST_CHECK(sentinelChecker.CheckSig(sentinel, dummyPubKey, dummyScript, SIGVERSION_BASE));
}

BOOST_AUTO_TEST_CASE(sentinel_signature_with_different_hashtypes)
{
    MockSignatureChecker mockChecker;
    SentinelSignatureChecker sentinelChecker(mockChecker, true);

    std::vector<unsigned char> dummyPubKey(33, 0x02);
    CScript dummyScript;

    // Test with different hash types
    std::vector<unsigned char> sigAll = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01}; // SIGHASH_ALL
    std::vector<unsigned char> sigNone = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02}; // SIGHASH_NONE
    std::vector<unsigned char> sigSingle = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x03}; // SIGHASH_SINGLE

    BOOST_CHECK(sentinelChecker.CheckSig(sigAll, dummyPubKey, dummyScript, SIGVERSION_BASE));
    BOOST_CHECK(sentinelChecker.CheckSig(sigNone, dummyPubKey, dummyScript, SIGVERSION_BASE));
    BOOST_CHECK(sentinelChecker.CheckSig(sigSingle, dummyPubKey, dummyScript, SIGVERSION_BASE));
}

BOOST_AUTO_TEST_CASE(sentinel_signature_disabled)
{
    // When disabled, sentinel should delegate to wrapped checker
    MockSignatureChecker mockChecker;
    SentinelSignatureChecker sentinelChecker(mockChecker, false); // Disabled

    std::vector<unsigned char> sentinel = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01};
    std::vector<unsigned char> dummyPubKey(33, 0x02);
    CScript dummyScript;

    // Should fail because mock checker fails and sentinel is disabled
    BOOST_CHECK(!sentinelChecker.CheckSig(sentinel, dummyPubKey, dummyScript, SIGVERSION_BASE));
}

BOOST_AUTO_TEST_CASE(non_sentinel_signature_delegates)
{
    // Non-sentinel signatures should delegate to wrapped checker
    MockSignatureChecker mockChecker;
    SentinelSignatureChecker sentinelChecker(mockChecker, true);

    // Random signature (not sentinel pattern)
    std::vector<unsigned char> randomSig = {0x30, 0x45, 0x02, 0x21, 0x00, 0xab, 0xcd};
    std::vector<unsigned char> dummyPubKey(33, 0x02);
    CScript dummyScript;

    // Should fail because it's not a sentinel and mock checker fails
    BOOST_CHECK(!sentinelChecker.CheckSig(randomSig, dummyPubKey, dummyScript, SIGVERSION_BASE));
}

BOOST_AUTO_TEST_CASE(non_sentinel_with_passing_checker)
{
    // Non-sentinel with passing checker should pass
    PassingSignatureChecker passingChecker;
    SentinelSignatureChecker sentinelChecker(passingChecker, true);

    std::vector<unsigned char> randomSig = {0x30, 0x45, 0x02, 0x21, 0x00, 0xab, 0xcd};
    std::vector<unsigned char> dummyPubKey(33, 0x02);
    CScript dummyScript;

    // Should pass because wrapped checker passes
    BOOST_CHECK(sentinelChecker.CheckSig(randomSig, dummyPubKey, dummyScript, SIGVERSION_BASE));
}

BOOST_AUTO_TEST_CASE(too_short_signature)
{
    // Signatures shorter than 9 bytes should not match sentinel
    MockSignatureChecker mockChecker;
    SentinelSignatureChecker sentinelChecker(mockChecker, true);

    std::vector<unsigned char> shortSig = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}; // 8 bytes, no hashtype
    std::vector<unsigned char> dummyPubKey(33, 0x02);
    CScript dummyScript;

    // Should fail - too short to be valid sentinel
    BOOST_CHECK(!sentinelChecker.CheckSig(shortSig, dummyPubKey, dummyScript, SIGVERSION_BASE));
}

BOOST_AUTO_TEST_CASE(almost_sentinel_signature)
{
    // Signatures that almost match sentinel pattern should fail
    MockSignatureChecker mockChecker;
    SentinelSignatureChecker sentinelChecker(mockChecker, true);

    std::vector<unsigned char> dummyPubKey(33, 0x02);
    CScript dummyScript;

    // Wrong first byte
    std::vector<unsigned char> wrongFirst = {0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01};
    BOOST_CHECK(!sentinelChecker.CheckSig(wrongFirst, dummyPubKey, dummyScript, SIGVERSION_BASE));

    // Wrong length byte
    std::vector<unsigned char> wrongLen = {0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01};
    BOOST_CHECK(!sentinelChecker.CheckSig(wrongLen, dummyPubKey, dummyScript, SIGVERSION_BASE));

    // Wrong r value
    std::vector<unsigned char> wrongR = {0x30, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x01};
    BOOST_CHECK(!sentinelChecker.CheckSig(wrongR, dummyPubKey, dummyScript, SIGVERSION_BASE));

    // Wrong s value
    std::vector<unsigned char> wrongS = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x01};
    BOOST_CHECK(!sentinelChecker.CheckSig(wrongS, dummyPubKey, dummyScript, SIGVERSION_BASE));
}

BOOST_AUTO_TEST_CASE(locktime_and_sequence_delegation)
{
    MockSignatureChecker mockChecker;
    SentinelSignatureChecker sentinelChecker(mockChecker, true);

    // CheckLockTime and CheckSequence should delegate to wrapped checker
    CScriptNum lockTime(12345);
    CScriptNum sequence(67890);

    BOOST_CHECK(sentinelChecker.CheckLockTime(lockTime));
    BOOST_CHECK(sentinelChecker.CheckSequence(sequence));
}

BOOST_AUTO_TEST_SUITE_END()
