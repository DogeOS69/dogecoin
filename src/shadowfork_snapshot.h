// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SHADOWFORK_SNAPSHOT_H
#define BITCOIN_SHADOWFORK_SNAPSHOT_H

#include "chain.h"
#include "fs.h"
#include "serialize.h"

#include <memory>
#include <stdint.h>
#include <string>
#include <vector>

class CAutoFile;
class CChainParams;

struct ShadowForkSnapshotMetadata
{
    std::string source_chain;
    uint256 genesis_hash;
    uint256 active_tip_hash;
    int active_tip_height;
    bool tx_index;
    bool have_pruned;
    int last_block_file;
    uint64_t block_count;
    std::vector<CBlockFileInfo> block_file_info;

    ShadowForkSnapshotMetadata()
        : active_tip_height(-1),
          tx_index(false),
          have_pruned(false),
          last_block_file(0),
          block_count(0)
    {
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(source_chain);
        READWRITE(genesis_hash);
        READWRITE(active_tip_hash);
        READWRITE(active_tip_height);
        READWRITE(tx_index);
        READWRITE(have_pruned);
        READWRITE(last_block_file);
        READWRITE(VARINT(block_count));
        READWRITE(block_file_info);
    }
};

struct ShadowForkActiveChainRecord
{
    uint256 block_hash;
    uint256 chain_work;
    uint32_t chain_tx_count;
    uint32_t time_max;

    ShadowForkActiveChainRecord()
        : chain_tx_count(0),
          time_max(0)
    {
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(block_hash);
        READWRITE(chain_work);
        READWRITE(chain_tx_count);
        READWRITE(time_max);
    }
};

fs::path GetShadowForkSnapshotPath(const std::string& source_chain);
std::string GetShadowForkSnapshotSourceChain(const CChainParams& chainparams);

class ShadowForkSnapshotWriter
{
public:
    ShadowForkSnapshotWriter();
    ~ShadowForkSnapshotWriter();

    bool Open(const std::string& source_chain, std::string* error);
    bool WriteMetadata(const ShadowForkSnapshotMetadata& metadata, std::string* error);
    bool WriteActiveChainRecord(const ShadowForkActiveChainRecord& record, std::string* error);
    bool Commit(std::string* error);

private:
    bool SetError(const std::string& message, std::string* error);

    fs::path final_path_;
    fs::path temp_path_;
    std::unique_ptr<CAutoFile> file_;
};

class ShadowForkSnapshotReader
{
public:
    ShadowForkSnapshotReader();
    ~ShadowForkSnapshotReader();

    bool Open(const std::string& source_chain, std::string* error);
    bool ReadMetadata(ShadowForkSnapshotMetadata& metadata, std::string* error);
    bool ReadNextActiveChainRecord(ShadowForkActiveChainRecord& record, std::string* error);
    bool ReadActiveChainRecordAtHeight(int height, ShadowForkActiveChainRecord& record, std::string* error);
    uint64_t RemainingRecords() const;
    uint64_t RecordCount() const;

private:
    bool SetError(const std::string& message, std::string* error);

    fs::path path_;
    std::unique_ptr<CAutoFile> file_;
    uint64_t record_count_;
    uint64_t remaining_records_;
    long records_offset_;
    bool metadata_loaded_;
};

#endif // BITCOIN_SHADOWFORK_SNAPSHOT_H
