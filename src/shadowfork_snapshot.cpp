// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "shadowfork_snapshot.h"

#include "clientversion.h"
#include "chainparams.h"
#include "streams.h"
#include "util.h"

#include <cstdio>
#include <cstring>

namespace {

static const unsigned char SHADOWFORK_SNAPSHOT_MAGIC[] = {
    's', 'f', 'b', 'l', 'k', 'i', 'd', 'x'
};

static const uint32_t SHADOWFORK_SNAPSHOT_VERSION = 2;
static const long SHADOWFORK_ACTIVE_CHAIN_RECORD_SIZE = 72;

static fs::path GetShadowForkSnapshotRoot()
{
    const std::string configured_root = GetArg("-shadowforksnapshotroot", "");
    if (!configured_root.empty()) {
        return fs::path(configured_root);
    }

    const fs::path data_root = GetDataDir(false);
    for (fs::path cursor = data_root; !cursor.empty(); cursor = cursor.parent_path()) {
        const fs::path candidate = cursor / "shadow-snapshots";
        if (fs::exists(candidate) && fs::is_directory(candidate)) {
            return candidate;
        }

        const fs::path parent = cursor.parent_path();
        if (parent == cursor) {
            break;
        }
    }

    return data_root / "shadow-snapshots";
}

static fs::path GetShadowForkSnapshotDirectory(const std::string& source_chain)
{
    return GetShadowForkSnapshotRoot() / source_chain;
}

} // namespace

fs::path GetShadowForkSnapshotPath(const std::string& source_chain)
{
    return GetShadowForkSnapshotDirectory(source_chain) / "blockindex.dat";
}

std::string GetShadowForkSnapshotSourceChain(const CChainParams& chainparams)
{
    if (chainparams.GetConsensus(0).fShadowForkMode) {
        return GetArg("-shadowforkchain", "main");
    }
    return chainparams.NetworkIDString();
}

ShadowForkSnapshotWriter::ShadowForkSnapshotWriter()
{
}

ShadowForkSnapshotWriter::~ShadowForkSnapshotWriter()
{
}

bool ShadowForkSnapshotWriter::SetError(const std::string& message, std::string* error)
{
    if (error) {
        *error = message;
    }
    return false;
}

bool ShadowForkSnapshotWriter::Open(const std::string& source_chain, std::string* error)
{
    final_path_ = GetShadowForkSnapshotPath(source_chain);
    temp_path_ = final_path_;
    temp_path_ += ".new";

    try {
        fs::create_directories(final_path_.parent_path());
    } catch (const fs::filesystem_error& e) {
        return SetError(strprintf("failed to create snapshot directory %s: %s",
                                  final_path_.parent_path().string(), e.what()), error);
    }

    FILE* raw_file = fsbridge::fopen(temp_path_, "wb");
    if (!raw_file) {
        return SetError(strprintf("failed to open snapshot temp file %s", temp_path_.string()), error);
    }

    file_.reset(new CAutoFile(raw_file, SER_DISK, CLIENT_VERSION));

    try {
        (*file_) << FLATDATA(SHADOWFORK_SNAPSHOT_MAGIC);
        (*file_) << SHADOWFORK_SNAPSHOT_VERSION;
    } catch (const std::exception& e) {
        file_.reset();
        return SetError(strprintf("failed to write snapshot header: %s", e.what()), error);
    }

    return true;
}

bool ShadowForkSnapshotWriter::WriteMetadata(const ShadowForkSnapshotMetadata& metadata, std::string* error)
{
    if (!file_) {
        return SetError("snapshot writer is not open", error);
    }

    try {
        (*file_) << metadata;
    } catch (const std::exception& e) {
        return SetError(strprintf("failed to write snapshot metadata: %s", e.what()), error);
    }

    return true;
}

bool ShadowForkSnapshotWriter::WriteActiveChainRecord(const ShadowForkActiveChainRecord& record, std::string* error)
{
    if (!file_) {
        return SetError("snapshot writer is not open", error);
    }

    try {
        (*file_) << record;
    } catch (const std::exception& e) {
        return SetError(strprintf("failed to write snapshot active-chain record: %s", e.what()), error);
    }

    return true;
}

bool ShadowForkSnapshotWriter::Commit(std::string* error)
{
    if (!file_) {
        return SetError("snapshot writer is not open", error);
    }

    try {
        FileCommit(file_->Get());
        file_->fclose();
        file_.reset();
        if (!RenameOver(temp_path_, final_path_)) {
            return SetError(strprintf("failed to replace snapshot file %s", final_path_.string()), error);
        }
    } catch (const std::exception& e) {
        return SetError(strprintf("failed to commit snapshot file: %s", e.what()), error);
    }

    return true;
}

ShadowForkSnapshotReader::ShadowForkSnapshotReader()
    : record_count_(0),
      remaining_records_(0),
      records_offset_(0),
      metadata_loaded_(false)
{
}

ShadowForkSnapshotReader::~ShadowForkSnapshotReader()
{
}

bool ShadowForkSnapshotReader::SetError(const std::string& message, std::string* error)
{
    if (error) {
        *error = message;
    }
    return false;
}

bool ShadowForkSnapshotReader::Open(const std::string& source_chain, std::string* error)
{
    path_ = GetShadowForkSnapshotPath(source_chain);

    FILE* raw_file = fsbridge::fopen(path_, "rb");
    if (!raw_file) {
        return SetError(strprintf("snapshot file %s does not exist", path_.string()), error);
    }

    file_.reset(new CAutoFile(raw_file, SER_DISK, CLIENT_VERSION));

    try {
        unsigned char magic[sizeof(SHADOWFORK_SNAPSHOT_MAGIC)];
        uint32_t version = 0;
        (*file_) >> FLATDATA(magic);
        (*file_) >> version;
        if (std::memcmp(magic, SHADOWFORK_SNAPSHOT_MAGIC, sizeof(SHADOWFORK_SNAPSHOT_MAGIC)) != 0) {
            file_.reset();
            return SetError(strprintf("snapshot file %s has an invalid magic header", path_.string()), error);
        }
        if (version != SHADOWFORK_SNAPSHOT_VERSION) {
            file_.reset();
            return SetError(strprintf("snapshot file %s has unsupported version %u", path_.string(), version), error);
        }
    } catch (const std::exception& e) {
        file_.reset();
        return SetError(strprintf("failed to read snapshot header from %s: %s", path_.string(), e.what()), error);
    }

    return true;
}

bool ShadowForkSnapshotReader::ReadMetadata(ShadowForkSnapshotMetadata& metadata, std::string* error)
{
    if (!file_) {
        return SetError("snapshot reader is not open", error);
    }

    try {
        (*file_) >> metadata;
        record_count_ = metadata.block_count;
        remaining_records_ = metadata.block_count;
        records_offset_ = std::ftell(file_->Get());
        if (records_offset_ < 0) {
            return SetError(strprintf("failed to determine snapshot record offset for %s", path_.string()), error);
        }
        metadata_loaded_ = true;
    } catch (const std::exception& e) {
        return SetError(strprintf("failed to read snapshot metadata: %s", e.what()), error);
    }

    return true;
}

bool ShadowForkSnapshotReader::ReadNextActiveChainRecord(ShadowForkActiveChainRecord& record, std::string* error)
{
    if (!file_) {
        return SetError("snapshot reader is not open", error);
    }
    if (!metadata_loaded_) {
        return SetError("snapshot metadata has not been loaded", error);
    }
    if (remaining_records_ == 0) {
        return SetError("snapshot has no remaining block records", error);
    }

    try {
        (*file_) >> record;
        --remaining_records_;
    } catch (const std::exception& e) {
        return SetError(strprintf("failed to read snapshot active-chain record: %s", e.what()), error);
    }

    return true;
}

bool ShadowForkSnapshotReader::ReadActiveChainRecordAtHeight(int height, ShadowForkActiveChainRecord& record, std::string* error)
{
    if (!file_) {
        return SetError("snapshot reader is not open", error);
    }
    if (!metadata_loaded_) {
        return SetError("snapshot metadata has not been loaded", error);
    }
    if (height < 0 || static_cast<uint64_t>(height) >= record_count_) {
        return SetError(strprintf("snapshot height %d is out of range", height), error);
    }

    const long offset = records_offset_ + static_cast<long>(height) * SHADOWFORK_ACTIVE_CHAIN_RECORD_SIZE;
    if (std::fseek(file_->Get(), offset, SEEK_SET) != 0) {
        return SetError(strprintf("failed to seek snapshot record at height %d", height), error);
    }

    try {
        (*file_) >> record;
    } catch (const std::exception& e) {
        return SetError(strprintf("failed to read snapshot record at height %d: %s", height, e.what()), error);
    }

    return true;
}

uint64_t ShadowForkSnapshotReader::RemainingRecords() const
{
    return remaining_records_;
}

uint64_t ShadowForkSnapshotReader::RecordCount() const
{
    return record_count_;
}
