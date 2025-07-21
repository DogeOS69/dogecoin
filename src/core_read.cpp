// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core_io.h"

#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "serialize.h"
#include "streams.h"
#include <univalue.h>
#include "util.h"
#include "utilstrencodings.h"
#include "version.h"

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/assign/list_of.hpp>

CScript ParseScript(const std::string& s, bool allowAllOpCodes)
{
    CScript result;

    static std::map<std::string, opcodetype> mapOpNames;
    static std::map<std::string, opcodetype> mapAllOpNames;
    static bool initialized = false;

    if (!initialized)
    {
        // 初始化标准操作码
        for (int op = 0; op <= OP_NOP10; op++)
        {
            const char* name = GetOpName((opcodetype)op);
            if (strcmp(name, "OP_UNKNOWN") == 0)
                continue;
            
            std::string strName(name);
            mapOpNames[strName] = (opcodetype)op;
            
            // 对于非数字操作码，添加不带OP_前缀的版本
            if (strName.substr(0, 3) == "OP_") {
                std::string strNameWithoutPrefix = strName.substr(3);
                mapOpNames[strNameWithoutPrefix] = (opcodetype)op;
            }
        }
        
        // 复制到全部操作码映射表
        mapAllOpNames = mapOpNames;
        
        // 添加数字操作码(1-16)的带OP_前缀版本，因为GetOpName返回的是不带前缀的版本
        mapAllOpNames["OP_1"] = OP_1;
        mapAllOpNames["OP_2"] = OP_2;
        mapAllOpNames["OP_3"] = OP_3;
        mapAllOpNames["OP_4"] = OP_4;
        mapAllOpNames["OP_5"] = OP_5;
        mapAllOpNames["OP_6"] = OP_6;
        mapAllOpNames["OP_7"] = OP_7;
        mapAllOpNames["OP_8"] = OP_8;
        mapAllOpNames["OP_9"] = OP_9;
        mapAllOpNames["OP_10"] = OP_10;
        mapAllOpNames["OP_11"] = OP_11;
        mapAllOpNames["OP_12"] = OP_12;
        mapAllOpNames["OP_13"] = OP_13;
        mapAllOpNames["OP_14"] = OP_14;
        mapAllOpNames["OP_15"] = OP_15;
        mapAllOpNames["OP_16"] = OP_16;
        
        // 也添加OP_0/OP_FALSE
        mapAllOpNames["OP_0"] = OP_0;
        mapAllOpNames["OP_FALSE"] = OP_0;
        
        // 添加OP_CHECKZKP的所有可能形式
        mapAllOpNames["OP_CHECKZKP"] = OP_CHECKZKP;
        mapAllOpNames["CHECKZKP"] = OP_CHECKZKP;
        mapAllOpNames["OP_NOP10"] = OP_NOP10;
        mapAllOpNames["NOP10"] = OP_NOP10;
        
        initialized = true;
    }

    // 根据allowAllOpCodes决定使用哪个映射表
    const std::map<std::string, opcodetype>& currentMap = allowAllOpCodes ? mapAllOpNames : mapOpNames;

    std::vector<std::string> words;
    boost::algorithm::split(words, s, boost::algorithm::is_any_of(" \t\n"), boost::algorithm::token_compress_on);

    for (std::vector<std::string>::const_iterator w = words.begin(); w != words.end(); ++w)
    {
        if (w->empty())
        {
            // 忽略空字符串
        }
        else if (all(*w, boost::algorithm::is_digit()) ||
            (boost::algorithm::starts_with(*w, "-") && all(std::string(w->begin()+1, w->end()), boost::algorithm::is_digit())))
        {
            // 数字
            int64_t n = atoi64(*w);
            result << n;
        }
        else if (boost::algorithm::starts_with(*w, "0x") && (w->begin()+2 != w->end()) && IsHex(std::string(w->begin()+2, w->end())))
        {
            // 十六进制数据
            std::vector<unsigned char> raw = ParseHex(w->substr(2));
            result << raw;
        }
        else if (w->size() >= 2 && boost::algorithm::starts_with(*w, "'") && boost::algorithm::ends_with(*w, "'"))
        {
            // 字符串
            std::vector<unsigned char> value(w->begin()+1, w->end()-1);
            result << value;
        }
        else if (boost::algorithm::istarts_with(*w, "0x") && IsHex(w->substr(2))) {
            // treat as raw data push
            std::vector<unsigned char> data = ParseHex(w->substr(2));
            result << data;
        } else if (IsHex(*w)) {
            // also allow un-prefixed hex
            std::vector<unsigned char> data = ParseHex(*w);
            result << data;
        } else {
            auto itOp = currentMap.find(*w);
            if (itOp == currentMap.end())
                throw std::runtime_error("ParseScript(): unknown opcode or data \"" + *w + "\"");
            result.push_back(itOp->second);
        }
    }

    return result;
}

bool DecodeHexTx(CMutableTransaction& tx, const std::string& strHexTx, bool fTryNoWitness)
{
    if (!IsHex(strHexTx))
        return false;

    std::vector<unsigned char> txData(ParseHex(strHexTx));

    if (fTryNoWitness) {
        CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS);
        try {
            ssData >> tx;
            if (ssData.eof()) {
                return true;
            }
        }
        catch (const std::exception&) {
            // Fall through.
        }
    }

    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    try {
        ssData >> tx;
        if (!ssData.empty())
            return false;
    }
    catch (const std::exception&) {
        return false;
    }

    return true;
}

bool DecodeHexBlk(CBlock& block, const std::string& strHexBlk)
{
    if (!IsHex(strHexBlk))
        return false;

    std::vector<unsigned char> blockData(ParseHex(strHexBlk));
    CDataStream ssBlock(blockData, SER_NETWORK, PROTOCOL_VERSION);
    try {
        ssBlock >> block;
    }
    catch (const std::exception&) {
        return false;
    }

    return true;
}

uint256 ParseHashUV(const UniValue& v, const std::string& strName)
{
    std::string strHex;
    if (v.isStr())
        strHex = v.getValStr();
    return ParseHashStr(strHex, strName);  // Note: ParseHashStr("") throws a runtime_error
}

uint256 ParseHashStr(const std::string& strHex, const std::string& strName)
{
    if (!IsHex(strHex)) // Note: IsHex("") is false
        throw std::runtime_error(strName + " must be hexadecimal string (not '" + strHex + "')");

    uint256 result;
    result.SetHex(strHex);
    return result;
}

std::vector<unsigned char> ParseHexUV(const UniValue& v, const std::string& strName)
{
    std::string strHex;
    if (v.isStr())
        strHex = v.getValStr();
    if (!IsHex(strHex))
        throw std::runtime_error(strName + " must be hexadecimal string (not '" + strHex + "')");
    return ParseHex(strHex);
}
