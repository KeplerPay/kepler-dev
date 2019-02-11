// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"

#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "crypto/common.h"

#define BEGIN(a)            ((char*)&(a))
#define END(a)              ((char*)&((&(a))[1]))

uint256 CBlockHeader::GetHash() const
{
    return HashX11(BEGIN(nVersion), END(nNonce)); // Might change to SHA256 //     return SerializeHash(*this);
    // idk why I did this in monea     return Hash(BEGIN(nVersion), END(nNonce));
}

uint256 CBlockHeader::GetPoWHash(int algo) const
{
    LogPrintf("DEBUG: GetPoWHash %d \n",algo);
    switch (algo)
    {
        case ALGO_SLOT1:
            return GetHash();
        case ALGO_SLOT2:
            return HashArgon2d(BEGIN(nVersion), END(nNonce));
        case ALGO_SLOT3:
            uint256 thash;
            yescrypt_hash(BEGIN(nVersion), BEGIN(thash));
            return thash;           
    }
    // catch-all if above doesn't match anything to algo
    return GetHash();
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (unsigned int i = 0; i < vtx.size(); i++)
    {
        s << "  " << vtx[i]->ToString() << "\n";
    }
    return s.str();
}
