// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "arith_uint256.h"
#include "chain.h"
#include "chainparams.h"
#include "primitives/block.h"
#include "uint256.h"
#include "bignum.h" // change lib later

#include <math.h>

/*unsigned int GetNextWorkRequiredBTC(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Genesis block
    if (pindexLast == NULL)
        return nProofOfWorkLimit;

    // Only change once per interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 2.5 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 1 day worth of blocks
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

   return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}*/

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, int algo, const Consensus::Params& params)
{
    const arith_uint256 nProofOfWorkLimit = UintToArith256(params.powLimit[algo]);

    // Genesis block
    if (pindexLast == NULL)
        return nProofOfWorkLimit.GetCompact();

    // find previous block with same algo
    const CBlockIndex* pindexPrev = GetLastBlockIndexForAlgo(pindexLast, algo);
    if (pindexPrev == NULL)
        return nProofOfWorkLimit.GetCompact();

    const CBlockIndex* pindexFirst = pindexPrev;

    int64_t nMinActualTimespan = params.nPoWAveragingTargetTimespan() * (100 - params.nMaxAdjustUp) / 100;
    int64_t nMaxActualTimespan = params.nPoWAveragingTargetTimespan() * (100 - params.nMaxAdjustDown) / 100;

    // Go back by what we want to be nAveragingInterval blocks
    for (int i = 0; pindexFirst && i < params.nPoWAveragingInterval - 1; i++)
    {
        pindexFirst = GetLastBlockIndexForAlgo(pindexFirst, algo);
        if (pindexFirst == NULL)
            return nProofOfWorkLimit.GetCompact();
    }

    int64_t nActualTimespan = pindexLast->GetMedianTimePast() - pindexFirst->GetMedianTimePast();

    LogPrintf("GetNextWorkRequired(Algo=%d):   nActualTimespan = %d before bounds   %d   %d\n", algo, nActualTimespan, pindexLast->GetMedianTimePast(), pindexFirst->GetMedianTimePast());

    if (nActualTimespan < nMinActualTimespan)
        nActualTimespan = nMinActualTimespan;
    if (nActualTimespan > nMaxActualTimespan)
        nActualTimespan = nMaxActualTimespan;

    LogPrintf("GetNextWorkRequired(Algo=%d):   nActualTimespan = %d after bounds   %d   %d\n", algo, nActualTimespan, nMinActualTimespan, nMaxActualTimespan);

    arith_uint256 bnNew;
    bnNew.SetCompact(pindexPrev->nBits);
    arith_uint256 bnOld;
    bnOld = bnNew;

    bnNew *= nActualTimespan;
    bnNew /= params.nPoWAveragingTargetTimespan();
    if(bnNew > nProofOfWorkLimit)
        bnNew = nProofOfWorkLimit;

    LogPrintf("GetNextWorkRequired(Algo=%d) RETARGET\n", algo);
    LogPrintf("nTargetTimespan = %d    nActualTimespan = %d\n", params.nPoWAveragingTargetTimespan(), nActualTimespan);
    LogPrintf("Before: %08x  %s\n", pindexPrev->nBits, bnOld.ToString());
    LogPrintf("After:  %08x  %s\n", bnNew.GetCompact(), bnNew.ToString());

    return bnNew.GetCompact();
}

// for DIFF_BTC only!
unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, int algo, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit[algo]);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, int algo, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit[algo]))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}

arith_uint256 GetPrevWorkForAlgoWithDecay(const CBlockIndex& block, int algo)
{
    int nDistance = 0;
    arith_uint256 nWork;
    const CBlockIndex* pindex = &block;
    while (pindex != NULL)
    {
        if (nDistance > 100)
            return arith_uint256(0);
        if (pindex->GetAlgo() == algo)
        {
            arith_uint256 nWork = GetBlockProofBase(*pindex);
            nWork *= (100 - nDistance);
            nWork /= 100;
            return nWork;
        }
        pindex = pindex->pprev;
        nDistance++;
    }
    return arith_uint256(0);
}

arith_uint256 GetGeometricMeanPrevWork(const CBlockIndex& block)
{
    arith_uint256 nBlockWork = GetBlockProofBase(block);
    CBigNum bnBlockWork = CBigNum(ArithToUint256(nBlockWork));
    int nAlgo = block.GetAlgo();
    for (int algo = 0; algo < NUM_ALGOS; algo++)
    {
        if (algo != nAlgo)
        {
            arith_uint256 nBlockWorkAlt = GetPrevWorkForAlgoWithDecay(block, algo);
            CBigNum bnBlockWorkAlt = CBigNum(ArithToUint256(nBlockWorkAlt));
            if (bnBlockWorkAlt != 0)
                bnBlockWork *= bnBlockWorkAlt;
        }
    }
    // Compute the geometric mean
    CBigNum bnRes = bnBlockWork.nthRoot(NUM_ALGOS);
    // Scale to roughly match the old work calculation
    bnRes <<= 8;
    return UintToArith256(bnRes.getuint256());
}

arith_uint256 GetBlockProofBase(const CBlockIndex& block)
{
    arith_uint256 bnTarget;
    bool fNegative;
    bool fOverflow;
    bnTarget.SetCompact(block.nBits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || bnTarget == 0)
        return 0;
    // We need to compute 2**256 / (bnTarget+1), but we can't represent 2**256
    // as it's too large for a arith_uint256. However, as 2**256 is at least as large
    // as bnTarget+1, it is equal to ((2**256 - bnTarget - 1) / (bnTarget+1)) + 1,
    // or ~bnTarget / (nTarget+1) + 1.
    return (~bnTarget / (bnTarget + 1)) + 1;
}

arith_uint256 GetBlockProof(const CBlockIndex& block)
{
    return GetGeometricMeanPrevWork(block);
}

int64_t GetBlockProofEquivalentTime(const CBlockIndex& to, const CBlockIndex& from, const CBlockIndex& tip, const Consensus::Params& params)
{
    arith_uint256 r;
    int sign = 1;
    if (to.nChainWork > from.nChainWork) {
        r = to.nChainWork - from.nChainWork;
    } else {
        r = from.nChainWork - to.nChainWork;
        sign = -1;
    }
    r = r * arith_uint256(params.nPowTargetSpacing) / GetBlockProof(tip);
    if (r.bits() > 63) {
        return sign * std::numeric_limits<int64_t>::max();
    }
    return sign * r.GetLow64();
}
