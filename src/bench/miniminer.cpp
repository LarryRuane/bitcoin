// Copyright (c) 2015-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <node/mini_miner.h>
#include <policy/policy.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <txmempool_entry.h>
#include <validation.h>

#include <vector>

// Extremely fast-running benchmark:
#include <math.h>


volatile double summ = 0.0; // volatile, global so not optimized away

static void MiniMiner(benchmark::Bench& bench)
{
    FastRandomContext det_rand{true};
    auto testing_setup = MakeNoLogFileContext<TestChain100Setup>(CBaseChainParams::REGTEST, {"-checkmempool=1"});
    CTxMemPool& pool = *testing_setup.get()->m_node.mempool;
    LOCK(cs_main);
    std::vector<COutPoint> outpoints;
    {
        LOCK(pool.cs);
        std::vector<CTransactionRef> mempool_transactions{testing_setup->PopulateMempool(det_rand, 600, true)};
        for (const auto& tx : mempool_transactions) {
            const auto txid = tx.get()->GetHash();
            for (const auto& op : tx.get()->vout) {
                outpoints.emplace_back(txid, op.nValue);
            }
        }
    }
    std::vector<int> feerates{
        10, 500, 999, 1000, 2000, 2500, 7800,
        11199, 23330, 50000, CENT,
        };
    bench.run([&] {
        for (auto fr : feerates) {
            node::MiniMiner mini_miner(pool, outpoints);
            CFeeRate feerate{CFeeRate(fr)};
            mini_miner.CalculateBumpFees(feerate);
            mini_miner.CalculateTotalBumpFees(feerate);
        }
    });
}

BENCHMARK(MiniMiner, benchmark::PriorityLevel::HIGH);
