// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/mini_miner.h>

#include <consensus/amount.h>
#include <logging.h>
#include <policy/feerate.h>
#include <primitives/transaction.h>
#include <timedata.h>
#include <util/check.h>
#include <util/moneystr.h>

#include <algorithm>
#include <numeric>
#include <utility>

namespace node {

MiniMiner::MiniMiner(const CTxMemPool& mempool, const std::vector<COutPoint>& outpoints)
    : m_requested_outpoints(outpoints)
{
    // Topological sort: unordered list of transactions with zero parents.
    std::vector<Tx*> zero_in_degree;
    {
        LOCK(mempool.cs);

        // Find which outpoints to calculate bump fees for.
        // Anything that's spent by the mempool is to-be-replaced
        // Anything otherwise unavailable just has a bump fee of 0
        std::vector<CTxMemPool::txiter> cluster;
        {
            std::vector<uint256> txids;
            for (auto& outpoint : outpoints) {
                if (!mempool.exists(GenTxid::Txid(outpoint.hash))) {
                    // This UTXO is either confirmed or not yet submitted to mempool.
                    // In the former case, no bump fee is required.
                    // In the latter case, we have no information, so just return 0.
                    LogPrint(BCLog::MINIMINER, "tx not in mempool %s\n", outpoint.hash.ToString());
                    continue;
                }
                // This UTXO is unconfirmed, in the mempool, and available to spend.
                if (!m_tx_map.count(outpoint.hash)) {
                    LogPrint(BCLog::MINIMINER, "tx arg %i %s\n", m_tx_vec.size(), outpoint.hash.ToString());
                    m_tx_map.insert({outpoint.hash, m_tx_vec.size()});
                    m_tx_vec.push_back(Tx());
                    txids.push_back(outpoint.hash);
                }
            }
            cluster = mempool.CalculateCluster(txids);
        }

        // Make sure there's an entry for every tx in the cluster (it may
        // already exist), and set the fee and vsize of all entries.
        for (const auto& txiter : cluster) {
            const auto hash{txiter->GetTx().GetHash()};
            if (!m_tx_map.count(hash)) {
                m_tx_map.insert({hash, m_tx_vec.size()});
                m_tx_vec.push_back(Tx());
            }
            tx_index_t tx_index{m_tx_map[hash]};
            Tx& tx{m_tx_vec[tx_index]};
            tx.m_index = tx_index;
            tx.m_fee = txiter->GetModifiedFee();
            tx.m_vsize = txiter->GetTxSize();
            LogPrint(BCLog::MINIMINER, "tx %i %s fee=%i vsize=%d\n", tx_index, hash.ToString(), tx.m_fee, tx.m_vsize);
        }

        // Use the mempool to set up the parent and children relationships.
        for (const auto& txiter : cluster) {
            const uint256& hash{txiter->GetTx().GetHash()};
            LogPrint(BCLog::MINIMINER, "cluster tx %i", m_tx_map[hash]);
            const tx_index_t tx_index{m_tx_map[hash]};
            Tx& tx{m_tx_vec[tx_index]};

            // set this transaction's children list
            {
                LogPrint(BCLog::MINIMINER, " -- children:");
                const auto& children = txiter->GetMemPoolChildrenConst();
                for (const auto child : children) {
                    tx_index_t child_tx_index{m_tx_map[child.get().GetTx().GetHash()]};
                    LogPrint(BCLog::MINIMINER, " %i", child_tx_index);
                    tx.m_children.push_back(&m_tx_vec[child_tx_index]);
                }
            }

            // set this transaction's parents list
            {
                LogPrint(BCLog::MINIMINER, " -- parents:");
                const auto& parents = txiter->GetMemPoolParentsConst();
                for (const auto parent : parents) {
                    tx_index_t parent_tx_index{m_tx_map[parent.get().GetTx().GetHash()]};
                    LogPrint(BCLog::MINIMINER, " %i", parent_tx_index);
                    tx.m_parents.push_back(&m_tx_vec[parent_tx_index]);
                }
                LogPrint(BCLog::MINIMINER, "\n");

                // for topological sort
                tx.m_in_degree = parents.size();
                if (tx.m_in_degree == 0) zero_in_degree.push_back(&tx);
            }
        }
    }

    // topological sort, m_top_sort lists ancestors then descendants
    LogPrint(BCLog::MINIMINER, "topsort:");
    while (!zero_in_degree.empty()) {
        Tx* tx{zero_in_degree.back()};
        zero_in_degree.pop_back();
        m_top_sort.push_back(tx);
        LogPrint(BCLog::MINIMINER, " %i", tx->m_index);
        for (Tx* child : tx->m_children) {
            Assume(child->m_in_degree > 0);
            if (--child->m_in_degree <= 0) zero_in_degree.push_back(child);
        }
    }
    LogPrint(BCLog::MINIMINER, "\n");
    Assume(m_top_sort.size() == m_tx_vec.size());
}

/**
 * (Re-)calculate the given transaction's ancestor values (fee and vsize),
 * for performance, calculate only once (per mining step). Be sure to
 * increment m_ltime whenever ancestor fees might have changed.
 */
void MiniMiner::calculateAncestorValues(Tx* tx)
{
    ++m_calc_ltime;
    std::vector<Tx*> ancestors;
    std::vector<Tx*> todo{tx};
    while (!todo.empty()) {
        Tx* atx = todo.back();
        todo.pop_back();
        if (atx->m_mined || atx->m_calc_ltime == m_calc_ltime) continue;
        atx->m_calc_ltime = m_calc_ltime;
        ancestors.push_back(atx);
        for (Tx* parent : atx->m_parents) {
            if (parent->m_mined || parent->m_calc_ltime == m_calc_ltime) continue;
            todo.push_back(parent);
        }
    }
    tx->m_ancestor_fee = 0;
    tx->m_ancestor_vsize = 0;
    for (Tx* atx : ancestors) {
        tx->m_ancestor_fee += atx->m_fee;
        tx->m_ancestor_vsize += atx->m_vsize;
    }
}

/**
 * Determine which transactions would be "mined" at the given
 * target feerate (set their m_mined to true). The rest will need
 * a fee-bump (the actual fee-bump is not determined in this
 * function). For those that need a fee-bump, set their
 * m_ancestor_{fee,vsize}, which determines the transaction's
 * ancestor feerate.
 *
 * This method can be called multiple times with different
 * target feerates.
 *
 * Example (ancestors/parents on the left, descendants/children
 * on the right):
 *
 *               B fee=200 size=100
 *               /                  \
 *              /                    \
 *    A fee=100 size=100            D fee=150 size=100
 *               \                   /
 *                \                 /
 *               C fee=300 size=100
 *
 * A is the parent of B and C, and they are both parents of D.
 * Suppose m_top_sort is [A, B, C, D]. (Another possible sort
 * is [A, C, B, D].) Initially, none of the transactions is mined.
 * During the first pass over m_top_sort, we start with A. Its
 * ancestor fee and size are initialized to its individual fee
 * and size, 100 and 100. Now we loop over A's parents to add
 * their ancestor values, but A has no parents. Calculate A's
 * ancestor feerate, 100/100 = 1.
 *
 * For this example, suppose target_feerate is 1.8. Since 1 is
 * less than 1.8, we do not "mine" this transaction, and we
 * continue to the next loop iteration, which considers B.
 *
 * B's ancestor fee and size are its own plus those of its
 * parents. Its only parent is A; we add A's ancestor fee and
 * size, so B's ancestor feerate will be (200+100)/(100+100)
 * = 1.5. Since 1.5 is less than 1.8, we continue to the next
 * loop iteration without mining B.
 *
 * Continuing in the same way, transaction C's ancestor feerate
 * is (300+100)/(100+100)=2. Since that's greater than 1.8, we
 * "mine" C and all its ancestors, namely A. This is what the
 * `to_mine` loop does. Mining a transaction merely sets its
 * `m_mined` flag.
 *
 * It's important to note that when calculating ancestor fees and
 * sizes, we skip mined transactions, because ancestor feerates
 * only depend on mempool (unmined) transactions. Even though
 * these transactions haven't literally been mined, we anticipate
 * that they will be (before the transaction we're evaluating),
 * so we treat them as if they have been mined.
 * 
 * Since we've just mined some transactions, some of the previous
 * ancestor calculations may now be invalid, so we restart the
 * t-sort loop, beginning again with A. Since A has been mined,
 * we skip it. We visit B, but this time when we recalculate its
 * ancestor fee and size, A is not included since it has been
 * mined. Therefore B's ancestor feerate is 200/100 = 2. Since
 * this is greater than 1.8, B is now mined, even though it
 * was not mined during the first pass. We also mine all of B's
 * ancestors, but A is already mined; B has no unmined ancestors.
 * 
 * We restart the topological-sort loop beginning again with A.
 * We skip A, B, and C since they are already mined.
 *
 * Transaction D's ancestor fee and size are just its own since
 * all of its ancestors have been mined. D's ancestor feerate
 * is 1.5, which is less than 1.8, so it remains unmined.
 *
 * We've now made a complete pass over the m_top_sort list
 * without mining any transactions (we've made no progress),
 * so the algorithm has completed.
 *
 * The ancestor fees and sizes of unmined nodes are needed by
 * later functions (CalculateBumpFees and CalculateTotalBumpFees),
 * so those are another result of this algorithm, in addition
 * to the m_mined flags.
 */

void MiniMiner::BuildMockTemplate(const CFeeRate& target_feerate)
{
    // reset the state to as it was after the constructor ran.
    ++m_mine_ltime;
    for (Tx& tx : m_tx_vec) {
        tx.m_mined = false;
        calculateAncestorValues(&tx);
    }

    bool progress{true};
    while (progress) {
        progress = false;
        LogPrint(BCLog::MINIMINER, "start BuildMockTemplate target_feerate:%s\n",
            target_feerate.ToString());
        for (Tx* tx : m_top_sort) {
            LogPrint(BCLog::MINIMINER, "tx %i mined:%d af:%i as:%i\n",
                tx->m_index, tx->m_mined, tx->m_ancestor_fee, tx->m_ancestor_vsize);
            if (tx->m_mined) continue;
            CFeeRate afeerate(tx->m_ancestor_fee, tx->m_ancestor_vsize);
            if (false) {
                // feerate should be up-to-date; this is an expensive test
                CAmount save_fee{tx->m_ancestor_fee};
                auto save_vsize{tx->m_ancestor_vsize};
                calculateAncestorValues(tx);
                assert(tx->m_ancestor_fee == save_fee);
                assert(tx->m_ancestor_vsize == save_vsize);
            }
            if (afeerate < target_feerate) continue;
                // "mine" this tx and all of its (unmined) ancestors
            progress = true;
            ++m_mine_ltime;
            std::vector<Tx*> recalc_todo;
            std::vector<Tx*> mine_todo{tx};
            while (!mine_todo.empty()) {
                Tx* atx = mine_todo.back();
                mine_todo.pop_back();
                if (atx->m_mined) continue;
                atx->m_mined = true;
                LogPrint(BCLog::MINIMINER, "  atx %i mined:%d af:%i as:%i\n",
                    atx->m_index, atx->m_mined, atx->m_ancestor_fee, atx->m_ancestor_vsize);
                for (Tx* parent : atx->m_parents) {
                    LogPrint(BCLog::MINIMINER, "    parent %i mined:%d af:%i as:%i\n",
                        parent->m_index, parent->m_mined,
                        parent->m_ancestor_fee, parent->m_ancestor_vsize);
                    if (parent->m_mined) continue;
                    mine_todo.push_back(parent);
                }
                // ensure that we recalculate this child only one time
                for (Tx* child : atx->m_children) {
                    if (!child->m_mined && child->m_child_ltime != m_mine_ltime) {
                        child->m_child_ltime = m_mine_ltime;
                        recalc_todo.push_back(child);
                    }
                }
            }
            // recalculate the ancestor values of decendants of selected transactions
            while (!recalc_todo.empty()) {
                Tx* recalc_tx{recalc_todo.back()};
                recalc_todo.pop_back();
                LogPrint(BCLog::MINIMINER, "    recalc %i mined:%d af:%i as:%i\n",
                    recalc_tx->m_index, recalc_tx->m_mined,
                    recalc_tx->m_ancestor_fee, recalc_tx->m_ancestor_vsize);
                calculateAncestorValues(recalc_tx);
                LogPrint(BCLog::MINIMINER, "    after recalc %i mined:%d af:%i as:%i\n",
                    recalc_tx->m_index, recalc_tx->m_mined,
                    recalc_tx->m_ancestor_fee, recalc_tx->m_ancestor_vsize);
                for (Tx* child : recalc_tx->m_children) {
                    if (child->m_child_ltime != m_mine_ltime) {
                        child->m_child_ltime = m_mine_ltime;
                        recalc_todo.push_back(child);
                    }
                }
            }
            // Restart the loop because ancestor fees and sizes may have changed.
            break;
        }
    }
}

std::map<COutPoint, CAmount> MiniMiner::CalculateBumpFees(const CFeeRate& target_feerate)
{
    LogPrint(BCLog::MINIMINER, "CalculateBumpFees target_feerate:%i\n",
        target_feerate.GetFeePerK());
    // Build a block template of all transaction packages at or above target_feerate.
    BuildMockTemplate(target_feerate);

    std::map<COutPoint, CAmount> bump_fees;
    for (const auto& requested_outpoint : m_requested_outpoints) {
        const auto& it{m_tx_map.find(requested_outpoint.hash)};
        if (it == m_tx_map.end()) {
            // this outpoint wasn't found in the mempool
            LogPrint(BCLog::MINIMINER, "not in mempool %s\n", requested_outpoint.hash.ToString());
            bump_fees.emplace(requested_outpoint, 0);
            continue;
        }
        Tx& tx{m_tx_vec[it->second]};
        if (tx.m_mined) {
            // "mined" transactions don't need to have their fee bumped
            LogPrint(BCLog::MINIMINER, "mined %i\n", tx.m_index);
            bump_fees.emplace(requested_outpoint, 0);
            continue;
        }
        CAmount target_fee{target_feerate.GetFee(tx.m_ancestor_vsize)};
        Assume(target_fee > tx.m_ancestor_fee);
        CAmount bump_fee{target_fee - tx.m_ancestor_fee};
        bump_fees.emplace(requested_outpoint, bump_fee);
        LogPrint(BCLog::MINIMINER, "tx %i bump:%i\n", tx.m_index, bump_fee);
    }
    return bump_fees;
}

CAmount MiniMiner::CalculateTotalBumpFees(const CFeeRate& target_feerate)
{
    LogPrint(BCLog::MINIMINER, "target_feerate:%i)\n", target_feerate.GetFeePerK());
    // Build a block template of all transaction packages at or above target_feerate.
    BuildMockTemplate(target_feerate);

    // Sum the individual tx fees and sizes of non-mined transactions.
    CAmount total_fees{0};
    CAmount total_vsize{0};
    std::vector<Tx*> todo;
    for (const auto& requested_outpoint : m_requested_outpoints) {
        const auto& it{m_tx_map.find(requested_outpoint.hash)};
        if (it == m_tx_map.end()) {
            // this outpoint wasn't found in the mempool
            continue;
        }
        tx_index_t tx_index{it->second};
        Tx* tx{&m_tx_vec[tx_index]};
        if (tx->m_mined) continue;
        tx->m_mined = true;
        todo.push_back(tx);
    }
    while (!todo.empty()) {
        Tx* tx{todo.back()};
        todo.pop_back();
        total_fees += tx->m_fee;
        total_vsize += tx->m_vsize;
        tx->m_mined = true;
        for (Tx* parent : tx->m_parents) {
            if (!parent->m_mined) todo.push_back(parent);
        }
    }
    CAmount target_fee = target_feerate.GetFee(total_vsize);
    CAmount bump{target_fee - total_fees};
    LogPrint(BCLog::MINIMINER, "total_fees:%i total_vsize:%i target_fee:%i bump:%i\n",
             total_fees, total_vsize, target_fee, bump);
    return bump;
}
} // namespace node
