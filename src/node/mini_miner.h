// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_MINI_MINER_H
#define BITCOIN_NODE_MINI_MINER_H

#include <txmempool.h>

namespace node {

/**
 * A minimal version of BlockAssembler. Allows us to run the mining algorithm on a subset of
 * mempool transactions, ignoring consensus rules, to calculate mining scores.
 */
class MiniMiner
{
    //! Copy of the original outpoints requested.
    std::vector<COutPoint> m_requested_outpoints;

    /*
     * A very simplified representation of a mempool transaction.
     */
    struct Tx {
        int m_in_degree{0};             //! only for topological sort
        bool m_mined{false};            //! this transaction has been "mined"
        std::vector<size_t> m_parents;  //! references to our parents (unordered)
        std::vector<size_t> m_children; //! references to our children (unordered)
        CAmount m_fee{0};               //! fee of this individual transaction
        uint32_t m_vsize{0};            //! virtual size of this individual transaction
        CAmount m_ancestor_fee{0};      //! sum of our fee and all our ancestors
        uint32_t m_ancestor_vsize{0};   //! sum of our vsize and all our ancestors
    };

    //! Index into `m_tx_vec`
    using tx_index_t = size_t;

    //! Transactions in the order encountered; the order is arbitrary.
    std::vector<Tx> m_tx_vec;

    //! Return a transaction's index into m_tx_vec, given its txid (hash).
    std::map<uint256, tx_index_t> m_tx_map;

    //! References to transactions in topologically-sorted order, ancestors first.
    std::vector<tx_index_t> m_top_sort;

    /**
     * Build a block template of transactions with ancestor feerates greater
     * or equal to the the target feerate, and calculate all transactions'
     * ancestor fees and vsizes. The results are used by the calculate methods.
     */
    void BuildMockTemplate(const CFeeRate& target_feerate);

public:
    /**
     * Using the mempool, find all transactions "connected" to any of the given
     * outpoints (this is called a cluster), and create simplified `Tx`
     * representations of these, including their individual (but not ancestor)
     * fee and size values, and their parent-child relationships with other
     * transactions in the cluster (mined parents are not represented at all).
     * This constructor is the only method of this object that uses the mempool.
     */
    MiniMiner(const CTxMemPool& mempool, const std::vector<COutPoint>& outpoints);

    /**
     * Construct a new block template (which is not used for anything) and, for
     * each outpoint corresponding to a transaction that did not make it into the
     * block, calculate the cost of bumping those transactions (and their
     * ancestors) to the target feerate.
     */
    std::map<COutPoint, CAmount> CalculateBumpFees(const CFeeRate& target_feerate);

    /**
     * Construct a new block template and calculate the cost of bumping all
     * transactions that did not make it into the block to the target feerate,
     * being careful to count any shared ancestors only once.
     */
    CAmount CalculateTotalBumpFees(const CFeeRate& target_feerate);
};
} // namespace node

#endif // BITCOIN_NODE_MINI_MINER_H
