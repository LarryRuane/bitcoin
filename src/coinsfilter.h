// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_COINSFILTER_H
#define BITCOIN_COINSFILTER_H

#include <crypto/common.h>
#include <memusage.h>
#include <primitives/transaction.h>

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

// A sorted list of spent coins
using CompactSpentsList = std::vector<COutPoint>;

/**
 * A blocked bloom filter over the compact spents vector (m_compact_spents).
 *
 * Most IsCompactSpent() lookups are negative: the outpoint being fetched is not
 * a compacted spent coin, and the lookup proceeds to the base view. A binary
 * search over the (large) sorted vector costs O(log n) scattered memory reads,
 * most of which are cache misses. This filter answers negative lookups with a
 * single 64-byte cache-line probe. Positive answers (rare, and including false
 * positives) fall back to the binary search, so a false positive only costs an
 * unnecessary search; false negatives cannot occur, which is the property that
 * correctness depends on.
 *
 * The filter must always describe the current contents of m_compact_spents.
 * That vector only changes wholesale (rebuilt in CompactSpents(), cleared in
 * ResetCompactSpents()), so the filter is rebuilt or cleared at those same
 * two places, and needs no incremental deletion support.
 *
 * Each entry sets HASHES bits within a single 64-byte block; ~16 bits per entry
 * of total filter space keeps the false positive rate well under 1%. Sizing to
 * ~2 bytes per entry is small next to the 36 bytes per entry of the vector.
 */
class CompactSpentsFilter
{
    //! 64 bytes, i.e. one cache line, per block.
    static constexpr size_t WORDS_PER_BLOCK{8};
    //! Bits set/tested per entry. 7 bit positions of 9 bits each (a block holds
    //! 512 bits) consume 63 of the 64 bits of one hash word. Fixed (rather than
    //! derived from filter size) because the bits-per-entry ratio is pinned by
    //! design, and a constant trip count lets the compiler fully unroll the
    //! probe loops with immediate shift amounts (Insert() compiles to
    //! branchless straight-line code; MayContain() keeps its early exits,
    //! which shorten the dominant negative-lookup case).
    static constexpr int HASHES{7};
    //! Bits per drawn position: a block holds 512 bits, so positions are 9 bits.
    static constexpr int POS_BITS{9};
    //! Target filter bits per entry, before rounding the block count up to a
    //! power of two.
    static constexpr size_t BITS_PER_ENTRY{16};

    static_assert(WORDS_PER_BLOCK * 64 == 1 << POS_BITS, "a position must address exactly one block's bits");
    static_assert(HASHES * POS_BITS <= 64, "positions are drawn POS_BITS at a time from a single 64-bit hash");
    static_assert(BITS_PER_ENTRY > 0);

    //! Salts, random unless deterministic (see SaltedOutpointHasher). The txid
    //! part of an outpoint is already uniformly distributed, but is chosen by
    //! peers; the salt keeps an attacker from grinding txids that concentrate
    //! in one block. Even a successful grinding attack only raises the false
    //! positive rate, degrading to the pre-filter behavior (binary search).
    const uint64_t m_k0, m_k1;
    std::vector<uint64_t> m_words;
    uint64_t m_block_mask{0};

    static uint64_t Mix(uint64_t x) noexcept
    {
        // splitmix64 finalizer (deliberate uint64 wraparound; Mix and Hash are
        // suppressed in test/sanitizer_suppressions/ubsan, like CBloomFilter)
        x ^= x >> 30; x *= 0xbf58476d1ce4e5b9ULL;
        x ^= x >> 27; x *= 0x94d049bb133111ebULL;
        x ^= x >> 31;
        return x;
    }

    //! Two independent 64-bit hashes: one selects the block, one supplies the
    //! bit positions within it.
    std::pair<uint64_t, uint64_t> Hash(const COutPoint& outpoint) const noexcept
    {
        const uint64_t h1{Mix((ReadLE64(outpoint.hash.data()) + outpoint.n) ^ m_k0)};
        const uint64_t h2{Mix((ReadLE64(outpoint.hash.data() + 8) - outpoint.n) ^ m_k1)};
        return {h1, h2};
    }

public:
    explicit CompactSpentsFilter(bool deterministic);

    //! Clear the filter and size it for the given number of entries (0 frees all
    //! memory). Insert() may then be called for each entry.
    void Reset(size_t count)
    {
        m_words.clear();
        m_words.shrink_to_fit();
        m_block_mask = 0;
        if (count == 0) return;
        const size_t min_blocks{(count * BITS_PER_ENTRY + 511) / 512};
        size_t blocks{1};
        while (blocks < min_blocks) blocks <<= 1;
        m_words.assign(blocks * WORDS_PER_BLOCK, 0);
        m_block_mask = blocks - 1;
    }

    void Insert(const COutPoint& outpoint) noexcept
    {
        const auto [h1, h2] = Hash(outpoint);
        uint64_t* block{&m_words[(h1 & m_block_mask) * WORDS_PER_BLOCK]};
        uint64_t bits{h2};
        for (int i{0}; i < HASHES; ++i) {
            const unsigned pos(bits & ((1 << POS_BITS) - 1));
            block[pos >> 6] |= uint64_t{1} << (pos & 63);
            bits >>= POS_BITS;
        }
    }

    //! False means definitely not inserted; true means probably inserted.
    //! An empty filter (empty set) returns false for everything.
    bool MayContain(const COutPoint& outpoint) const noexcept
    {
        if (m_words.empty()) return false;
        const auto [h1, h2] = Hash(outpoint);
        const uint64_t* block{&m_words[(h1 & m_block_mask) * WORDS_PER_BLOCK]};
        uint64_t bits{h2};
        for (int i{0}; i < HASHES; ++i) {
            const unsigned pos(bits & ((1 << POS_BITS) - 1));
            if ((block[pos >> 6] & (uint64_t{1} << (pos & 63))) == 0) return false;
            bits >>= POS_BITS;
        }
        return true;
    }

    //! True when the filter describes the empty set.
    bool Empty() const noexcept { return m_words.empty(); }

    size_t DynamicMemoryUsage() const { return memusage::DynamicUsage(m_words); }
};

#endif // BITCOIN_COINSFILTER_H
