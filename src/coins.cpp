// Copyright (c) 2012-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>

#include <consensus/consensus.h>
#include <logging.h>
#include <random.h>
#include <util/trace.h>
#include <version.h>

bool CCoinsView::GetCoin(const COutPoint &outpoint, Coin &coin) const { return false; }
uint256 CCoinsView::GetBestBlock() const { return uint256(); }
std::vector<uint256> CCoinsView::GetHeadBlocks() const { return std::vector<uint256>(); }
bool CCoinsView::BatchWrite(CCoinsMap &mapCoins, const uint256 &hashBlock, bool erase, bool partial) { return false; }
std::unique_ptr<CCoinsViewCursor> CCoinsView::Cursor() const { return nullptr; }

bool CCoinsView::HaveCoin(const COutPoint &outpoint) const
{
    Coin coin;
    return GetCoin(outpoint, coin);
}

CCoinsViewBacked::CCoinsViewBacked(CCoinsView *viewIn) : base(viewIn) { }
bool CCoinsViewBacked::GetCoin(const COutPoint &outpoint, Coin &coin) const { return base->GetCoin(outpoint, coin); }
bool CCoinsViewBacked::HaveCoin(const COutPoint &outpoint) const { return base->HaveCoin(outpoint); }
uint256 CCoinsViewBacked::GetBestBlock() const { return base->GetBestBlock(); }
std::vector<uint256> CCoinsViewBacked::GetHeadBlocks() const { return base->GetHeadBlocks(); }
void CCoinsViewBacked::SetBackend(CCoinsView &viewIn) { base = &viewIn; }
bool CCoinsViewBacked::BatchWrite(CCoinsMap &mapCoins, const uint256 &hashBlock, bool erase, bool partial) { return base->BatchWrite(mapCoins, hashBlock, erase, partial); }
std::unique_ptr<CCoinsViewCursor> CCoinsViewBacked::Cursor() const { return base->Cursor(); }
size_t CCoinsViewBacked::EstimateSize() const { return base->EstimateSize(); }

CCoinsViewCache::CCoinsViewCache(CCoinsView* baseIn, bool deterministic) :
    CCoinsViewBacked(baseIn), m_deterministic(deterministic),
    cacheCoins(0, SaltedOutpointHasher(/*deterministic=*/deterministic), CCoinsMap::key_equal{}, &m_cache_coins_memory_resource)
{}

size_t CCoinsViewCache::DynamicMemoryUsage() const {
    return memusage::DynamicUsage(cacheCoins) + cachedCoinsUsage; // LMR XXX double-counting?
}

void CCoinsViewCache::MemoryAdd(const CCoinsCacheEntry& entry) const {
    size_t mem_usage{entry.coin.DynamicMemoryUsage()};
    cachedCoinsUsage += mem_usage;
    if (entry.flags & CCoinsCacheEntry::FLUSH) {
        flush_count++;
        flush_coins_usage += mem_usage;
    }
    assert(flush_coins_usage <= cachedCoinsUsage);
}

void CCoinsViewCache::MemorySub(const CCoinsCacheEntry& entry) const {
    size_t mem_usage{entry.coin.DynamicMemoryUsage()};
    cachedCoinsUsage -= mem_usage;
    if (entry.flags & CCoinsCacheEntry::FLUSH) {
        assert(flush_count > 0);
        flush_count--;
        assert(flush_coins_usage >= mem_usage);
        flush_coins_usage -= mem_usage;
    }
    assert(flush_coins_usage <= cachedCoinsUsage);
}

CCoinsMap::iterator CCoinsViewCache::FetchCoin(const COutPoint &outpoint) const {
    CCoinsMap::iterator it = cacheCoins.find(outpoint);
    if (it != cacheCoins.end())
        return it;
    Coin tmp;
    if (!base->GetCoin(outpoint, tmp))
        return cacheCoins.end();
    CCoinsMap::iterator ret = cacheCoins.emplace(std::piecewise_construct, std::forward_as_tuple(outpoint), std::forward_as_tuple(std::move(tmp))).first;
    if (ret->second.coin.IsSpent()) {
        // The parent only has an empty entry for this outpoint; we can consider our
        // version as fresh.
        ret->second.flags = CCoinsCacheEntry::FRESH;
    }
    MemoryAdd(ret->second);
    return ret;
}

bool CCoinsViewCache::GetCoin(const COutPoint &outpoint, Coin &coin) const {
    CCoinsMap::const_iterator it = FetchCoin(outpoint);
    if (it != cacheCoins.end()) {
        coin = it->second.coin;
        return !coin.IsSpent();
    }
    return false;
}

void CCoinsViewCache::AddCoin(const COutPoint &outpoint, Coin&& coin, bool possible_overwrite) {
    assert(!coin.IsSpent());
    if (coin.out.scriptPubKey.IsUnspendable()) return;
    CCoinsMap::iterator it;
    bool inserted;
    std::tie(it, inserted) = cacheCoins.emplace(std::piecewise_construct, std::forward_as_tuple(outpoint), std::tuple<>());
    bool fresh = false;
    if (!inserted) {
        // The coin is being replaced; first subtract the existing coin's memory size
        MemorySub(it->second);
    }
    if (!possible_overwrite) {
        if (!it->second.coin.IsSpent()) {
            throw std::logic_error("Attempted to overwrite an unspent coin (when possible_overwrite is false)");
        }
        // If the coin exists in this cache as a spent coin and is DIRTY, then
        // its spentness hasn't been flushed to the parent cache. We're
        // re-adding the coin to this cache now but we can't mark it as FRESH.
        // If we mark it FRESH and then spend it before the cache is flushed
        // we would remove it from this cache and would never flush spentness
        // to the parent cache.
        //
        // Re-adding a spent coin can happen in the case of a re-org (the coin
        // is 'spent' when the block adding it is disconnected and then
        // re-added when it is also added in a newly connected block).
        //
        // If the coin doesn't exist in the current cache, or is spent but not
        // DIRTY, then it can be marked FRESH.
        fresh = !(it->second.flags & CCoinsCacheEntry::DIRTY);
    }
    it->second.coin = std::move(coin);
    it->second.flags |= CCoinsCacheEntry::DIRTY | (fresh ? CCoinsCacheEntry::FRESH : 0);
    it->second.flags &= ~CCoinsCacheEntry::FLUSH;
    TRACE5(utxocache, add,
           outpoint.hash.data(),
           (uint32_t)outpoint.n,
           (uint32_t)it->second.coin.nHeight,
           (int64_t)it->second.coin.out.nValue,
           (bool)it->second.coin.IsCoinBase());
    static bool tried_open_flushbits{false};
    static FILE* flushbits_fd;
    static int bitmask{0};
    static uint8_t flushbits;
    if (!tried_open_flushbits) {
        tried_open_flushbits = true;
        flushbits_fd = fopen("/ext/linux-share/bitvector-bin", "rb");
    }
    if (flushbits_fd) {
        if (bitmask == 0) {
            bitmask = 0x80;
            if (!fread(&flushbits, 1, 1, flushbits_fd)) {
                // probably reached end of file, that's okay
                flushbits = 0;
                fclose(flushbits_fd);
                flushbits_fd = nullptr;
            }
        }
        // based on the historical record...
        if (flushbits & bitmask) it->second.flags |= CCoinsCacheEntry::FLUSH;
        bitmask >>= 1;
    }
    MemoryAdd(it->second);
}

void CCoinsViewCache::EmplaceCoinInternalDANGER(COutPoint&& outpoint, Coin&& coin) {
    cachedCoinsUsage += coin.DynamicMemoryUsage();
    cacheCoins.emplace(
        std::piecewise_construct,
        std::forward_as_tuple(std::move(outpoint)),
        std::forward_as_tuple(std::move(coin), CCoinsCacheEntry::DIRTY));
}

void AddCoins(CCoinsViewCache& cache, const CTransaction &tx, int nHeight, bool check_for_overwrite) {
    bool fCoinbase = tx.IsCoinBase();
    const uint256& txid = tx.GetHash();
    for (size_t i = 0; i < tx.vout.size(); ++i) {
        bool overwrite = check_for_overwrite ? cache.HaveCoin(COutPoint(txid, i)) : fCoinbase;
        // Coinbase transactions can always be overwritten, in order to correctly
        // deal with the pre-BIP30 occurrences of duplicate coinbase transactions.
        cache.AddCoin(COutPoint(txid, i), Coin(tx.vout[i], nHeight, fCoinbase), overwrite);
    }
}

bool CCoinsViewCache::SpendCoin(const COutPoint &outpoint, Coin* moveout) {
    CCoinsMap::iterator it = FetchCoin(outpoint);
    if (it == cacheCoins.end()) return false;
    MemorySub(it->second);
    TRACE5(utxocache, spent,
           outpoint.hash.data(),
           (uint32_t)outpoint.n,
           (uint32_t)it->second.coin.nHeight,
           (int64_t)it->second.coin.out.nValue,
           (bool)it->second.coin.IsCoinBase());
    if (moveout) {
        *moveout = std::move(it->second.coin);
    }
    if (it->second.flags & CCoinsCacheEntry::FRESH) {
        cacheCoins.erase(it);
    } else {
        it->second.flags |= CCoinsCacheEntry::DIRTY;
        it->second.flags &= ~CCoinsCacheEntry::FLUSH;
        it->second.coin.Clear();
    }
    return true;
}

static const Coin coinEmpty;

const Coin& CCoinsViewCache::AccessCoin(const COutPoint &outpoint) const {
    CCoinsMap::const_iterator it = FetchCoin(outpoint);
    if (it == cacheCoins.end()) {
        return coinEmpty;
    } else {
        return it->second.coin;
    }
}

bool CCoinsViewCache::HaveCoin(const COutPoint &outpoint) const {
    CCoinsMap::const_iterator it = FetchCoin(outpoint);
    return (it != cacheCoins.end() && !it->second.coin.IsSpent());
}

bool CCoinsViewCache::HaveCoinInCache(const COutPoint &outpoint) const {
    CCoinsMap::const_iterator it = cacheCoins.find(outpoint);
    return (it != cacheCoins.end() && !it->second.coin.IsSpent());
}

uint256 CCoinsViewCache::GetBestBlock() const {
    if (hashBlock.IsNull())
        hashBlock = base->GetBestBlock();
    return hashBlock;
}

void CCoinsViewCache::SetBestBlock(const uint256 &hashBlockIn) {
    hashBlock = hashBlockIn;
}

bool CCoinsViewCache::BatchWrite(CCoinsMap &mapCoins, const uint256 &hashBlockIn, bool erase, bool partial) {
    for (CCoinsMap::iterator it = mapCoins.begin();
            it != mapCoins.end();
            it = erase ? mapCoins.erase(it) : std::next(it)) {
        // Ignore non-dirty entries (optimization).
        if (!(it->second.flags & CCoinsCacheEntry::DIRTY)) {
            continue;
        }
        CCoinsMap::iterator itUs = cacheCoins.find(it->first);
        if (itUs == cacheCoins.end()) {
            // The parent cache does not have an entry, while the child cache does.
            // We can ignore it if it's both spent and FRESH in the child
            if (!(it->second.flags & CCoinsCacheEntry::FRESH && it->second.coin.IsSpent())) {
                // Create the coin in the parent cache, move the data up
                // and mark it as dirty.
                CCoinsCacheEntry& entry = cacheCoins[it->first];
                if (erase) { // true if flushing from block validation (ConnectTip) to main mem cache
                    // The `move` call here is purely an optimization; we rely on the
                    // `mapCoins.erase` call in the `for` expression to actually remove
                    // the entry from the child map.
                    entry.coin = std::move(it->second.coin);
                } else {
                    entry.coin = it->second.coin;
                }
                entry.flags = CCoinsCacheEntry::DIRTY;
                // We can mark it FRESH in the parent if it was FRESH in the child
                // Otherwise it might have just been flushed from the parent's cache
                // and already exist in the grandparent
                if (it->second.flags & CCoinsCacheEntry::FRESH) {
                    entry.flags |= CCoinsCacheEntry::FRESH;
                }
                entry.flags |= it->second.flags & CCoinsCacheEntry::FLUSH;
                MemoryAdd(entry);
            }
        } else {
            // Found the entry in the parent cache
            if ((it->second.flags & CCoinsCacheEntry::FRESH) && !itUs->second.coin.IsSpent()) {
                // The coin was marked FRESH in the child cache, but the coin
                // exists in the parent cache. If this ever happens, it means
                // the FRESH flag was misapplied and there is a logic error in
                // the calling code.
                throw std::logic_error("FRESH flag misapplied to coin that exists in parent cache");
            }

            if ((itUs->second.flags & CCoinsCacheEntry::FRESH) && it->second.coin.IsSpent()) {
                // The grandparent cache does not have an entry, and the coin
                // has been spent. We can just delete it from the parent cache.
                MemorySub(itUs->second);
                cacheCoins.erase(itUs);
            } else {
                // A normal modification (typically, unspent becoming spent).
                MemorySub(itUs->second);
                if (erase) {
                    // The `move` call here is purely an optimization; we rely on the
                    // `mapCoins.erase` call in the `for` expression to actually remove
                    // the entry from the child map.
                    itUs->second.coin = std::move(it->second.coin);
                } else {
                    itUs->second.coin = it->second.coin;
                }
                itUs->second.flags &= ~CCoinsCacheEntry::FLUSH;
                itUs->second.flags |= it->second.flags & CCoinsCacheEntry::FLUSH;
                MemoryAdd(itUs->second);
                itUs->second.flags |= CCoinsCacheEntry::DIRTY;
                // NOTE: It isn't safe to mark the coin as FRESH in the parent
                // cache. If it already existed and was spent in the parent
                // cache then marking it FRESH would prevent that spentness
                // from being flushed to the grandparent.
            }
        }
    }
    hashBlock = hashBlockIn;
    return true;
}

bool CCoinsViewCache::Flush(bool partial_ok) {
    // XXX LMR right here, if partial_ok is set (flushstatetodisk knows),
    // we decide if we should do a partial or a full flush, based
    // on flushed_count (compared with cacheCoins.size())
    // Seems like if there are very few non-flush, OR, very few flush,
    // then just do a complete flush; else do a partial flush.
    // When we do a partial flush, we know that all the FLUSH guys are
    // are written out, so we can just subtract flush_coins_usage
    // from cachedCoinsUsage (and then set flush_coins_usage to zero).
    // (and also set flush_count to 0)
    // If we do a full flush, then we set everything to zero.

    // XXX remove this
    size_t cached_coins_usage{0};
    size_t flush_coins{0};
    size_t nflush{0};
    for (const auto& [_, entry] : cacheCoins) {
        size_t dmu{entry.coin.DynamicMemoryUsage()};
        cached_coins_usage += dmu;
        if (entry.flags & CCoinsCacheEntry::FLUSH) {
            nflush++;
            flush_coins += dmu;
        }
    }
    assert(cachedCoinsUsage == cached_coins_usage);
    assert(flush_coins == flush_coins_usage);
    assert(nflush == flush_count);

    // If there are few flush coins (less than 10%) or many flush
    // coins (more than 90%), then do a normal (full) flush
    bool partial = partial_ok && // IsInitialBlockDownload() &&
        flush_coins_usage * 10 > cachedCoinsUsage &&
        flush_coins_usage * 10 < cachedCoinsUsage * 9;
    if (partial_ok) {
        LogPrint(BCLog::COINDB, "Flush: before cachedCoinsUsage %u f_coins_usage %u  f_count %u p %d\n",
            cachedCoinsUsage, flush_coins_usage, flush_count, partial);
    }
    bool fOk = base->BatchWrite(cacheCoins, hashBlock, /*erase=*/true, partial);
    if (fOk && !partial) {
        if (!cacheCoins.empty()) {
            /* BatchWrite must erase all cacheCoins elements when erase=true. */
            throw std::logic_error("Not all cached coins were erased");
        }
        ReallocateCache();
    }
    if (partial) {
        assert(cachedCoinsUsage >= flush_coins_usage);
        cachedCoinsUsage -= flush_coins_usage;
    } else {
        cachedCoinsUsage = 0;
    }
    // We always flush all of the flush coins.
    flush_coins_usage = 0;
    flush_count = 0;
    if (partial_ok) {
        LogPrint(BCLog::COINDB, "Flush: before cachedCoinsUsage %u f_coins_usage %u  f_count %u\n",
            cachedCoinsUsage, flush_coins_usage, flush_count);
    }

    return fOk;
}

bool CCoinsViewCache::Sync()
{
    bool fOk = base->BatchWrite(cacheCoins, hashBlock, /*erase=*/false);
    // Instead of clearing `cacheCoins` as we would in Flush(), just clear the
    // FRESH/DIRTY flags of any coin that isn't spent.
    for (auto it = cacheCoins.begin(); it != cacheCoins.end(); ) {
        if (it->second.coin.IsSpent()) {
            cachedCoinsUsage -= it->second.coin.DynamicMemoryUsage();
            it = cacheCoins.erase(it);
        } else {
            it->second.flags = 0;
            ++it;
        }
    }
    return fOk;
}

void CCoinsViewCache::Uncache(const COutPoint& hash)
{
    CCoinsMap::iterator it = cacheCoins.find(hash);
    if (it != cacheCoins.end() && it->second.flags == 0) {
        cachedCoinsUsage -= it->second.coin.DynamicMemoryUsage();
        TRACE5(utxocache, uncache,
               hash.hash.data(),
               (uint32_t)hash.n,
               (uint32_t)it->second.coin.nHeight,
               (int64_t)it->second.coin.out.nValue,
               (bool)it->second.coin.IsCoinBase());
        cacheCoins.erase(it);
    }
}

unsigned int CCoinsViewCache::GetCacheSize() const {
    return cacheCoins.size();
}

bool CCoinsViewCache::HaveInputs(const CTransaction& tx) const
{
    if (!tx.IsCoinBase()) {
        for (unsigned int i = 0; i < tx.vin.size(); i++) {
            if (!HaveCoin(tx.vin[i].prevout)) {
                return false;
            }
        }
    }
    return true;
}

void CCoinsViewCache::ReallocateCache()
{
    // Cache should be empty when we're calling this.
    assert(cacheCoins.size() == 0);
    cacheCoins.~CCoinsMap();
    m_cache_coins_memory_resource.~CCoinsMapMemoryResource();
    ::new (&m_cache_coins_memory_resource) CCoinsMapMemoryResource{};
    ::new (&cacheCoins) CCoinsMap{0, SaltedOutpointHasher{/*deterministic=*/m_deterministic}, CCoinsMap::key_equal{}, &m_cache_coins_memory_resource};
}

void CCoinsViewCache::SanityCheck() const
{
    size_t recomputed_usage = 0;
    for (const auto& [_, entry] : cacheCoins) {
        unsigned attr = 0;
        if (entry.flags & CCoinsCacheEntry::DIRTY) attr |= 1;
        if (entry.flags & CCoinsCacheEntry::FRESH) attr |= 2;
        if (entry.coin.IsSpent()) attr |= 4;
        // Only 5 combinations are possible.
        assert(attr != 2 && attr != 4 && attr != 7);

        // Recompute cachedCoinsUsage.
        recomputed_usage += entry.coin.DynamicMemoryUsage();
    }
    assert(recomputed_usage == cachedCoinsUsage);
}

static const size_t MIN_TRANSACTION_OUTPUT_WEIGHT = WITNESS_SCALE_FACTOR * ::GetSerializeSize(CTxOut(), PROTOCOL_VERSION);
static const size_t MAX_OUTPUTS_PER_BLOCK = MAX_BLOCK_WEIGHT / MIN_TRANSACTION_OUTPUT_WEIGHT;

const Coin& AccessByTxid(const CCoinsViewCache& view, const uint256& txid)
{
    COutPoint iter(txid, 0);
    while (iter.n < MAX_OUTPUTS_PER_BLOCK) {
        const Coin& alternate = view.AccessCoin(iter);
        if (!alternate.IsSpent()) return alternate;
        ++iter.n;
    }
    return coinEmpty;
}

bool CCoinsViewErrorCatcher::GetCoin(const COutPoint &outpoint, Coin &coin) const {
    try {
        return CCoinsViewBacked::GetCoin(outpoint, coin);
    } catch(const std::runtime_error& e) {
        for (const auto& f : m_err_callbacks) {
            f();
        }
        LogPrintf("Error reading from database: %s\n", e.what());
        // Starting the shutdown sequence and returning false to the caller would be
        // interpreted as 'entry not found' (as opposed to unable to read data), and
        // could lead to invalid interpretation. Just exit immediately, as we can't
        // continue anyway, and all writes should be atomic.
        std::abort();
    }
}
