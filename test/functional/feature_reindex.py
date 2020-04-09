#!/usr/bin/env python3
# Copyright (c) 2014-2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test running bitcoind with -reindex and -reindex-chainstate options.

- Start a single node and generate 3 blocks.
- Stop the node and restart it with -reindex. Verify that the node has reindexed up to block 3.
- Stop the node and restart it with -reindex-chainstate. Verify that the node has reindexed up to block 3.
- Verify that out-of-order blocks are correctly processed, see LoadExternalBlockFile()
"""

import os
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    wait_until,
)

class ReindexTest(BitcoinTestFramework):

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def reindex(self, justchainstate=False):
        self.nodes[0].generatetoaddress(3, self.nodes[0].get_deterministic_priv_key().address)
        self.sync_blocks()
        blockcount = self.nodes[0].getblockcount()
        self.stop_nodes()
        extra_args = [["-reindex-chainstate" if justchainstate else "-reindex"]]
        self.start_nodes(extra_args)
        wait_until(lambda: self.nodes[0].getblockcount() == blockcount)

    # Check that blocks can be processed out of order
    def out_of_order(self):
        # The previous test created 12 blocks
        assert_equal(self.nodes[0].getblockcount(), 12)
        self.stop_nodes()

        # In this test environment, blocks will always be in order (since
        # we're generating them rather than getting them from peers, so to
        # test out-of-order handling, swap blocks 1 and 2 on disk.
        blk0 = os.path.join(self.nodes[0].datadir, self.nodes[0].chain, 'blocks', 'blk00000.dat')
        with open(blk0, 'r+b') as bf:
            b = bf.read(814)

            # This is really just checking the test; these are is the first
            # "marker" bytes of the four blocks, genesis and 3 more
            # (these offsets are extremely unlikely ever to change)
            assert_equal(b[0], 0xfa)
            assert_equal(b[293], 0xfa)
            assert_equal(b[553], 0xfa)
            assert_equal(b[813], 0xfa)

            # Swap the same-size second and third blocks (don't change genesis).
            bf.seek(293)
            bf.write(b[553:813])
            bf.write(b[293:553])

        extra_args = [["-reindex", "-debug=reindex"]]
        self.start_nodes(extra_args)

        # All blocks should be accepted and processed.
        wait_until(lambda: self.nodes[0].getblockcount() == 12)

    def run_test(self):
        self.reindex(False)
        self.reindex(True)
        self.reindex(False)
        self.reindex(True)

        self.out_of_order()

if __name__ == '__main__':
    ReindexTest().main()
