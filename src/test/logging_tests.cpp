// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <logging.h>
#include <logging/timer.h>
#include <test/util/setup_common.h>

#include <chrono>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(logging_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(logging_timer)
{
    SetMockTime(1);
    auto sec_timer = BCLog::Timer<std::chrono::seconds>("tests", "end_msg");
    SetMockTime(2);
    BOOST_CHECK_EQUAL(sec_timer.LogMsg("test secs"), "tests: test secs (1.00s)");

    SetMockTime(1);
    auto ms_timer = BCLog::Timer<std::chrono::milliseconds>("tests", "end_msg");
    SetMockTime(2);
    BOOST_CHECK_EQUAL(ms_timer.LogMsg("test ms"), "tests: test ms (1000.00ms)");

    SetMockTime(1);
    auto micro_timer = BCLog::Timer<std::chrono::microseconds>("tests", "end_msg");
    SetMockTime(2);
    BOOST_CHECK_EQUAL(micro_timer.LogMsg("test micros"), "tests: test micros (1000000.00μs)");
}

BOOST_AUTO_TEST_CASE(rotate)
{
    // The values represent the contents of the log files,
    // a[i] = j means debug.i contains j. There should never be
    // Value (content) zero means that log file doesn't exist.
    // The content can be thought of as a timestamp (ever increasing).
    std::array<int, 10> a, b;

    auto exists = [&a](int i) { BOOST_CHECK(i < 10); return a[i] > 0; };
    auto remove = [&a](int i) { a[i] = 0; };
    auto rename = [&a](int from, int to) {
        // Rename source should alway exist.
        BOOST_CHECK(a[from] > 0);
        // Some platforms, such as Windows, don't allow the rename target
        // to be an existing file (represented here by content > 0). The
        // algorithm should ensure that the rename target doesn't exist.
        if (a[to] > 0) {
            BOOST_CHECK(a[to] == 0);
            return false;
        }
        a[to] = a[from];
        return true;
    };

    // Initially, there are no log files, so nothing to rotate. Return 0
    // to indicate that debug.log should be renamed debug.0.
    //   0  1  2  3  4  5  6  7  8  9
    a = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    b = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    BOOST_CHECK_EQUAL(BCLog::Shift(3, 10, exists, remove, rename), 0);
    BOOST_CHECK(a == b);

    // Only debug.0 exists (content = 1), so leave it unchanged, return 1
    // so that debug.log can be renamed to debug.1.
    //   0  1  2  3  4  5  6  7  8  9
    a = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    b = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    BOOST_CHECK_EQUAL(BCLog::Shift(3, 10, exists, remove, rename), 1);
    BOOST_CHECK(a == b);

    // Still ramping up, not needing to delete (rotate) any files.
    //   0  1  2  3  4  5  6  7  8  9
    a = {1, 2, 0, 0, 0, 0, 0, 0, 0, 0};
    b = {1, 2, 0, 0, 0, 0, 0, 0, 0, 0};
    BOOST_CHECK_EQUAL(BCLog::Shift(3, 10, exists, remove, rename), 2);
    BOOST_CHECK(a == b);

    // After this, debug.0, .1, .2, exist, now can rename debug.log to
    // debug.3 (there will be 3 backup files, the requested number).
    //   0  1  2  3  4  5  6  7  8  9
    a = {1, 2, 3, 0, 0, 0, 0, 0, 0, 0};
    b = {1, 2, 3, 0, 0, 0, 0, 0, 0, 0};
    BOOST_CHECK_EQUAL(BCLog::Shift(3, 10, exists, remove, rename), 3);
    BOOST_CHECK(a == b);

    // This should cause a shift (sequence of renames), and allow
    // debug.log to be renamed to debug.3. Note here that debug.1
    // (a[1], (oldest) will contain content 2 (the previous debug.2),
    // debug.2 will contain 3, and so on.
    //   0  1  2  3  4  5  6  7  8  9
    a = {1, 2, 3, 4, 0, 0, 0, 0, 0, 0};
    b = {2, 3, 4, 0, 0, 0, 0, 0, 0, 0};
    BOOST_CHECK_EQUAL(BCLog::Shift(3, 10, exists, remove, rename), 3);
    BOOST_CHECK(a == b);

    // Another shift (stead-state pattern), leaving name debug.3
    // available to rename debug.log into.
    //   0  1  2  3  4  5  6  7  8  9
    a = {2, 3, 4, 5, 0, 0, 0, 0, 0, 0};
    b = {3, 4, 5, 0, 0, 0, 0, 0, 0, 0};
    BOOST_CHECK_EQUAL(BCLog::Shift(3, 10, exists, remove, rename), 3);
    BOOST_CHECK(a == b);

    // In this scenario, the number of backup debug.log files was
    // set to 4 (as is the current state of this test), but then
    // node is restarted with a smaller number of backups, say, 2.
    // The algorithm should keep the backup files ordered correctly
    // by shifting down by two instead of just one, leaving debug.2
    // available to rename debug.log into.
    //   0  1  2  3  4  5  6  7  8  9
    a = {3, 4, 5, 6, 0, 0, 0, 0, 0, 0};
    b = {5, 6, 0, 0, 0, 0, 0, 0, 0, 0};
    BOOST_CHECK_EQUAL(BCLog::Shift(2, 10, exists, remove, rename), 2);
    BOOST_CHECK(a == b);

    // If the number of backup debug.log files is increased, no
    // shifting is needed, and the return value tells us to rename
    // debug.log to debug.4 (first 0 position).
    //   0  1  2  3  4  5  6  7  8  9
    a = {5, 6, 7, 0, 0, 0, 0, 0, 0, 0};
    b = {5, 6, 7, 0, 0, 0, 0, 0, 0, 0};
    BOOST_CHECK_EQUAL(BCLog::Shift(3, 10, exists, remove, rename), 3);
    BOOST_CHECK(a == b);

    // Check the edge case where we want to retain only one backup
    // log files, debug.log will renamed to debug.1. (This is also
    // how you retain zero backup files, just don't rename debug.log.)
    //   0  1  2  3  4  5  6  7  8  9
    a = {5, 6, 7, 8, 0, 0, 0, 0, 0, 0};
    b = {8, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    BOOST_CHECK_EQUAL(BCLog::Shift(1, 10, exists, remove, rename), 1);
    BOOST_CHECK(a == b);

    // Check the edge case where we don't want to retain backup files.
    //   0  1  2  3  4  5  6  7  8  9
    a = {5, 6, 7, 8, 0, 0, 0, 0, 0, 0};
    b = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    BOOST_CHECK_EQUAL(BCLog::Shift(0, 10, exists, remove, rename), 0);
    BOOST_CHECK(a == b);

    // Another edge case, retain 9 backups (must be less than 10).
    //   0  1  2  3  4  5  6  7  8  9
    a = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    b = {2, 3, 4, 5, 6, 7, 8, 9, 10, 0};
    BOOST_CHECK_EQUAL(BCLog::Shift(9, 10, exists, remove, rename), 9);
    BOOST_CHECK(a == b);
}

BOOST_AUTO_TEST_SUITE_END()
