// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <logging.h>
#include <test/util/setup_common.h>


static void Logging(benchmark::Bench& bench, const std::vector<const char*>& extra_args, const std::function<void()>& log)
{
    // Reset any enabled logging categories from a previous benchmark run.
    LogInstance().DisableCategory(BCLog::LogFlags::ALL);

    TestingSetup test_setup{
        CBaseChainParams::REGTEST,
        extra_args,
    };

    bench.run([&] { log(); });
}

// The test framework currently enables all categories by default, but in case
// that changes, we set -debug=category in the benchmarks below when we expect a
// category to be logged.

static void LogPrintLevelWithThreadNames(benchmark::Bench& bench)
{
    Logging(bench, {"-logthreadnames=1", "-debug=validation"}, [] {
        LogPrintLevel(BCLog::VALIDATION, BCLog::Level::Error, "%s\n", "test");
    });
}

static void LogPrintLevelWithoutThreadNames(benchmark::Bench& bench)
{
    Logging(bench, {"-logthreadnames=0", "-debug=validation"}, [] {
        LogPrintLevel(BCLog::VALIDATION, BCLog::Level::Error, "%s\n", "test");
    });
}

static void LogPrintWithCategory(benchmark::Bench& bench)
{
    Logging(bench, {"-logthreadnames=0", "-debug=validation"}, [] {
        LogPrint(BCLog::VALIDATION, "%s\n", "test");
    });
}

static void LogPrintWithoutCategory(benchmark::Bench& bench)
{
    Logging(bench, {"-logthreadnames=0", "-debug=0"}, [] {
        LogPrint(BCLog::VALIDATION, "%s\n", "test");
    });
}

static void LogPrintfCategoryWithThreadNames(benchmark::Bench& bench)
{
    Logging(bench, {"-logthreadnames=1", "-debug=validation"}, [] {
        LogPrintfCategory(BCLog::VALIDATION, "%s\n", "test");
    });
}

static void LogPrintfCategoryWithoutThreadNames(benchmark::Bench& bench)
{
    Logging(bench, {"-logthreadnames=0", "-debug=validation"}, [] {
        LogPrintfCategory(BCLog::VALIDATION, "%s\n", "test");
    });
}

static void LogPrintfWithThreadNames(benchmark::Bench& bench)
{
    Logging(bench, {"-logthreadnames=1"}, [] { LogPrintf("%s\n", "test"); });
}

static void LogPrintfWithoutThreadNames(benchmark::Bench& bench)
{
    Logging(bench, {"-logthreadnames=0"}, [] { LogPrintf("%s\n", "test"); });
}

static void LogWithoutWriteToFile(benchmark::Bench& bench)
{
    // Disable writing the log to a file, as used for unit tests and fuzzing in `MakeNoLogFileContext`.
    Logging(bench, {"-nodebuglogfile", "-debug=1"}, [] {
        LogPrintf("%s\n", "test");
        LogPrint(BCLog::VALIDATION, "%s\n", "test");
    });
}

BENCHMARK(LogPrintLevelWithThreadNames, benchmark::PriorityLevel::HIGH);
BENCHMARK(LogPrintLevelWithoutThreadNames, benchmark::PriorityLevel::HIGH);
BENCHMARK(LogPrintWithCategory, benchmark::PriorityLevel::HIGH);
BENCHMARK(LogPrintWithoutCategory, benchmark::PriorityLevel::HIGH);
BENCHMARK(LogPrintfCategoryWithThreadNames, benchmark::PriorityLevel::HIGH);
BENCHMARK(LogPrintfCategoryWithoutThreadNames, benchmark::PriorityLevel::HIGH);
BENCHMARK(LogPrintfWithThreadNames, benchmark::PriorityLevel::HIGH);
BENCHMARK(LogPrintfWithoutThreadNames, benchmark::PriorityLevel::HIGH);
BENCHMARK(LogWithoutWriteToFile, benchmark::PriorityLevel::HIGH);
