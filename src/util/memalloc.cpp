// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <stdlib.h>

void* operator new(size_t size) {
    //std::cout << "alloc " << size << '\n';
    return malloc(size);
}

void operator delete(void* p, size_t s) {
    //std::cout << "free " << s << '\n';
    free(p);
}
