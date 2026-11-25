// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// SHA-256 (FIPS 180-4). Own implementation so that the wrapper can hash the agent
// before any crypto DLL is loaded, and so that every platform hashes the same way.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace mebet {

struct Sha256Digest {
    unsigned char bytes[32];
    bool operator==(const Sha256Digest& o) const;
    bool operator!=(const Sha256Digest& o) const { return !(*this == o); }
    std::string hex() const;  // lower-case
};

class Sha256 {
public:
    Sha256();
    void update(const void* data, std::size_t len);
    Sha256Digest finish();

    static Sha256Digest of(const void* data, std::size_t len);

private:
    void block(const unsigned char* p);

    std::uint32_t h_[8];
    unsigned char buf_[64];
    std::size_t buf_len_;
    std::uint64_t total_;
};

}  // namespace mebet
