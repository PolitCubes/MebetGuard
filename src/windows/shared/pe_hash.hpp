// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Signing-invariant hash of a PE file.
//
// The wrapper embeds the hash of the agent (ТЗ §4 step 4: "хэш агента вшит в exe"), but
// the agent is signed after the build (SignPath), and signing rewrites the checksum, the
// certificate directory entry and appends the certificate table. This hash skips exactly
// those, so the value computed at build time matches the signed file:
//   SHA-256( [0, checksum) + [checksum+4, certdir) + [certdir+8, end of last section) )
// Data after the last section (overlay: certificate table, alignment) is not mapped and
// does not take part. tools/agent_hash.py implements the same function for the build.
#pragma once

#include <cstddef>

#include "sha256.hpp"

namespace mebet::win {

bool pe_image_hash(const unsigned char* data, std::size_t size, Sha256Digest& out);

}  // namespace mebet::win
