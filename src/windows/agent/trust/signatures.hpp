// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Authenticode and catalog signatures of a file (ТЗ §6 «Процедура проверки»).
//
// Every signature is read: the primary one and the nested ones (OBS carries RSA + ECC,
// vendors often sign second to fourth), then the catalog when the file has no usable
// embedded signature (~75% of system DLLs are catalog-only). No network: cache-only URL
// retrieval, no revocation (revocation goes through the denylist, ТЗ §6).
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "config_types.hpp"
#include "nt.hpp"
#include "sha256.hpp"

namespace mebet::trust {

struct Signer {
    std::string cn, o, ou, c;  // leaf subject, UTF-8
    std::string issuer_cn;
    std::string serial;  // upper-case hex, big-endian, no leading zeros
    Sha256Digest leaf_sha256{};
    std::string root_cn;
    Sha256Digest root_sha256{};
    bool ms_os = false;   // CERT_CHAIN_POLICY_MICROSOFT_ROOT, flags 0
    bool ms_app = false;  // … with CHECK_APPLICATION_ROOT (Microsoft Root 2011)
    int pinned_root = -1; // index into config::kRoots of the chain's own end (for the report card)
    // Bit i: the chain is anchored on kRoots[i] — a certificate in it carries that root's subject
    // and key, self-signed or cross-signed. The publisher rule matches on this, not on pinned_root.
    std::uint32_t pinned_mask = 0;
    std::vector<std::string> ekus;
    std::int64_t not_before = 0, not_after = 0;  // unix seconds
    std::int64_t timestamp = 0;                  // from the countersignature, 0 if none
    std::string tsa_cn;
};

enum class SigKind { none, embedded, catalog };

struct Signatures {
    SigKind kind = SigKind::none;
    long result = 0;           // WinVerifyTrust result of the primary signature or the catalog
    std::wstring catalog;      // catalog file, for catalog signatures
    std::vector<Signer> signers;
    bool digest_invalid = false;    // the file changed after it was signed
    bool sha2_unsupported = false;  // Windows 7 without KB4474419
};

// Loads and exercises wintrust / crypt32 and their providers before the hooks exist, so
// that a check inside the load hook never has to load another DLL (ТЗ §5).
void warm_up(const std::wstring& sample_embedded, const std::wstring& sample_catalog);
bool windows7_without_sha2();

Signatures read_embedded(HANDLE file, const std::wstring& path);
Signatures read_catalog(HANDLE file, const std::wstring& path);

}  // namespace mebet::trust
