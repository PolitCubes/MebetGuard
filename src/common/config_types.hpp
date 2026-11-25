// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Types of the tables that tools/gen_config.py generates from config/*.json.
// The tables themselves live in the generated headers mebet_config.hpp and
// mebet_trust_data.hpp; nothing here is read from disk at runtime (ТЗ §3).
#pragma once

#include <cstddef>
#include <cstdint>

namespace mebet::config {

// Reaction of a protection module (ТЗ §3 «Куда попадает каждый сигнал»).
enum class Level : unsigned char {
    off,     // switched off — test builds only
    report,  // signal goes to the report, the game keeps running
    close,   // close the client + report
    on,      // always active, no verdict (hardening, DACL, dropping injected input…)
};

struct ModuleDef {
    const char* id;
    const char* title;  // UTF-8, for reports and logs
    Level level;
    bool locked;  // dev_mode: cannot be switched off in any build
};

struct ReasonDef {
    const char* id;
    int exit_code;
    const wchar_t* title_ru;
    const wchar_t* title_en;
    const wchar_t* text_ru;  // may contain "{file}"
    const wchar_t* text_en;
};

// Root classes (ТЗ §6 «Корни, закреплённые в клиенте»). ms_os / ms_app are decided by
// CERT_CHAIN_POLICY_MICROSOFT_ROOT, the others by the pinned root's identity (subject and public
// key) anywhere in the validated chain, self-signed or cross-signed.
enum class RootClass : unsigned char {
    ms_os,      // Microsoft Root 2010 and older product roots
    ms_app,     // Microsoft Root 2011 (application root)
    ms_ivr,     // Microsoft Identity Verification Root 2020 — Trusted Signing customers, NOT Microsoft
    public_ca,  // pinned public code signing roots
};

struct RootDef {
    const char* id;
    RootClass cls;
    const unsigned char* der;
    std::size_t der_len;
    unsigned char sha256[32];
    const char* name;
};

struct PublisherDef {
    const char* id;
    const char* name;   // UTF-8
    const char* group;  // gpu, overlay, antivirus, input, shell, utility, peripheral, audio, java
    std::uint32_t root_mask;  // bit i = kRoots[i] is acceptable
    const char* min_product_version;  // optional VERSIONINFO ProductVersion floor
};

// One accepted (CN, O[, issuer CN]) variant of a publisher, already normalized with
// mebet::normalize_name (case and punctuation folded).
struct SignerDef {
    std::uint16_t publisher;  // index into kPublishers
    const char* cn;
    const char* o;
    const char* issuer_cn;  // nullptr = any issuer
};

// Serial prefix of a certificate already seen for a publisher (history, not a match key).
struct ObservationDef {
    std::uint16_t publisher;
    const char* serial_prefix;  // upper hex, leading zeros stripped
};

enum class DenyKind : unsigned char {
    leaf_sha256,     // sha256 = SHA-256 of the leaf certificate
    issuer_serial,   // a = normalized issuer CN, b = serial (upper hex, no leading zeros)
    publisher_file,  // a = normalized CN, b = normalized O, c = lower-case file name
    file_sha256,     // sha256 = SHA-256 of the file
};

struct DenyDef {
    const char* id;
    DenyKind kind;
    const char* a;
    const char* b;
    const char* c;
    unsigned char sha256[32];
};

struct HashDef {
    std::uint64_t size;
    unsigned char sha256[32];
    const char* label;  // "<profile>:<path>"
};

}  // namespace mebet::config
