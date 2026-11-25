// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
#include "trust/signatures.hpp"

#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>

#include <cstddef>
#include <cstring>

#include "core/win_util.hpp"
#include "mebet_trust_data.hpp"
#include "strings.hpp"

namespace mebet::trust {

namespace {

// --- Structures newer than the Windows 7 SDK level we compile for -----------------------

constexpr DWORD kWssVerifySpecific = 0x00000001;
constexpr DWORD kWssGetSecondarySigCount = 0x00000002;

struct SignatureSettings {  // WINTRUST_SIGNATURE_SETTINGS (Windows 8+)
    DWORD cbStruct;
    DWORD dwIndex;
    DWORD dwFlags;
    DWORD cSecondarySigs;
    DWORD dwVerifiedSigIndex;
    void* pCryptoPolicy;
};

struct WintrustData {  // WINTRUST_DATA with the Windows 8 pSignatureSettings field
    DWORD cbStruct;
    LPVOID pPolicyCallbackData;
    LPVOID pSIPClientData;
    DWORD dwUIChoice;
    DWORD fdwRevocationChecks;
    DWORD dwUnionChoice;
    void* pInfo;
    DWORD dwStateAction;
    HANDLE hWVTStateData;
    WCHAR* pwszURLReference;
    DWORD dwProvFlags;
    DWORD dwUIContext;
    SignatureSettings* pSignatureSettings;
};

struct CatalogInfo {  // WINTRUST_CATALOG_INFO with the Windows 8 hCatAdmin field
    DWORD cbStruct;
    DWORD dwCatalogVersion;
    LPCWSTR pcwszCatalogFilePath;
    LPCWSTR pcwszMemberTag;
    LPCWSTR pcwszMemberFilePath;
    HANDLE hMemberFile;
    BYTE* pbCalculatedFileHash;
    DWORD cbCalculatedFileHash;
    PCCTL_CONTEXT pcCatalogContext;
    HANDLE hCatAdmin;
};

constexpr DWORD kMicrosoftRootCheckApplicationRoot = 0x00020000;

using AcquireContext2Fn = BOOL(WINAPI*)(HCATADMIN*, const GUID*, PCWSTR, PCCERT_STRONG_SIGN_PARA, DWORD);
using CalcHash2Fn = BOOL(WINAPI*)(HCATADMIN, HANDLE, DWORD*, BYTE*, DWORD);

struct CatApi {
    AcquireContext2Fn acquire2 = nullptr;
    CalcHash2Fn calc2 = nullptr;
};

const CatApi& cat_api() {
    static const CatApi a = [] {
        CatApi c;
        if (HMODULE w = GetModuleHandleW(L"wintrust.dll")) {
            c.acquire2 = reinterpret_cast<AcquireContext2Fn>(
                reinterpret_cast<void*>(GetProcAddress(w, "CryptCATAdminAcquireContext2")));
            c.calc2 = reinterpret_cast<CalcHash2Fn>(
                reinterpret_cast<void*>(GetProcAddress(w, "CryptCATAdminCalcHashFromFileHandle2")));
        }
        return c;
    }();
    return a;
}

bool g_sha2_broken = false;

// --- Certificate fields ------------------------------------------------------------------

std::string name_attr(PCCERT_CONTEXT cert, const char* oid, bool issuer) {
    wchar_t buf[512];
    const DWORD n = CertGetNameStringW(cert, CERT_NAME_ATTR_TYPE, issuer ? CERT_NAME_ISSUER_FLAG : 0,
                                       const_cast<char*>(oid), buf, 512);
    if (n <= 1) return std::string();
    return to_utf8(std::wstring(buf, n - 1));
}

std::string simple_name(PCCERT_CONTEXT cert) {
    wchar_t buf[512];
    const DWORD n = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, buf, 512);
    return n > 1 ? to_utf8(std::wstring(buf, n - 1)) : std::string();
}

std::string serial_hex(PCCERT_CONTEXT cert) {
    const CRYPT_INTEGER_BLOB& s = cert->pCertInfo->SerialNumber;  // little-endian
    std::string out;
    static const char* digits = "0123456789ABCDEF";
    for (DWORD i = s.cbData; i > 0; --i) {
        const BYTE b = s.pbData[i - 1];
        out.push_back(digits[b >> 4]);
        out.push_back(digits[b & 15]);
    }
    const auto first = out.find_first_not_of('0');
    return first == std::string::npos ? std::string("0") : out.substr(first);
}

std::int64_t unix_seconds(const FILETIME& ft) {
    const std::uint64_t t = (static_cast<std::uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    if (t < 116444736000000000ull) return 0;
    return static_cast<std::int64_t>((t - 116444736000000000ull) / 10000000ull);
}

std::vector<std::string> ekus_of(PCCERT_CONTEXT cert) {
    std::vector<std::string> out;
    DWORD size = 0;
    if (!CertGetEnhancedKeyUsage(cert, CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG, nullptr, &size) || size == 0) return out;
    std::vector<unsigned char> buf(size);
    auto* usage = reinterpret_cast<PCERT_ENHKEY_USAGE>(buf.data());
    if (!CertGetEnhancedKeyUsage(cert, CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG, usage, &size)) return out;
    for (DWORD i = 0; i < usage->cUsageIdentifier && out.size() < 16; ++i) out.emplace_back(usage->rgpszUsageIdentifier[i]);
    return out;
}

bool microsoft_root(PCCERT_CHAIN_CONTEXT chain, DWORD flags) {
    if (!chain) return false;
    CERT_CHAIN_POLICY_PARA para{};
    para.cbSize = sizeof(para);
    para.dwFlags = flags;
    CERT_CHAIN_POLICY_STATUS status{};
    status.cbSize = sizeof(status);
    return CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_MICROSOFT_ROOT, chain, &para, &status) &&
           status.dwError == 0;
}

int pinned_index(PCCERT_CONTEXT root) {
    if (!root) return -1;
    const Sha256Digest d = Sha256::of(root->pbCertEncoded, root->cbCertEncoded);
    for (std::size_t i = 0; i < sizeof(config::kRoots) / sizeof(config::kRoots[0]); ++i) {
        if (std::memcmp(d.bytes, config::kRoots[i].sha256, 32) == 0) return static_cast<int>(i);
    }
    return -1;
}

PCCERT_CONTEXT chain_root(PCCERT_CHAIN_CONTEXT chain) {
    if (!chain || chain->cChain == 0) return nullptr;
    const CERT_SIMPLE_CHAIN* simple = chain->rgpChain[0];
    if (!simple || simple->cElement == 0) return nullptr;
    return simple->rgpElement[simple->cElement - 1]->pCertContext;
}

// Chain engine whose only anchors are the roots pinned in config/roots.json. Used when
// the system store does not know a root (Windows 7 without root updates, ТЗ §6).
HCERTCHAINENGINE pinned_engine() {
    static HCERTCHAINENGINE engine = [] {
        HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, nullptr);
        if (!store) return HCERTCHAINENGINE(nullptr);
        for (const auto& r : config::kRoots) {
            CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING, r.der, static_cast<DWORD>(r.der_len),
                                             CERT_STORE_ADD_ALWAYS, nullptr);
        }
        CERT_CHAIN_ENGINE_CONFIG cfg{};
        cfg.cbSize = sizeof(cfg);
        cfg.hExclusiveRoot = store;
        cfg.dwFlags = CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL | CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE;
        HCERTCHAINENGINE e = nullptr;
        if (!CertCreateCertificateChainEngine(&cfg, &e)) e = nullptr;
        return e;
    }();
    return engine;
}

// Builds the chain of the leaf against the pinned roots only. Time validity is not
// required: an expired leaf with a valid timestamp is fine (ТЗ §6), WinVerifyTrust has
// already judged the time against the timestamp.
int pinned_root_by_own_chain(PCCERT_CONTEXT leaf, HCERTSTORE extra) {
    HCERTCHAINENGINE engine = pinned_engine();
    if (!engine) return -1;
    CERT_CHAIN_PARA para{};
    para.cbSize = sizeof(para);
    PCCERT_CHAIN_CONTEXT chain = nullptr;
    if (!CertGetCertificateChain(engine, leaf, nullptr, extra, &para, CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL, nullptr,
                                 &chain))
        return -1;
    const DWORD ignore = CERT_TRUST_IS_NOT_TIME_VALID | CERT_TRUST_IS_NOT_TIME_NESTED | CERT_TRUST_REVOCATION_STATUS_UNKNOWN |
                         CERT_TRUST_IS_OFFLINE_REVOCATION | CERT_TRUST_IS_NOT_VALID_FOR_USAGE;
    int idx = -1;
    if ((chain->TrustStatus.dwErrorStatus & ~ignore) == 0) idx = pinned_index(chain_root(chain));
    CertFreeCertificateChain(chain);
    return idx;
}

void fill_signer(CRYPT_PROVIDER_DATA* prov, Signer& s) {
    CRYPT_PROVIDER_SGNR* sgnr = WTHelperGetProvSignerFromChain(prov, 0, FALSE, 0);
    if (!sgnr) return;
    CRYPT_PROVIDER_CERT* pc = WTHelperGetProvCertFromChain(sgnr, 0);
    if (!pc || !pc->pCert) return;
    PCCERT_CONTEXT leaf = pc->pCert;
    s.cn = name_attr(leaf, szOID_COMMON_NAME, false);
    s.o = name_attr(leaf, szOID_ORGANIZATION_NAME, false);
    s.ou = name_attr(leaf, szOID_ORGANIZATIONAL_UNIT_NAME, false);
    s.c = name_attr(leaf, szOID_COUNTRY_NAME, false);
    s.issuer_cn = name_attr(leaf, szOID_COMMON_NAME, true);
    s.serial = serial_hex(leaf);
    s.leaf_sha256 = Sha256::of(leaf->pbCertEncoded, leaf->cbCertEncoded);
    s.ekus = ekus_of(leaf);
    s.not_before = unix_seconds(leaf->pCertInfo->NotBefore);
    s.not_after = unix_seconds(leaf->pCertInfo->NotAfter);
    if (sgnr->csCounterSigners > 0 && sgnr->pasCounterSigners) {
        s.timestamp = unix_seconds(sgnr->sftVerifyAsOf);
        CRYPT_PROVIDER_CERT* tsa = WTHelperGetProvCertFromChain(&sgnr->pasCounterSigners[0], 0);
        if (tsa && tsa->pCert) s.tsa_cn = name_attr(tsa->pCert, szOID_COMMON_NAME, false);
    }

    PCCERT_CONTEXT root = chain_root(sgnr->pChainContext);
    if (root && CertCompareCertificateName(X509_ASN_ENCODING, &root->pCertInfo->Subject, &root->pCertInfo->Issuer)) {
        s.root_cn = simple_name(root);
        s.root_sha256 = Sha256::of(root->pbCertEncoded, root->cbCertEncoded);
        s.ms_os = microsoft_root(sgnr->pChainContext, 0);
        s.ms_app = !s.ms_os && microsoft_root(sgnr->pChainContext, kMicrosoftRootCheckApplicationRoot);
        s.pinned_root = pinned_index(root);
    }
    if (!s.ms_os && !s.ms_app && s.pinned_root < 0) {
        // The system chain did not reach a known root: try the pinned roots with the
        // certificates that came with the signature.
        HCERTSTORE collection = CertOpenStore(CERT_STORE_PROV_COLLECTION, 0, 0, 0, nullptr);
        if (collection) {
            for (DWORD i = 0; i < prov->chStores; ++i) CertAddStoreToCollection(collection, prov->pahStores[i], 0, 0);
            s.pinned_root = pinned_root_by_own_chain(leaf, collection);
            if (s.pinned_root >= 0 && s.root_cn.empty()) s.root_cn = config::kRoots[s.pinned_root].name;
            CertCloseStore(collection, 0);
        }
    }
}

// The digest of the file is valid and a signer could be read (the root may still be unknown).
bool digest_ok(LONG r) {
    return r == ERROR_SUCCESS || r == CERT_E_UNTRUSTEDROOT || r == CERT_E_CHAINING ||
           r == static_cast<LONG>(CERT_E_UNTRUSTEDTESTROOT) || r == CERT_E_UNTRUSTEDCA;
}

bool no_signature(LONG r) {
    return r == TRUST_E_NOSIGNATURE || r == TRUST_E_SUBJECT_FORM_UNKNOWN || r == TRUST_E_PROVIDER_UNKNOWN;
}

// One WinVerifyTrust round; fills the signer when the digest is valid.
LONG verify_one(DWORD union_choice, void* info, SignatureSettings* settings, Signer* signer, bool* got) {
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WintrustData wd{};
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = union_choice;
    wd.pInfo = info;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE | WTD_DISABLE_MD2_MD4;
    wd.pSignatureSettings = win::is_windows8_or_later() ? settings : nullptr;
    const LONG r = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &wd);
    *got = false;
    if (digest_ok(r) && wd.hWVTStateData) {
        if (CRYPT_PROVIDER_DATA* prov = WTHelperProvDataFromStateData(wd.hWVTStateData)) {
            fill_signer(prov, *signer);
            *got = !signer->cn.empty() || !signer->o.empty();
        }
    }
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &wd);
    return r;
}

std::wstring hex_upper(const BYTE* p, DWORD n) {
    static const wchar_t* digits = L"0123456789ABCDEF";
    std::wstring s(n * 2, L'0');
    for (DWORD i = 0; i < n; ++i) {
        s[2 * i] = digits[p[i] >> 4];
        s[2 * i + 1] = digits[p[i] & 15];
    }
    return s;
}

bool sha2_failure(LONG r) {
    return r == NTE_BAD_ALGID || r == TRUST_E_BAD_DIGEST || r == TRUST_E_NOSIGNATURE;
}

}  // namespace

bool windows7_without_sha2() { return g_sha2_broken; }

Signatures read_embedded(HANDLE file, const std::wstring& path) {
    Signatures out;
    WINTRUST_FILE_INFO fi{};
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = path.c_str();
    fi.hFile = file;

    SignatureSettings ss{};
    ss.cbStruct = sizeof(ss);
    ss.dwIndex = 0;
    ss.dwFlags = kWssGetSecondarySigCount | kWssVerifySpecific;
    Signer first;
    bool got = false;
    out.result = verify_one(WTD_CHOICE_FILE, &fi, &ss, &first, &got);
    if (no_signature(out.result)) {
        out.kind = SigKind::none;
        return out;
    }
    out.kind = SigKind::embedded;
    if (out.result == TRUST_E_BAD_DIGEST) out.digest_invalid = true;
    if (got) out.signers.push_back(std::move(first));

    // Nested signatures (Windows 8+): OBS carries two, vendors often sign 2nd–4th.
    const DWORD secondary = win::is_windows8_or_later() ? ss.cSecondarySigs : 0;
    for (DWORD i = 1; i <= secondary && i <= 8; ++i) {
        SignatureSettings si{};
        si.cbStruct = sizeof(si);
        si.dwIndex = i;
        si.dwFlags = kWssVerifySpecific;
        Signer s;
        bool g = false;
        const LONG r = verify_one(WTD_CHOICE_FILE, &fi, &si, &s, &g);
        if (r == TRUST_E_BAD_DIGEST) out.digest_invalid = true;
        if (g) out.signers.push_back(std::move(s));
    }
    if (g_sha2_broken && out.signers.empty()) out.sha2_unsupported = true;
    return out;
}

Signatures read_catalog(HANDLE file, const std::wstring& path) {
    Signatures out;
    const CatApi& api = cat_api();
    struct Algo {
        const wchar_t* name;  // nullptr = SHA-1
    };
    const Algo algos[] = {{L"SHA256"}, {nullptr}};
    for (const Algo& algo : algos) {
        HCATADMIN admin = nullptr;
        bool v2 = false;
        if (algo.name) {
            if (!api.acquire2 || !api.calc2) continue;  // Windows 7: SHA-1 catalogs only
            if (!api.acquire2(&admin, nullptr, algo.name, nullptr, 0)) continue;
            v2 = true;
        } else if (!CryptCATAdminAcquireContext(&admin, nullptr, 0)) {
            continue;
        }
        BYTE hash[64];
        DWORD hash_len = sizeof(hash);
        const BOOL hashed = v2 ? api.calc2(admin, file, &hash_len, hash, 0)
                               : CryptCATAdminCalcHashFromFileHandle(file, &hash_len, hash, 0);
        if (hashed) {
            const std::wstring tag = hex_upper(hash, hash_len);
            HCATINFO prev = nullptr;
            for (HCATINFO cat = CryptCATAdminEnumCatalogFromHash(admin, hash, hash_len, 0, &prev); cat;
                 cat = CryptCATAdminEnumCatalogFromHash(admin, hash, hash_len, 0, &prev)) {
                prev = cat;
                CATALOG_INFO ci{};
                ci.cbStruct = sizeof(ci);
                if (!CryptCATCatalogInfoFromContext(cat, &ci, 0)) continue;
                CatalogInfo wc{};
                wc.cbStruct = win::is_windows8_or_later() ? sizeof(wc) : static_cast<DWORD>(offsetof(CatalogInfo, hCatAdmin));
                wc.pcwszCatalogFilePath = ci.wszCatalogFile;
                wc.pcwszMemberTag = tag.c_str();
                wc.pcwszMemberFilePath = path.c_str();
                wc.hMemberFile = file;
                wc.pbCalculatedFileHash = hash;
                wc.cbCalculatedFileHash = hash_len;
                wc.hCatAdmin = admin;
                Signer s;
                bool got = false;
                const LONG r = verify_one(WTD_CHOICE_CATALOG, &wc, nullptr, &s, &got);
                if (got) {
                    out.kind = SigKind::catalog;
                    out.result = r;
                    out.catalog = win::file_name_of(ci.wszCatalogFile);
                    out.signers.push_back(std::move(s));
                    CryptCATAdminReleaseCatalogContext(admin, cat, 0);
                    CryptCATAdminReleaseContext(admin, 0);
                    return out;
                }
            }
            // The enumeration releases the previous context itself; the last one is
            // released when the enumeration returns nullptr.
        }
        CryptCATAdminReleaseContext(admin, 0);
    }
    return out;
}

void warm_up(const std::wstring& sample_embedded, const std::wstring& sample_catalog) {
    cat_api();
    pinned_engine();
    if (!sample_catalog.empty()) {
        HANDLE f = CreateFileW(sample_catalog.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
                               OPEN_EXISTING, 0, nullptr);
        if (f != INVALID_HANDLE_VALUE) {
            read_embedded(f, sample_catalog);
            read_catalog(f, sample_catalog);
            CloseHandle(f);
        }
    }
    if (!sample_embedded.empty()) {
        HANDLE f = CreateFileW(sample_embedded.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
                               OPEN_EXISTING, 0, nullptr);
        if (f != INVALID_HANDLE_VALUE) {
            const Signatures s = read_embedded(f, sample_embedded);
            // Windows 7 without the SHA-2 update cannot verify a SHA-256 Authenticode
            // signature such as the Java vendor's (ТЗ §6: close with a clear reason).
            const auto& v = win::os_version();
            if (v.major == 6 && v.minor == 1 && s.signers.empty() && sha2_failure(s.result)) g_sha2_broken = true;
            CloseHandle(f);
        }
    }
}

}  // namespace mebet::trust
