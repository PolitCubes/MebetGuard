// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
#include "process/dacl.hpp"

#include <vector>

#include "config.hpp"

namespace mebet::dacl {

namespace {

std::vector<unsigned char> g_process_sd;  // self-relative descriptors, built once
std::vector<unsigned char> g_thread_sd;
bool g_ready = false;

std::vector<unsigned char> token_user_sid() {
    std::vector<unsigned char> out;
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return out;
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<unsigned char> buf(size);
    if (size && GetTokenInformation(token, TokenUser, buf.data(), size, &size)) {
        const auto* tu = reinterpret_cast<const TOKEN_USER*>(buf.data());
        const DWORD len = GetLengthSid(tu->User.Sid);
        out.assign(static_cast<const unsigned char*>(tu->User.Sid), static_cast<const unsigned char*>(tu->User.Sid) + len);
    }
    CloseHandle(token);
    return out;
}

// Self-relative SD with a protected DACL: user gets `user_rights`, OWNER RIGHTS gets READ_CONTROL.
std::vector<unsigned char> build(const std::vector<unsigned char>& user_sid, DWORD user_rights) {
    std::vector<unsigned char> out;
    SID_IDENTIFIER_AUTHORITY creator = SECURITY_CREATOR_SID_AUTHORITY;
    PSID owner_rights = nullptr;
    if (!AllocateAndInitializeSid(&creator, 1, SECURITY_CREATOR_OWNER_RIGHTS_RID, 0, 0, 0, 0, 0, 0, 0, &owner_rights))
        return out;
    const DWORD acl_size = sizeof(ACL) + 2 * sizeof(ACCESS_ALLOWED_ACE) + static_cast<DWORD>(user_sid.size()) +
                           GetLengthSid(owner_rights);
    std::vector<unsigned char> acl_buf(acl_size);
    auto* acl = reinterpret_cast<PACL>(acl_buf.data());
    bool ok = InitializeAcl(acl, acl_size, ACL_REVISION) &&
              AddAccessAllowedAce(acl, ACL_REVISION, user_rights, const_cast<unsigned char*>(user_sid.data())) &&
              AddAccessAllowedAce(acl, ACL_REVISION, READ_CONTROL, owner_rights);
    SECURITY_DESCRIPTOR sd{};
    ok = ok && InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION) && SetSecurityDescriptorDacl(&sd, TRUE, acl, FALSE) &&
         SetSecurityDescriptorControl(&sd, SE_DACL_PROTECTED, SE_DACL_PROTECTED);
    if (ok) {
        DWORD len = 0;
        MakeSelfRelativeSD(&sd, nullptr, &len);
        out.resize(len);
        if (!len || !MakeSelfRelativeSD(&sd, out.data(), &len)) out.clear();
    }
    FreeSid(owner_rights);
    return out;
}

bool apply(HANDLE object, std::vector<unsigned char>& sd) {
    const auto& a = nt::api();
    if (sd.empty() || !a.NtSetSecurityObject) return false;
    return nt::ok(a.NtSetSecurityObject(object, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, sd.data()));
}

}  // namespace

bool prepare() {
    if (g_ready) return true;
    const std::vector<unsigned char> user = token_user_sid();
    if (user.empty()) return false;
    // OBS opens the game with QUERY_INFORMATION | SYNCHRONIZE; Task Manager needs TERMINATE (ТЗ §7).
    g_process_sd = build(user, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION | SYNCHRONIZE | PROCESS_TERMINATE);
    g_thread_sd = build(user, THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE);
    g_ready = !g_process_sd.empty() && !g_thread_sd.empty();
    return g_ready;
}

bool protect_process() {
    if (!config::enabled(config::Module::process_dacl) || !prepare()) return false;
    return apply(nt::current_process(), g_process_sd);
}

bool protect_thread(HANDLE thread) {
    if (!config::enabled(config::Module::process_dacl) || !g_ready) return false;
    return apply(thread, g_thread_sd);
}

void protect_current_thread() {
    if (g_ready && config::enabled(config::Module::process_dacl)) apply(nt::current_thread(), g_thread_sd);
}

void protect_existing_threads() {
    if (!config::enabled(config::Module::process_dacl) || !g_ready) return;
    const auto& a = nt::api();
    if (!a.NtGetNextThread) return;
    HANDLE prev = nullptr;
    for (int i = 0; i < 4096; ++i) {
        HANDLE next = nullptr;
        if (!nt::ok(a.NtGetNextThread(nt::current_process(), prev, WRITE_DAC | READ_CONTROL, 0, 0, &next)) || !next) break;
        if (prev) CloseHandle(prev);
        apply(next, g_thread_sd);
        prev = next;
    }
    if (prev) CloseHandle(prev);
}

}  // namespace mebet::dacl
