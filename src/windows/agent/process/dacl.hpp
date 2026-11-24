// Process and thread DACL (ТЗ §7 «Права в DACL»). Everything not listed is denied: reading
// and writing memory, creating threads, duplicating handles, suspending, changing rights;
// on threads — SET_CONTEXT (APC, thread hijack) and SUSPEND_RESUME. SYSTEM and an
// administrator with SeDebugPrivilege pass by any DACL; handles opened before are not revoked.
#pragma once

#include "nt.hpp"

namespace mebet::dacl {

// Builds the descriptors (process: user = QUERY_LIMITED | QUERY | SYNCHRONIZE | TERMINATE,
// OWNER RIGHTS = READ_CONTROL; threads: user = QUERY_LIMITED | SYNCHRONIZE).
bool prepare();
bool protect_process();
// Existing threads (agent start) — new ones go through protect_current_thread().
void protect_existing_threads();
void protect_current_thread();  // DLL_THREAD_ATTACH
bool protect_thread(HANDLE thread);

}  // namespace mebet::dacl
