// Load gate (ТЗ §5 «Отказать в загрузке», §6). The decision is made once per file,
// synchronously, in the thread that maps it, before any of its code can run.
#pragma once

#include <cstdint>
#include <string>

#include "nt.hpp"
#include "trust/engine.hpp"

namespace mebet::gate {

// NtCreateSection(SEC_IMAGE) slow path. false = deny with STATUS_ACCESS_DENIED (the
// close has been requested already).
bool on_image_section(HANDLE file);
// NtCreateSection succeeded: the next map of this handle on this thread is pre-approved.
void on_section_created(HANDLE section);

// NtMapViewOfSection of an image into our process succeeded. false = unmap and deny.
bool on_image_view(HANDLE section, void* base, SIZE_T size);
void on_view_unmapped(void* base);

// LdrRegisterDllNotification: accounting and report, no veto (ТЗ §5).
void register_loader_notifications();

// The decision for a module that was already in the process before the hooks (start-up
// self-check, ТЗ §5 «Проверка при старте агента»).
trust::Decision decide_loaded_module(std::uintptr_t base, std::size_t size, const std::wstring& peb_name);

// Builds the "closed: module" report and asks the guard to close.
void deny_module(const trust::Decision& d, config::Reason reason, const char* phase);

bool jvm_started();
void set_jvm_started();

// The guard's own reading of a file through Windows APIs (VERSIONINFO for a report card,
// a version floor) may map that file as an image resource. Inside this scope such
// mappings belong to the guard itself and pass the gate — otherwise building the report
// about a refused file would ask the gate about the same file again, forever.
class OwnReadScope {
public:
    OwnReadScope();
    ~OwnReadScope();
    OwnReadScope(const OwnReadScope&) = delete;
    OwnReadScope& operator=(const OwnReadScope&) = delete;
};
bool own_read_on_this_thread();

}  // namespace mebet::gate
