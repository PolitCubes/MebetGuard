// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Trustworthiness of the system (ТЗ §8 «Среда», §7 table): dev mode, virtual machine,
// kernel state, drivers, Wine, extension points, debugger, time.
#pragma once

#include <string>

namespace mebet::env {

// ТЗ §8: test signing, debug mode, code integrity off, kernel debugging → close before
// the start, always, on every architecture and in every build. Never returns on failure.
void check_dev_mode();

// ТЗ §8 «Виртуальная машина»: classify and close / report before the start.
void check_virtual_machine();
std::string vm_class();  // tag for every event

// Tags only (ТЗ §12 «Метки»): Secure Boot and HVCI are reported, never required.
void tag_kernel_state();

void report_wine();               // ТЗ §7: Wine/Proton — closes (level of the wine module)
void report_extension_points();   // ТЗ §7: IFEO, AppInit_DLLs, AppCertDlls — report only
void report_drivers();            // ТЗ §12: once per session, non-Microsoft drivers

void check_debugger();            // periodic, close
void check_time();                // periodic, report only

}  // namespace mebet::env
