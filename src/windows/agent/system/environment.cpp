// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
#include "system/environment.hpp"

#if defined(_M_IX86) || defined(_M_X64)
#include <intrin.h>
#endif

#include <cstdio>
#include <cstring>
#include <vector>

#include "config.hpp"
#include "core/guard.hpp"
#include "core/watchdog.hpp"
#include "core/win_util.hpp"
#include "json_writer.hpp"
#include "report/cards.hpp"
#include "strings.hpp"
#include "trust/engine.hpp"

namespace mebet::env {

namespace {

std::string g_vm_class = "unknown";

// ---- Hypervisor information: CPUID on x86/x64, SystemHypervisorDetailInformation on ARM64.
struct Hv {
    bool present = false;
    std::string vendor;       // leaf 0x40000000
    std::string vendor_100;   // leaf 0x40000100 (KVM with Hyper-V enlightenments)
    std::uint32_t features_ebx = 0;  // leaf 0x40000003 EBX: partition privileges, high half
    bool features_known = false;
};

std::string regs_to_vendor(std::uint32_t b, std::uint32_t c, std::uint32_t d) {
    char s[13];
    std::memcpy(s, &b, 4);
    std::memcpy(s + 4, &c, 4);
    std::memcpy(s + 8, &d, 4);
    s[12] = 0;
    std::string out;
    for (char ch : s) {
        if (!ch) break;
        out.push_back(ch >= 32 && ch < 127 ? ch : '?');
    }
    return out;
}

Hv read_hypervisor() {
    Hv hv;
#if defined(_M_IX86) || defined(_M_X64)
    int r[4];
    __cpuid(r, 1);
    hv.present = (static_cast<std::uint32_t>(r[2]) >> 31) & 1;
    if (!hv.present) return hv;
    __cpuid(r, 0x40000000);
    const auto max_leaf = static_cast<std::uint32_t>(r[0]);
    hv.vendor = regs_to_vendor(r[1], r[2], r[3]);
    if (max_leaf >= 0x40000003) {
        __cpuid(r, 0x40000003);
        hv.features_ebx = static_cast<std::uint32_t>(r[1]);
        hv.features_known = true;
    }
    __cpuid(r, 0x40000100);
    const std::string v100 = regs_to_vendor(r[1], r[2], r[3]);
    if (v100 != hv.vendor) hv.vendor_100 = v100;
#else
    nt::HypervisorDetailInformation info{};
    const auto& a = nt::api();
    if (a.NtQuerySystemInformation &&
        nt::ok(a.NtQuerySystemInformation(nt::kSystemHypervisorDetailInformation, &info, sizeof(info), nullptr))) {
        const auto& v = info.HvVendorAndMaxFunction.Data;
        hv.vendor = regs_to_vendor(v[1], v[2], v[3]);
        hv.present = !hv.vendor.empty();
        hv.features_ebx = info.HvFeatures.Data[1];
        hv.features_known = hv.present;
    }
#endif
    return hv;
}

bool known_vm_vendor(const std::string& v) {
    static const char* const kVendors[] = {"VMwareVMware", "VBoxVBoxVBox", "KVMKVMKVM", "TCGTCGTCGTCG", "prl hyperv",
                                           "lrpepyh  vr", "XenVMMXenVMM", "bhyve bhyve", "ACRNACRNACRN", "QNXQVMBSQG",
                                           "VirtualApple", "UnisysSpar64", "Jailhouse", "SRESRESRESRE"};
    for (const char* k : kVendors)
        if (v.compare(0, std::strlen(k), k) == 0) return true;
    return false;
}

// ---- SMBIOS (manufacturer and model only — serials and UUIDs are never read, ТЗ §12).
struct Smbios {
    std::string bios_vendor, manufacturer, product;
};

Smbios read_smbios() {
    Smbios s;
    const DWORD sig = 'RSMB';
    const UINT size = GetSystemFirmwareTable(sig, 0, nullptr, 0);
    if (!size || size > (1u << 20)) return s;
    std::vector<unsigned char> buf(size);
    if (GetSystemFirmwareTable(sig, 0, buf.data(), size) != size || size < 8) return s;
    const std::uint32_t len = *reinterpret_cast<const std::uint32_t*>(buf.data() + 4);
    const unsigned char* p = buf.data() + 8;
    const unsigned char* end = p + (len < size - 8 ? len : size - 8);
    while (p + 4 <= end) {
        const unsigned char type = p[0], flen = p[1];
        if (flen < 4 || p + flen > end) break;
        const unsigned char* strings = p + flen;
        auto str = [&](unsigned char index) {
            if (!index) return std::string();
            const unsigned char* q = strings;
            for (unsigned char i = 1; i < index && q < end; ++i) {
                while (q < end && *q) ++q;
                ++q;
            }
            std::string out;
            while (q < end && *q && out.size() < 64) out.push_back(static_cast<char>(*q++));
            return out;
        };
        if (type == 0 && flen > 4) s.bios_vendor = str(p[4]);
        if (type == 1 && flen > 5) {
            s.manufacturer = str(p[4]);
            s.product = str(p[5]);
        }
        const unsigned char* q = strings;
        while (q + 1 < end && !(q[0] == 0 && q[1] == 0)) ++q;
        p = q + 2;
        if (type == 127) break;
    }
    return s;
}

bool smbios_says_vm(const Smbios& s) {
    const std::string all = lower_ascii(s.bios_vendor + "|" + s.manufacturer + "|" + s.product);
    static const char* const kMarks[] = {"vmware", "virtualbox", "innotek", "qemu", "kvm", "xen", "parallels",
                                         "bochs", "virtual machine", "google compute engine", "amazon ec2",
                                         "openstack", "bhyve", "apple virtualization"};
    for (const char* m : kMarks)
        if (all.find(m) != std::string::npos) return true;
    return false;
}

// ---- Loaded kernel modules.
std::vector<std::wstring> kernel_modules() {
    std::vector<std::wstring> out;
    const auto& a = nt::api();
    if (!a.NtQuerySystemInformation) return out;
    ULONG size = 1 << 16;
    std::vector<unsigned char> buf;
    for (int i = 0; i < 5; ++i) {
        buf.resize(size);
        ULONG ret = 0;
        const NTSTATUS s = a.NtQuerySystemInformation(nt::kSystemModuleInformation, buf.data(), size, &ret);
        if (nt::ok(s)) break;
        if (s != nt::kStatusInfoLengthMismatch) return out;
        size = ret > size ? ret + 4096 : size * 2;
    }
    const auto* mods = reinterpret_cast<const nt::ProcessModules*>(buf.data());
    for (ULONG i = 0; i < mods->NumberOfModules && i < 4096; ++i) {
        const auto& m = mods->Modules[i];
        const char* full = reinterpret_cast<const char*>(m.FullPathName);
        out.push_back(win::from_ansi(std::string(full, strnlen(full, sizeof(m.FullPathName)))));
    }
    return out;
}

std::vector<std::string> guest_drivers() {
    static const char* const kGuest[] = {"vmbus.sys", "storvsc.sys", "netvsc.sys", "hyperkbd.sys", "vmbushid.sys",
                                         "vboxguest.sys", "vboxmouse.sys", "vboxsf.sys", "vboxwddm.sys", "vmhgfs.sys",
                                         "vmmouse.sys", "vm3dmp.sys", "vmci.sys", "vmmemctl.sys", "prl_fs.sys",
                                         "prl_tg.sys", "prl_eth5.sys", "xenbus.sys", "xenvbd.sys", "viostor.sys",
                                         "vioscsi.sys", "netkvm.sys", "balloon.sys", "qemupciserial.sys"};
    std::vector<std::string> found;
    for (const auto& path : kernel_modules()) {
        const std::string name = to_utf8(lower_ascii(win::file_name_of(path)));
        for (const char* g : kGuest)
            if (name == g) found.push_back(name);
    }
    return found;
}

std::wstring kernel_path_to_dos(const std::wstring& p) {
    if (istarts_with(p, L"\\SystemRoot\\")) return win::windows_dir() + p.substr(11);
    if (istarts_with(p, L"\\??\\")) return p.substr(4);
    if (istarts_with(p, L"\\Windows\\")) return win::windows_dir() + p.substr(8);
    if (p.find(L'\\') == std::wstring::npos) return win::windows_dir() + L"\\System32\\drivers\\" + p;
    if (istarts_with(p, L"System32\\")) return win::windows_dir() + L"\\" + p;
    return win::nt_to_dos(p);
}

report::Event make_event(const char* type, const char* title, report::Level level) {
    report::Event ev;
    ev.type = type;
    ev.title = title;
    ev.level = level;
    return ev;
}

}  // namespace

void check_dev_mode() {
    // Locked module: runs in every build (ТЗ §8).
    const auto& a = nt::api();
    if (!a.NtQuerySystemInformation) return;
    nt::CodeIntegrityInformation ci{sizeof(ci), 0};
    const bool ci_ok = nt::ok(a.NtQuerySystemInformation(nt::kSystemCodeIntegrityInformation, &ci, sizeof(ci), nullptr));
    bool kd_enabled = false, kd_present = false;
    nt::KernelDebuggerInformationEx kx{};
    if (nt::ok(a.NtQuerySystemInformation(nt::kSystemKernelDebuggerInformationEx, &kx, sizeof(kx), nullptr))) {
        kd_enabled = kx.DebuggerEnabled != 0;
        kd_present = kx.DebuggerPresent != 0;
    } else {
        nt::KernelDebuggerInformation kd{};
        if (nt::ok(a.NtQuerySystemInformation(nt::kSystemKernelDebuggerInformation, &kd, sizeof(kd), nullptr))) {
            kd_enabled = kd.KernelDebuggerEnabled != 0;
            kd_present = kd.KernelDebuggerNotPresent == 0;
        }
    }
    const ULONG o = ci.CodeIntegrityOptions;
    const bool test_sign = ci_ok && (o & nt::kCiTestSign);
    const bool debug_mode = ci_ok && (o & nt::kCiDebugModeEnabled);
    // ТЗ §8: on 32-bit Windows the default of 0x01 is not measured yet; the rule waits.
    const bool require_ci = !win::is_native_x86_os() || config::opt::devmode_require_ci_on_x86;
    const bool ci_off = ci_ok && require_ci && !(o & nt::kCiEnabled);
    if (!(test_sign || debug_mode || ci_off || kd_enabled || kd_present)) return;

    report::Event ev = make_event("close.dev_mode", "Closed: Windows developer mode", report::Level::error);
    char raw[16];
    std::snprintf(raw, sizeof(raw), "0x%08lX", static_cast<unsigned long>(o));
    JsonWriter w;
    w.begin_object();
    w.field("code_integrity_options", raw);
    w.field("test_signing", test_sign);
    w.field("debug_mode", debug_mode);
    w.field("code_integrity_off", ci_off);
    w.field("kernel_debugger_enabled", kd_enabled);
    w.field("kernel_debugger_present", kd_present);
    w.end_object();
    ev.extra_json = w.take();
    ev.fingerprint = {"close.dev_mode", raw};
    // The flags go into the launcher log line too: the player and support see which one.
    std::wstring which;
    auto add = [&](bool on, const wchar_t* name) {
        if (!on) return;
        if (!which.empty()) which += L", ";
        which += name;
    };
    add(test_sign, L"testsigning");
    add(debug_mode, L"debug mode");
    add(ci_off, L"code integrity off");
    add(kd_enabled, L"kernel debugger enabled");
    add(kd_present, L"kernel debugger attached");
    which += L" (CodeIntegrityOptions " + win::wide(raw) + L")";
    guard::close_now(config::Reason::dev_mode, which, std::move(ev));
}

std::string vm_class() { return g_vm_class; }

void check_virtual_machine() {
    const Hv hv = read_hypervisor();
    const Smbios bios = read_smbios();
    const bool bios_vm = smbios_says_vm(bios);
    std::vector<std::string> guests;
    std::string cls;
    bool close = false;

    if (!hv.present) {
        cls = bios_vm ? "physical_vm_hardware" : "physical";
        if (bios_vm) {
            guests = guest_drivers();
            close = !guests.empty();  // hypervisor bit hidden, but SMBIOS and guest drivers agree
        }
    } else if (known_vm_vendor(hv.vendor) || known_vm_vendor(hv.vendor_100)) {
        cls = "known_vm";
        close = true;  // a host never calls itself that (ТЗ §8)
    } else if (hv.vendor == "Microsoft Hv") {
        const bool root = hv.features_known && (hv.features_ebx & 1u) && (hv.features_ebx & (1u << 12));
        guests = guest_drivers();
        const bool second_sign = bios_vm || !guests.empty();
        if (root) {
            cls = second_sign ? "root_with_vm_hardware" : "host_hypervisor";
            close = second_sign;
        } else {
            cls = "hyperv_guest";
            close = config::opt::vm_close_hyperv_guest && second_sign;
        }
    } else {
        cls = "unknown_hypervisor";
    }
    g_vm_class = cls;
    report::Reporter::instance().set_tag("vm", cls);

    const bool report_only = !close && (cls == "hyperv_guest" || cls == "unknown_hypervisor" || cls == "physical_vm_hardware");
    if (!close && !report_only) return;

    report::Event ev = make_event(close ? "close.virtual_machine" : "report.virtual_machine",
                                  close ? "Closed: virtual machine" : "Report: hypervisor", close ? report::Level::error
                                                                                                   : report::Level::warning);
    char ebx[16];
    std::snprintf(ebx, sizeof(ebx), "0x%08X", hv.features_ebx);
    JsonWriter w;
    w.begin_object();
    w.field("class", cls);
    w.field("vendor_40000000", hv.vendor);
    w.field("vendor_40000100", hv.vendor_100);
    w.field("ebx_40000003", ebx);
    w.field("smbios_manufacturer", truncate_utf8(bios.manufacturer, 64));
    w.field("smbios_product", truncate_utf8(bios.product, 64));
    w.field("smbios_bios_vendor", truncate_utf8(bios.bios_vendor, 64));
    w.key("guest_drivers").begin_array();
    for (const auto& g : guests) w.value(g);
    w.end_array();
    w.end_object();
    ev.extra_json = w.take();
    ev.fingerprint = {ev.type, cls, hv.vendor};
    if (close && config::closes(config::Module::virtual_machine)) {
        guard::close_now(config::Reason::virtual_machine, std::wstring(), std::move(ev));
    }
    if (config::enabled(config::Module::virtual_machine)) {
        ev.dedupe_key = ev.type;
        report::Reporter::instance().submit(std::move(ev));
    }
}

void tag_kernel_state() {
    const auto& a = nt::api();
    if (!a.NtQuerySystemInformation) return;
    nt::SecureBootInformation sb{};
    const bool sb_ok = nt::ok(a.NtQuerySystemInformation(nt::kSystemSecureBootInformation, &sb, sizeof(sb), nullptr));
    nt::CodeIntegrityInformation ci{sizeof(ci), 0};
    const bool ci_ok = nt::ok(a.NtQuerySystemInformation(nt::kSystemCodeIntegrityInformation, &ci, sizeof(ci), nullptr));
    auto& r = report::Reporter::instance();
    r.set_tag("secure_boot", sb_ok ? (sb.SecureBootEnabled ? "on" : "off") : "unknown");
    r.set_tag("hvci", ci_ok ? ((ci.CodeIntegrityOptions & nt::kCiHvciKmciEnabled) ? "on" : "off") : "unknown");
}

void report_wine() {
    const auto& a = nt::api();
    if (!a.wine_get_version || !config::enabled(config::Module::wine)) return;
    const char* v = a.wine_get_version();
    report::Event ev = make_event("report.wine", "Report: Wine/Proton", report::Level::warning);
    JsonWriter w;
    w.begin_object().field("wine_version", truncate_utf8(v ? v : "", 64)).end_object();
    ev.extra_json = w.take();
    ev.fingerprint = {"report.wine", v ? v : ""};
    ev.dedupe_key = "report.wine";
    report::Reporter::instance().submit(std::move(ev));
}

void report_extension_points() {
    if (!config::enabled(config::Module::extension_points)) return;
    JsonWriter w;
    w.begin_object();
    bool any = false;
    std::string key;

    // Image File Execution Options for our exe and Java.
    const std::wstring exe = win::file_name_of(win::module_path(nullptr));
    w.key("ifeo").begin_array();
    for (const std::wstring& name : {exe, std::wstring(L"javaw.exe"), std::wstring(L"java.exe")}) {
        const std::wstring k = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\" + name;
        for (const wchar_t* v : {L"Debugger", L"VerifierDlls", L"GlobalFlag"}) {
            std::wstring val = win::reg_string(HKEY_LOCAL_MACHINE, k.c_str(), v);
            const DWORD flag = win::reg_dword(HKEY_LOCAL_MACHINE, k.c_str(), v, 0);
            if (val.empty() && flag == 0) continue;
            if (val.empty()) val = std::to_wstring(flag);
            any = true;
            key = "ifeo";
            w.begin_object();
            w.field("image", to_utf8(name));
            w.field("value", to_utf8(v));
            w.field("data", cards::anonymize(val));
            w.end_object();
        }
    }
    w.end_array();

    // AppInit_DLLs (both views) and AppCertDlls.
    w.key("appinit").begin_array();
    for (REGSAM view : {static_cast<REGSAM>(KEY_WOW64_64KEY), static_cast<REGSAM>(KEY_WOW64_32KEY)}) {
        const wchar_t* k = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
        const std::wstring dlls = win::reg_string(HKEY_LOCAL_MACHINE, k, L"AppInit_DLLs", view);
        const DWORD load = win::reg_dword(HKEY_LOCAL_MACHINE, k, L"LoadAppInit_DLLs", 0, view);
        if (dlls.empty()) continue;
        any = true;
        if (key.empty()) key = "appinit";
        w.begin_object();
        w.field("view", view == KEY_WOW64_64KEY ? "64" : "32");
        w.field("dlls", cards::anonymize(dlls));
        w.field("load_appinit", static_cast<std::uint64_t>(load));
        w.end_object();
    }
    w.end_array();
    w.key("appcert").begin_array();
    const wchar_t* ac = L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls";
    for (const auto& name : win::reg_value_names(HKEY_LOCAL_MACHINE, ac)) {
        const std::wstring path = win::reg_string(HKEY_LOCAL_MACHINE, ac, name.c_str());
        any = true;
        if (key.empty()) key = "appcert";
        w.begin_object();
        w.field("name", to_utf8(name));
        w.field("path", cards::anonymize(path));
        if (win::file_exists(path)) w.key("file").raw(cards::file_card_json(path));
        w.end_object();
    }
    w.end_array();
    w.end_object();
    if (!any) return;
    report::Event ev = make_event("report.extension_points", "Report: OS extension points are set", report::Level::warning);
    ev.extra_json = w.take();
    ev.fingerprint = {"report.extension_points", key};
    ev.dedupe_key = "report.extension_points";
    report::Reporter::instance().submit(std::move(ev));
}

void report_drivers() {
    if (!config::enabled(config::Module::driver_names)) return;
    JsonWriter w;
    w.begin_object();
    w.key("drivers").begin_array();
    unsigned listed = 0;
    for (const auto& kernel_path : kernel_modules()) {
        if (listed >= config::kLimit_list_items) break;
        if (guard::closing()) return;  // a close is pending: it must not wait for this report
        watchdog::worker_beat();  // a signature and a hash per driver: minutes on a slow disk
        const std::wstring path = kernel_path_to_dos(kernel_path);
        const trust::Decision d = trust::decide_path(path);
        if (d.verdict.trust == trust::Trust::os) continue;  // Microsoft
        ++listed;
        w.begin_object();
        w.field("name", to_utf8(win::file_name_of(path)));
        w.field("path", cards::anonymize(path));
        const auto& sig = d.facts.sigs;
        w.field("signer", sig.signers.empty() ? std::string() : sig.signers.front().cn);
        w.field("signer_o", sig.signers.empty() ? std::string() : sig.signers.front().o);
        HANDLE h = trust::open_read(path);
        Sha256Digest sha{};
        if (h != INVALID_HANDLE_VALUE) {
            if (trust::sha256_of(h, sha, 64ull << 20)) w.field("sha256", sha.hex());
            CloseHandle(h);
        }
        w.end_object();
    }
    w.end_array();
    w.end_object();
    if (!listed) return;
    report::Event ev = make_event("report.drivers", "Report: non-Microsoft drivers", report::Level::info);
    ev.extra_json = w.take();
    ev.fingerprint = {"report.drivers"};
    ev.dedupe_key = "report.drivers";
    report::Reporter::instance().submit(std::move(ev));
}

void check_debugger() {
    if (!config::enabled(config::Module::debugger)) return;
    const auto& a = nt::api();
    if (!a.NtQueryInformationProcess) return;
    ULONG_PTR port = 0;
    if (!nt::ok(a.NtQueryInformationProcess(nt::current_process(), nt::kProcessDebugPort, &port, sizeof(port), nullptr)) ||
        port == 0)
        return;
    // The parent process: a "debugger" substituted through IFEO shows up here (ТЗ §12).
    PROCESS_BASIC_INFORMATION pbi{};
    std::wstring parent;
    if (nt::ok(a.NtQueryInformationProcess(nt::current_process(), 0 /* ProcessBasicInformation */, &pbi, sizeof(pbi), nullptr))) {
        const DWORD ppid = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(pbi.Reserved3));
        if (HANDLE p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ppid)) {
            wchar_t buf[MAX_PATH * 2];
            DWORD n = MAX_PATH * 2;
            if (QueryFullProcessImageNameW(p, 0, buf, &n)) parent.assign(buf, n);
            CloseHandle(p);
        }
    }
    report::Event ev = make_event("close.debugger", "Closed: debugger attached", report::Level::error);
    JsonWriter w;
    w.begin_object();
    if (!parent.empty()) w.key("parent").raw(cards::file_card_json(parent));
    w.end_object();
    ev.extra_json = w.take();
    std::string parent_key = "unknown";
    if (!parent.empty()) {
        HANDLE h = trust::open_read(parent);
        Sha256Digest sha{};
        if (h != INVALID_HANDLE_VALUE) {
            if (trust::sha256_of(h, sha, 512ull << 20)) parent_key = sha.hex();
            CloseHandle(h);
        }
    }
    ev.fingerprint = {"close.debugger", parent_key};
    guard::signal(config::Module::debugger, config::Reason::debugger, std::wstring(), std::move(ev));
}

void check_time() {
    if (!config::enabled(config::Module::time_check)) return;
    // KUSER_SHARED_DATA.InterruptTime (100 ns, kernel-updated) against the performance
    // counter: a speed hack inside the process can only move one of them.
    struct KSystemTime {
        ULONG LowPart;
        LONG High1Time;
        LONG High2Time;
    };
    const volatile auto* it = reinterpret_cast<const volatile KSystemTime*>(0x7FFE0008);
    auto interrupt_time = [&]() -> std::uint64_t {
        for (;;) {
            const LONG hi = it->High1Time;
            const ULONG lo = it->LowPart;
            if (hi == it->High2Time) return (static_cast<std::uint64_t>(static_cast<ULONG>(hi)) << 32) | lo;
        }
    };
    static std::uint64_t last_it = 0;
    static LARGE_INTEGER last_qpc{};
    static bool reported = false;
    LARGE_INTEGER now_qpc, freq;
    QueryPerformanceCounter(&now_qpc);
    QueryPerformanceFrequency(&freq);
    const std::uint64_t now_it = interrupt_time();
    if (last_it && !reported) {
        const double kernel_s = static_cast<double>(now_it - last_it) / 1e7;
        const double qpc_s = static_cast<double>(now_qpc.QuadPart - last_qpc.QuadPart) / static_cast<double>(freq.QuadPart);
        if (kernel_s > 5 && kernel_s < 600 && qpc_s > 0) {
            const double ratio = qpc_s / kernel_s;
            if (ratio < 0.95 || ratio > 1.05) {
                reported = true;
                report::Event ev = make_event("report.time", "Report: clock mismatch", report::Level::warning);
                JsonWriter w;
                w.begin_object();
                w.key("kernel_seconds").value_double(kernel_s);
                w.key("qpc_seconds").value_double(qpc_s);
                w.key("ratio").value_double(ratio);
                w.end_object();
                ev.extra_json = w.take();
                ev.fingerprint = {"report.time"};
                ev.dedupe_key = "report.time";
                report::Reporter::instance().submit(std::move(ev));
            }
        }
    }
    last_it = now_it;
    last_qpc = now_qpc;
}

}  // namespace mebet::env
