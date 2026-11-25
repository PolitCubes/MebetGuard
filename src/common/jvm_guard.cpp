// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
#include "jvm_guard.hpp"

#include <jni.h>
#include <jvmti.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <vector>

#if defined(_MSC_VER)
#include <intrin.h>
#define MEBET_RETURN_ADDRESS() _ReturnAddress()
#else
#define MEBET_RETURN_ADDRESS() __builtin_return_address(0)
#endif

#include "json_writer.hpp"
#include "strings.hpp"

namespace mebet::jvm {

namespace {

Platform g_platform;
std::atomic<bool> g_started{false};
jvmtiEnv* g_jvmti = nullptr;

decltype(JNINativeInterface_::DefineClass) g_orig_define_class = nullptr;
decltype(JNINativeInterface_::RegisterNatives) g_orig_register_natives = nullptr;

// Runtime-defined classes (no protection domain, user loader): first 50 origins.
struct ClassLog {
    std::mutex mu;
    std::vector<std::pair<std::string, std::string>> origins;  // class, loader class
    unsigned long long total = 0;
    bool reported = false;
};
ClassLog& class_log() {
    static ClassLog* l = new ClassLog();
    return *l;
}

thread_local bool t_in_hook = false;

void signal(config::Module m, config::Reason r, const std::string& detail, report::Event ev) {
    if (g_platform.signal) g_platform.signal(m, r, detail, std::move(ev));
}

std::string class_signature(jvmtiEnv* jvmti, jclass k) {
    if (!k) return std::string();
    char* sig = nullptr;
    if (jvmti->GetClassSignature(k, &sig, nullptr) != JVMTI_ERROR_NONE || !sig) return std::string();
    std::string s(sig);
    jvmti->Deallocate(reinterpret_cast<unsigned char*>(sig));
    return s;
}

void report_native_caller(const char* what, const char* name, const void* ret) {
    report::Event ev;
    ev.type = std::string("report.jni_") + what;
    ev.level = report::Level::warning;
    ev.title = std::string("Report: JNI ") + what + " from code outside allowed modules";
    char addr[32];
    std::snprintf(addr, sizeof(addr), "%p", ret);
    JsonWriter w;
    w.begin_object();
    w.field("function", what);
    w.field("name", truncate_utf8(name ? name : "", 256));
    w.field("return_address", addr);
    w.end_object();
    ev.extra_json = w.take();
    ev.fingerprint = {ev.type, name ? name : ""};
    ev.dedupe_key = ev.type + "|" + (name ? name : "");
    signal(config::Module::jvm_classes, config::Reason::unknown_class, name ? name : "", std::move(ev));
}

jclass JNICALL hook_define_class(JNIEnv* env, const char* name, jobject loader, const jbyte* buf, jsize len) {
    const void* ret = MEBET_RETURN_ADDRESS();
    if (g_platform.code_allowed && !g_platform.code_allowed(ret)) report_native_caller("DefineClass", name, ret);
    return g_orig_define_class(env, name, loader, buf, len);
}

jint JNICALL hook_register_natives(JNIEnv* env, jclass clazz, const JNINativeMethod* methods, jint n) {
    const void* ret = MEBET_RETURN_ADDRESS();
    if (g_platform.code_allowed && !g_platform.code_allowed(ret)) {
        std::string first = n > 0 && methods && methods[0].name ? methods[0].name : "";
        report_native_caller("RegisterNatives", first.c_str(), ret);
    }
    // A native method pointing outside allowed code would run foreign code from Java.
    if (g_platform.code_allowed && methods) {
        for (jint i = 0; i < n; ++i) {
            if (methods[i].fnPtr && !g_platform.code_allowed(methods[i].fnPtr)) {
                report::Event ev;
                ev.type = "close.foreign_code";
                ev.level = report::Level::error;
                ev.title = "Closed: native method bound to code outside allowed modules";
                char addr[32];
                std::snprintf(addr, sizeof(addr), "%p", methods[i].fnPtr);
                JsonWriter w;
                w.begin_object();
                w.field("method", truncate_utf8(methods[i].name ? methods[i].name : "", 256));
                w.field("address", addr);
                w.end_object();
                ev.extra_json = w.take();
                ev.fingerprint = {"close.foreign_code", "register_natives"};
                signal(config::Module::foreign_exec_memory, config::Reason::foreign_code, "", std::move(ev));
                break;
            }
        }
    }
    return g_orig_register_natives(env, clazz, methods, n);
}

void install_jni_hooks(jvmtiEnv* jvmti) {
    jniNativeInterface* table = nullptr;
    if (jvmti->GetJNIFunctionTable(&table) != JVMTI_ERROR_NONE || !table) return;
    auto* copy = new JNINativeInterface_(*table);  // lives for the whole process
    g_orig_define_class = table->DefineClass;
    g_orig_register_natives = table->RegisterNatives;
    copy->DefineClass = &hook_define_class;
    copy->RegisterNatives = &hook_register_natives;
    jvmti->SetJNIFunctionTable(copy);
    jvmti->Deallocate(reinterpret_cast<unsigned char*>(table));
}

void JNICALL on_vm_init(jvmtiEnv* jvmti, JNIEnv*, jthread) {
    install_jni_hooks(jvmti);
    char* version = nullptr;
    if (jvmti->GetSystemProperty("java.vm.version", &version) == JVMTI_ERROR_NONE && version) {
        report::Reporter::instance().set_tag("jvm", version);
        jvmti->Deallocate(reinterpret_cast<unsigned char*>(version));
    }
    if (g_platform.on_vm_init) g_platform.on_vm_init();
}

void flush_class_report() {
    ClassLog& log = class_log();
    std::lock_guard<std::mutex> lk(log.mu);
    if (log.reported || log.origins.empty()) return;
    log.reported = true;
    report::Event ev;
    ev.type = "report.runtime_classes";
    ev.level = report::Level::info;
    ev.title = "Report: classes defined at runtime outside jars";
    JsonWriter w;
    w.begin_object();
    w.field("total", static_cast<std::uint64_t>(log.total));
    w.key("origins").begin_array();
    for (const auto& o : log.origins) w.begin_object().field("class", o.first).field("loader", o.second).end_object();
    w.end_array();
    w.end_object();
    ev.extra_json = w.take();
    ev.fingerprint = {"report.runtime_classes"};
    ev.dedupe_key = "report.runtime_classes";
    report::Reporter::instance().submit(std::move(ev));
}

void JNICALL on_vm_death(jvmtiEnv*, JNIEnv*) {
    flush_class_report();
    if (g_platform.on_vm_death) g_platform.on_vm_death();
}

void JNICALL on_thread_start(jvmtiEnv*, JNIEnv*, jthread) {
    if (!g_platform.current_thread_allowed || !config::enabled(config::Module::jvm_agents)) return;
    std::string detail;
    if (g_platform.current_thread_allowed(&detail)) return;
    report::Event ev;
    ev.type = "close.jvm_attach";
    ev.level = report::Level::error;
    ev.title = "Closed: foreign code attached to the JVM";
    ev.extra_json = detail.empty() ? std::string() : detail;
    ev.fingerprint = {"close.jvm_attach"};
    signal(config::Module::jvm_agents, config::Reason::jvm_attach, "", std::move(ev));
}

void JNICALL on_class_file_load(jvmtiEnv* jvmti, JNIEnv* jni, jclass redefined, jobject loader, const char* name,
                                jobject protection_domain, jint, const unsigned char*, jint*, unsigned char**) {
    if (redefined || !loader || protection_domain || t_in_hook) return;
    t_in_hook = true;
    ClassLog& log = class_log();
    {
        std::lock_guard<std::mutex> lk(log.mu);
        ++log.total;
        if (log.origins.size() < config::kLimit_list_items) {
            jclass loader_class = jni ? jni->GetObjectClass(loader) : nullptr;
            log.origins.emplace_back(truncate_utf8(name ? name : "", 256), class_signature(jvmti, loader_class));
            if (loader_class) jni->DeleteLocalRef(loader_class);
        }
    }
    t_in_hook = false;
}

}  // namespace

void set_platform(const Platform& p) { g_platform = p; }
bool started() { return g_started.load(); }

}  // namespace mebet::jvm

using namespace mebet;

// The wrapper adds -agentpath:<this library>; the JVM finds the already loaded library
// and calls this function (ТЗ §4 step 9).
extern "C" JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM* vm, char*, void*) {
    if (jvm::g_started.exchange(true)) return JNI_OK;  // loaded twice through an old -agentlib
    jvmtiEnv* jvmti = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&jvmti), JVMTI_VERSION_1_2) != JNI_OK || !jvmti) {
        std::fprintf(stderr, "[Mebet] JVMTI is not available\n");
        return JNI_ERR;  // fail closed: no JVM without the guard
    }
    jvm::g_jvmti = jvmti;
    jvmtiCapabilities caps{};
    caps.can_generate_all_class_hook_events = 1;
    jvmti->AddCapabilities(&caps);
    jvmtiEventCallbacks cb{};
    cb.VMInit = &jvm::on_vm_init;
    cb.VMDeath = &jvm::on_vm_death;
    cb.ThreadStart = &jvm::on_thread_start;
    cb.ClassFileLoadHook = &jvm::on_class_file_load;
    jvmti->SetEventCallbacks(&cb, static_cast<jint>(sizeof(cb)));
    jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_VM_INIT, nullptr);
    jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_VM_DEATH, nullptr);
    jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_THREAD_START, nullptr);
    if (config::enabled(config::Module::jvm_classes))
        jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_CLASS_FILE_LOAD_HOOK, nullptr);
    return JNI_OK;
}

// Dynamic loading of the guard into a running JVM is not a supported way to start it.
extern "C" JNIEXPORT jint JNICALL Agent_OnAttach(JavaVM*, char*, void*) { return JNI_ERR; }
