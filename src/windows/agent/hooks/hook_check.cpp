// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Hook self-check (ТЗ §7 «Самопроверка хуков»): our hook removed or replaced → close;
// a foreign hook on top of ours (antivirus) → report.
#include "hooks/hook_check.hpp"

#include "config.hpp"
#include "core/guard.hpp"
#include "hooks/nt_hooks.hpp"
#include "json_writer.hpp"
#include "report/cards.hpp"

namespace mebet::hooks {

void self_check() {
    if (!config::enabled(config::Module::hook_self_check)) return;
    const unsigned hits = canary_round();
    EntryCheck checks[6];
    check_entries(checks);
    for (int i = 0; i < 6; ++i) {
        const bool reached = (hits & (1u << i)) != 0;
        if (reached && checks[i].bytes_same) continue;
        report::Event ev;
        JsonWriter w;
        w.begin_object();
        w.field("function", checks[i].name);
        w.field("expected_bytes", entry_bytes_hex(i, true));
        w.field("actual_bytes", entry_bytes_hex(i, false));
        w.key("jumps_to").raw(cards::address_json(checks[i].first_jump));
        w.end_object();
        ev.extra_json = w.take();
        const std::string target = cards::address_owner_key(checks[i].first_jump);
        if (!reached) {
            ev.type = "close.hook_tampered";
            ev.level = report::Level::error;
            ev.title = std::string("Closed: guard hook removed: ") + checks[i].name;
            ev.fingerprint = {"close.hook_tampered", checks[i].name, target};
            guard::signal(config::Module::hook_self_check, config::Reason::hook_tampered, std::wstring(), std::move(ev));
            return;
        }
        // Still reached, but another hook sits in front of ours.
        ev.type = "report.foreign_hook";
        ev.level = report::Level::warning;
        ev.title = std::string("Report: foreign hook on top of ") + checks[i].name;
        ev.fingerprint = {"report.foreign_hook", target};
        ev.dedupe_key = std::string("foreign_hook|") + checks[i].name + "|" + target;
        guard::defer_event(std::move(ev));
    }
}

}  // namespace mebet::hooks
