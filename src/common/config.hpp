// Accessors for the build configuration generated from config/*.json.
#pragma once

#include "mebet_config.hpp"

namespace mebet::config {

inline constexpr Level level(Module m) { return kModules[static_cast<int>(m)].level; }
inline constexpr bool enabled(Module m) { return level(m) != Level::off; }
inline constexpr bool closes(Module m) { return level(m) == Level::close; }
inline constexpr const ModuleDef& module(Module m) { return kModules[static_cast<int>(m)]; }
inline constexpr const ReasonDef& reason(Reason r) { return kReasons[static_cast<int>(r)]; }

static_assert(static_cast<int>(Module::count_) == sizeof(kModules) / sizeof(kModules[0]), "module table mismatch");
static_assert(static_cast<int>(Reason::count_) == sizeof(kReasons) / sizeof(kReasons[0]), "reason table mismatch");

}  // namespace mebet::config
