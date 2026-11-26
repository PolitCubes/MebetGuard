// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
#pragma once

namespace mebet::hooks {

// Periodic (worker): canary round + entry bytes of every hooked function (the six of the ТЗ and
// the Ex variants this Windows has).
void self_check();

}  // namespace mebet::hooks
