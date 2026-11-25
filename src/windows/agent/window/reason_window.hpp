// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Window with the reason and the code of a close (ТЗ §3). The look and the texts are a
// draft: the final window comes after the animated mockups (ТЗ §3, «сначала макеты»).
#pragma once

#include <string>

namespace mebet::reason_window {

void show(const std::wstring& title, const std::wstring& text);

}  // namespace mebet::reason_window
