# Архитектура

Физически: один exe (обёртка), одна библиотека (агент), один процесс. «Модуль» — блок
кода со своей зоной ответственности и своим уровнем в [`config/modules.json`](../config/modules.json).

## Порядок запуска (Windows)

| Шаг | Где | Что |
|---|---|---|
| 1 | `src/windows/exe/main.cpp`, `src/windows/shared/hardening.cpp` | порядок поиска DLL, отключение точек расширения, очистка окружения — до загрузки любой DLL; exe импортирует только `kernel32`, `user32` — отложенно |
| 2 | `exe/main.cpp`, `shared/pe_hash.cpp` | агент проверяется по вшитому хэшу (не меняется от подписи) и грузится по полному пути через тот же открытый дескриптор |
| 3 | `agent/entry.cpp` → `window/splash.cpp` | заставка в своём потоке |
| 4 | `trust/signatures.cpp`, `trust/engine.cpp` | прогрев wintrust/crypt32 до хуков, движок доверия |
| 5 | `hooks/nt_hooks.cpp` | шесть хуков ntdll одной транзакцией Detours |
| 6 | `system/environment.cpp` | дев-режим (всегда), ВМ |
| 7 | `scan/scans.cpp` (`startup_check`) | всё, что загрузилось раньше агента: модули, исполняемая память, потоки |
| 8 | `launch/launch.cpp` | `jli.dll` через шлюз, `JLI_InitArgProcessing(false, true)`, `JLI_CmdToArgs`, проверка файлов и аргументов |
| 9 | `process/dacl.cpp`, `core/guard.cpp` | DACL процесса и потоков, рабочий поток |
| 10 | `launch/launch.cpp` (`run_jvm`) | `JLI_Launch` со своим `-agentpath` |
| 11 | `src/common/jvm_guard.cpp` | `Agent_OnLoad`: JVMTI `ThreadStart`, `VMInit` (таблица JNI), `ClassFileLoadHook`, `VMDeath` |

## Модули → код

| Модуль (`modules.json`) | Код |
|---|---|
| `env_hardening`, `extension_point_disable` | `shared/hardening.cpp` |
| `jvm_launch` | `launch/launch.cpp` |
| `startup_self_check` | `scan/scans.cpp` (`startup_check`), `entry.cpp` (`check_jvm_library`) |
| `proxy_dll` | `launch/launch.cpp` (`check_files`) |
| `module_trust` | `hooks/load_gate.cpp` (решение в потоке загрузки), `trust/*` (правила) |
| `foreign_threads` | `scan/scans.cpp` (`on_thread_attach`, `thread_sweep`) |
| `hidden_images` | `scan/scans.cpp` (`memory_sweep`) |
| `foreign_exec_memory` | `hooks/exec_guard.cpp` (учёт), `scan/scans.cpp` (обход) |
| `jvm_agents`, `jvm_classes` | `src/common/jvm_guard.cpp`, `hooks/load_gate.cpp` (`instrument`/`jdwp`/`attach`) |
| `hook_self_check` | `hooks/hook_check.cpp` (канарейка + байты входа) |
| `virtual_machine`, `dev_mode`, `kernel_state`, `driver_names`, `wine`, `debugger`, `time_check`, `extension_points` | `system/environment.cpp` |
| `input_source`, `window_identity` | `window/game_window.cpp` |
| `process_dacl` | `process/dacl.cpp` |
| `splash` | `window/splash.cpp` |
| `linux_wsl`, `posix_preload` | `src/posix/agent/entry.cpp` |

## Горячий путь

У каждого хука быстрый путь — одна проверка, без стека, блокировок и выделения памяти:
`NtCreateSection` — не `SEC_IMAGE`; `NtAllocateVirtualMemory` / `NtProtectVirtualMemory` —
не запрошено исполнение; `NtFreeVirtualMemory` / `NtUnmapViewOfSection` — адреса нет в
таблицах (поиск без блокировок, `core/range_set.hpp`). Медленный путь (загрузка модуля,
исполняемая память) берёт до нескольких кадров стека над системными DLL. Все выделения
агента идут в собственную кучу (`core/private_heap.cpp`), чтобы хук на выделении памяти
не трогал кучу процесса, которую держит вызывающий.

## Закрытие

Хук никогда не завершает процесс: он отказывает и вызывает `guard::request_close`.
Рабочий поток прячет окна игры, показывает окно причины, отправляет отчёт и завершает
процесс кодом причины (`core/guard.cpp`). До запуска JVM то же делает главный поток.

## Списки

Всё разрешённое — в `config/` и вшивается генератором `tools/gen_config.py`:
`publishers.json` (CN + O + класс корня), `roots.json` + `roots/*.pem`, `denylist.json`,
`hashes/*.txt` (нативы по SHA-256, `tools/snap_hashes.py`). Правило Microsoft и правило
WHQL-драйвера видеокарты — в коде (`trust/engine.cpp`).
