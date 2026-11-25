# End-to-end layer tests

Каждый слой защиты стража проверяется одной и той же атакой **дважды**:

- **без гварда** — целевая JVM (`MebetTarget`) запускается обычным `java`. Атака **должна
  сработать**: её маркер появляется в выводе, приложение продолжает работать.
- **через гвард** — та же JVM запускается обёрткой (`MebetGuard.exe` / `MebetGuard`), ровно
  как настоящий клиент. Атака **должна быть заблокирована**: гвард закрывает процесс с кодом
  этого слоя (`config/exit_codes.json`) или молча нейтрализует атаку, а приложение живёт.

Слой засчитан, только если **и** без гварда атака воспроизвелась, **и** через гвард она больше
не проходит. Это и есть пруф «было уязвимо → стало закрыто» через наш исполняемый файл.

Один тест на каждый сценарий (pytest — видно каждый сценарий отдельно):

```
pytest tests/e2e -v --guard <MebetGuard> --java <JAVA_HOME> [--untrusted-native <lib>]
```

```
tests/e2e/test_layers.py::test_layer[env_hardening_jto]     PASSED
tests/e2e/test_layers.py::test_layer[jvm_agents_javaagent]  PASSED
tests/e2e/test_layers.py::test_layer[module_trust_load]     PASSED
```

Быстрая таблица без зависимостей (та же логика, одна строка на сценарий):

```
python tests/e2e/run.py --guard <MebetGuard> --java <JAVA_HOME> [--only id,id]
                        [--untrusted-native <lib>] [--work <dir>] [--json <out>]
```

Сценарии описаны в `harness.py` (`SCENARIOS`); добавить слой = добавить одну запись, тест на
него появляется сам. Оракул разделён на «без гварда сработало» и «через гвард заблокировано»,
поэтому упавший тест прямо говорит, какая половина сломалась.

Раннер сам собирает цель (`target/MebetTarget.java`), агент-маркер (`attacks/MebetMarkerAgent.java`
→ `mebet-marker.jar`) и неподписанный натив (`attacks/native/mebet_fake_cheat.c`, компилятором
`clang`/`cl`/`gcc`; если его нет — сценарии с нативом пропускаются или натив передаётся через
`--untrusted-native`). Выход ненулевой, если хоть один слой не прошёл.

## В GitHub Actions

Один workflow `.github/workflows/ci.yml`, четыре стадии:

```
1. сборка   Matrix: build-windows-binaries   windows x64 prod · x64 dev · x86 prod · x86 dev · arm64 prod · arm64 dev
            Matrix: build-linux-binaries     linux x64 prod · x64 dev · arm64 prod · arm64 dev
            Matrix: build-macos-binaries     macos x64 prod · x64 dev · arm64 prod · arm64 dev
2. e2e      (каждая — после сборки своей ОС)
            Matrix: e2e-windows   env_hardening_jto · env_hardening_jdk · jvm_agents_javaagent ·
                                  jvm_agents_agentpath · module_trust_load · dev_mode
            Matrix: e2e-linux     env_hardening_jto · env_hardening_jdk · jvm_agents_javaagent · jvm_agents_agentpath
            Matrix: e2e-macos     то же, что linux
3. ci-ok    зависит только от трёх e2e; красный, если любая упала, отменена или пропущена
            (пропущена = упала её сборка) — его требует правило ветки master
4. sign     только на тегах v* (на pull request всегда skipped)
```

Каждая сборка — отдельный джоб матрицы со своей галочкой и своим артефактом
`bin-<os>-<arch>-<variant>`; в саммари прогона у каждой раскрывающийся блок: чем и как собрано,
файлы, размеры, sha256. **prod** = `release` (все модули включены), **dev** = `devtest`
(выключены модули `virtual_machine`, `linux_wsl` и `dev_mode` — гвард стартует на ВМ и на
dev-режимном раннере).

e2e на Windows идёт на **dev**-сборке, кроме фичи `dev_mode`: она берёт **prod**-сборку и проверяет,
что та закрывается кодом **203** — раннеры GitHub грузятся с test-signing. Java для Windows-e2e —
Liberica (BellSoft): гвард доверяет издателю Java игры, DLL другой Java закрыл бы как недоверенные.

Что тесты не фейковые: подставь вместо гварда обычную `java` — все такие тесты падают (атака
проходит, защиты нет). Проверено.

## Виды сборки

`MEBET_BUILD_KIND` (через `config/modules.json`) даёт три вида:

- **release** — все модули включены, `virtual_machine`/`linux_wsl`/`dev_mode` на «закрыть».
  Подписываемый клиентский билд.
- **test** — `virtual_machine` и `linux_wsl` выключены (можно гонять в ВМ/контейнере на стенде и
  в e2e); `dev_mode` остаётся на «закрыть». Неподписанная.
- **devtest** — то же, что `test`, плюс выключен модуль `dev_mode` (для прогона Windows-слоёв на
  dev-режимных раннерах GitHub). Неподписанная, игрокам не раздаётся.

`dev_mode` залочен на «закрыть» в `release` и `test`; выключить его может только `devtest` —
это проверяет генератор. e2e для слоёв `virtual_machine`/`linux_wsl` идёт на **release**-сборке
в настоящей ВМ (204) и в WSL2 (205).

## Покрытие слоёв

Статус: ✅ реализовано и проверено вживую · 🟡 в работе · ⬜ запланировано.

| Слой (модуль) | Атака | Гвард должен | Код | Статус |
|---|---|---|---|---|
| `env_hardening` | чужой агент через `JAVA_TOOL_OPTIONS` | нейтрализовать (очистить env) | — | ✅ |
| `jvm_agents` | чужой `-javaagent` в строке | закрыть | 208 | ✅ |
| `module_trust` | `System.load` неподписанного натива | закрыть | 210 | ✅ |
| `jvm_agents` | `-agentpath` чужой нативный агент | закрыть | 208 | ✅ |
| `env_hardening` | чужой агент через `JDK_JAVA_OPTIONS` | нейтрализовать | — | ✅ |
| `jvm_agents` | агент-модуль JDK (`instrument.dll` и т.п.) | закрыть | 217 | ⬜ |
| `jvm_agents` | внешний attach к JVM | закрыть | 216 | ⬜ |
| `proxy_dll` | прокси-DLL рядом с exe | закрыть | 206 | ⬜ (Windows) |
| `proxy_dll` | лишний файл рядом с exe | закрыть | 207 | ⬜ (Windows) |
| `startup_self_check` | подмена jvm.dll/java.dll вне Java | закрыть | 209 | ⬜ (Windows) |
| `startup_self_check` | подмена агента (хэш не сходится) | закрыть | 201 | ⬜ |
| `foreign_threads` | `CreateRemoteThread` в чужой код | закрыть | 213 | ⬜ (Windows, натив) |
| `hidden_images` | ручной маппинг образа | закрыть | 214 | ⬜ (Windows, натив) |
| `foreign_exec_memory` | RWX-память + выполнение (JNA/шелл-код) | закрыть | 215 | ⬜ (Windows, натив) |
| `hook_self_check` | снос хуков стража в ntdll | закрыть | 219 | ⬜ (Windows, натив) |
| `module_trust` | денилистнутый модуль | закрыть | 211 | ⬜ |
| `jvm_classes` | `DefineClass` в рантайме вне jar | отчёт (не закрывать) | 223 | ⬜ (нужен канал отчётов) |
| `virtual_machine` | запуск в ВМ | закрыть (release) | 204 | 🟡 (release в VirtualBox) |
| `linux_wsl` | Linux-клиент в WSL2 | закрыть (release) | 205 | ⬜ (release в WSL2) |
| `dev_mode` | дев-режим / test-signing Windows | закрыть (заблокировано) | 203 | 🟡 (на GitHub-раннере он включён) |
| `debugger` | юзермод-отладчик | закрыть | 218 | ⬜ |
| `input_source` | синтетический ввод `SendInput` | отбросить + отчёт | — | ⬜ (Windows) |
| `process_dacl` | внешний `OpenProcess`/`CreateRemoteThread` | DACL не пускает | — | ⬜ (Windows) |
| `extension_point_disable` | не-MS AppInit_DLLs | не загрузить | — | ⬜ (Windows) |
| `posix_preload` | `LD_PRELOAD` чужой библиотеки | отчёт | — | ⬜ (Linux) |
| `wine` | запуск под Wine | отчёт | — | ⬜ |
| `kernel_state` / `driver_names` / `time_check` / `extension_points` | состояние среды | отчёт | — | ⬜ (нужен канал отчётов) |
| `jvm_launch` / `splash` / `window_identity` | порядок запуска, заставка, окно | работает как задумано | — | ⬜ (наблюдение) |

Слои уровня «отчёт» (`report`) не закрывают клиент — их e2e проверяет, что событие отправлено;
это требует тестового канала GlitchTip и будет добавлено вместе с ним.

### Модель угрозы: чит внутри процесса

Читы для Minecraft почти всегда внутрипроцессные — мод или jar внутри игровой JVM, а не
внешний инжектор. Поэтому слои памяти (`module_trust`, `foreign_exec_memory`, `foreign_threads`)
проверяются как поведение чит-мода **изнутри** целевой JVM: цель сама грузит чужой натив
(`System.load`), выделяет исполняемую память, стартует чужой поток — ровно то, что делает мод.
Так проверка не зависит от отдельного инструмента-инжектора.

`module_trust` и `jvm_agents` (`-agentpath`) используют одну неподписанную натив-заглушку
(`attacks/native/mebet_fake_cheat.c`, только маркер: экспортирует `JNI_OnLoad`, `Agent_OnLoad`,
`Agent_OnAttach`) — в контейнере её собирает `gcc`, в Windows-CI — MSVC в тестовый артефакт
(`dist/fixtures/mebet_fake_cheat.dll`); на стенде её выкачивают и передают через `--untrusted-native`.

Внешняя инъекция из другого процесса (`CreateRemoteThread` и т.п.) закрывается DACL процесса
(`process_dacl`): его e2e проверяет, что процесс стража нельзя открыть с правами на запись
памяти и создание потока, — отдельного инструмента-инжектора для этого не нужно.

## На всех системах

- **Windows x64/x86/arm64** — полный набор слоёв (гейт `NtCreateSection`, память, потоки, DACL).
- **Linux x64/arm64, macOS** — слои старта (чужой агент, окружение, WSL, LD_PRELOAD). In-process
  детект инъекции в память на Linux/macOS в страже пока не подключён, поэтому соответствующие
  слои там помечены как Windows-only, пока это не появится.

Контейнеры: Linux-слои гоняются в Docker (на **test**-сборке), Windows-слои — на раннере.
