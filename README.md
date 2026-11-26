<p align="center"><img src="assets/logo.svg" alt="Mebet Anticheat" width="260"></p>

# Mebet Anticheat (MebetGuard)

Нативный страж клиента PolitCubes. Заменяет GravitGuard: **один exe-обёртка** запускает
JVM вместо `javaw.exe`, **одна библиотека-агент** работает внутри процесса игры. Всё в
одном процессе. Код — наш, открытый, под GNU AGPL-3.0-only.

| Платформа | Файлы | Папка в лаунчере (`LauncherGuard`) |
|---|---|---|
| Windows x64 | `MebetGuard.exe` + `MebetGuard.dll` | `x86-64-mustdie` |
| Windows x86 | `MebetGuard.exe` + `MebetGuard.dll` | `x86-mustdie` |
| Windows ARM64 | `MebetGuard.exe` + `MebetGuard.dll` | `arm64-mustdie` |
| Linux x64 / ARM64 | `MebetGuard` + `libMebetGuard.so` | `x86-64-linux` / `arm64-linux` |
| macOS x64 / ARM64 | `MebetGuard` + `libMebetGuard.dylib` | `x86-64-macosx` / `arm64-macosx` |

Сборки — во вкладке Actions: артефакты `bin-<os>-<arch>-prod` (release) и `-dev` (devtest, только для
тестов); у macOS отдельная сборка на каждую архитектуру, не universal. Подписанных релизов пока нет: условие
первого релиза — собранный список разрешённого и закрытый чеклист `[скан]` (см. ниже).

## Что проверяет страж

Главный принцип: **неизвестное — закрыть клиент и отправить отчёт**. Разрешённое
собирается заранее и вшивается в сборку (`config/`); с диска во время игры ничего не
читается, сервера решений нет.

**До запуска игры (Windows)**
- закалка окружения: чистятся `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, `_JAVA_OPTIONS`,
  `JAVA_OPTIONS`, `JAVA_OPTS`, `_JAVA_OPTS`, `CLASSPATH` и переменные загрузчика Vulkan,
  безопасный порядок поиска DLL, отключены точки расширения (AppInit_DLLs, глобальные хуки);
- exe импортирует только `kernel32`; агент проверяется по вшитому хэшу перед загрузкой;
- дев-режим Windows (тестовая подпись, режим отладки, выключенная проверка кода, отладка
  ядра) — закрыть всегда, в любой сборке;
- виртуальная машина — закрыть (CPUID / `SystemHypervisorDetailInformation` на ARM64,
  SMBIOS, драйверы гостя); хост с изоляцией ядра, WSL2 и Docker пропускается;
- посторонние файлы рядом с exe, DLL с системными именами рядом с exe, в папке Java и
  natives, чужие `-agentpath` / `-agentlib` / `-javaagent` / `-Xrun` — закрыть;
- всё, что попало в процесс раньше агента: модули, исполняемая память, потоки.

**Во время игры (Windows)**
- каждая DLL проверяется один раз, в момент загрузки, в потоке, который её грузит
  (хук `NtCreateSection`): компонент Windows, наша Java (BellSoft), натив игры по SHA-256,
  доверенный издатель (CN + O + класс корня), WHQL-драйвер видеокарты — иначе отказ в
  загрузке и закрытие;
- исполняемая память вне образов (ручной маппинг, шелл-код): учёт выделений и обход регионов;
- потоки, стартующие вне разрешённого кода; образы, отображённые мимо загрузчика;
- внешнее подключение к JVM (JVMTI `ThreadStart`), агенты `instrument`/`jdwp`/`attach`;
- отладчик, снятие хуков стража;
- DACL процесса и потоков: чужие программы пользователя не читают память игры и не
  создают в ней потоки; Диспетчер задач и OBS (захват игры) работают;
- инжектированный ввод (`SendInput`, автокликеры) отбрасывается и считается.

**Linux / macOS** (базовый уровень, ТЗ §11): своя обёртка с `JLI_Launch` и своим
`-agentpath`, `PR_SET_DUMPABLE 0` / `PT_DENY_ATTACH`, хэш своих файлов, Linux-клиент в
WSL2 — закрыть; `LD_PRELOAD` и посторонние библиотеки — только отчёт.

Полная карта модулей и уровней — [`config/modules.json`](config/modules.json),
причины и коды выхода — [`config/exit_codes.json`](config/exit_codes.json).

## Что страж отправляет

Два анонимных канала в GlitchTip, оба включены по умолчанию и выключаются отдельно
(лаунчер передаёт `-Dmebet.errors=false` / `-Dmebet.reports=false`). Решения стража от
этих переключателей не зависят.

- **Ошибки стража** — сбои самого стража.
- **Отчёты стража** — причина закрытия и «карточка» файла (имя, обезличенный путь,
  размер, SHA-256, VERSIONINFO, подписи), инвентарь сторонних модулей. Нужны, чтобы
  доводить список разрешённого и денилист.

Не отправляются: ник, аккаунт, UUID игрока, имя компьютера и пользователя, MAC, HWID,
серийники SMBIOS, заголовки окон, список процессов, содержимое файлов (только хэши).
Пути обезличены (`%USERPROFILE%`, `%APPDATA%`, `%GAME%`, `%JAVA%` …). На диск страж
ничего не пишет. Подробно — [`docs/reports.md`](docs/reports.md).

## Подключение к лаунчеру

`LaunchServer/config/LauncherGuard/Config.json` (модуль `LauncherGuard_lmodule`):

```json
{
  "files": {
    "x86-64-mustdie": ["MebetGuard.exe", "MebetGuard.dll"],
    "x86-mustdie":    ["MebetGuard.exe", "MebetGuard.dll"],
    "arm64-mustdie":  ["MebetGuard.exe", "MebetGuard.dll"],
    "x86-64-linux":   ["MebetGuard", "libMebetGuard.so"],
    "arm64-linux":    ["MebetGuard", "libMebetGuard.so"]
  },
  "exeFile": {
    "x86-64-mustdie": "MebetGuard.exe", "x86-mustdie": "MebetGuard.exe", "arm64-mustdie": "MebetGuard.exe",
    "x86-64-linux": "MebetGuard", "arm64-linux": "MebetGuard"
  },
  "renameExeFile": true,
  "useClasspathProperty": true,
  "protectLauncher": false,
  "nativeAgent": {}
}
```

`nativeAgent` пустой: свой `-agentpath` добавляет сама обёртка (ТЗ §4). Остальное —
[`docs/launcher-integration.md`](docs/launcher-integration.md).

## Сборка

Нужны CMake ≥ 3.18, Python 3 и JDK (для `jni.h` / `jvmti.h`).

```sh
# Windows (Visual Studio 2022): -A x64 | Win32 | ARM64
cmake -S . -B build -A x64 -DMEBET_JAVA_HOME="C:/path/to/jdk"
cmake --build build --config Release

# Linux / macOS
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DMEBET_JAVA_HOME=/path/to/jdk
cmake --build build
```

`-DMEBET_BUILD_KIND=test` — тестовая сборка для стенда (например, без модуля ВМ). Такие
сборки не подписываются и игрокам не раздаются; дев-режим Windows проверяется в любой.

Списки разрешённого правятся только в `config/` и требуют пересборки и переподписи:
`publishers.json` — доверенные издатели, `roots.json` + `roots/` — закреплённые корни,
`denylist.json` — денилист, `hashes/*.txt` — нативы игры (`tools/snap_hashes.py`).

## Code signing policy

Цель — бесплатная подпись SignPath Foundation: «Free code signing provided by
[SignPath.io](https://signpath.io), certificate by
[SignPath Foundation](https://signpath.org)». Подписываются только `MebetGuard.exe` и
`MebetGuard.dll`, собранные в CI из тега этого репозитория. Каждый релиз одобряется
вручную.

- Авторы и ревьюеры: команда [mebet](https://github.com/orgs/PolitCubes/teams/mebet).
  Изменения от остальных попадают в `master` только через pull request с одобрением команды.
- Одобряющие подпись: команда [mebet](https://github.com/orgs/PolitCubes/teams/mebet).
- Политика конфиденциальности: что страж отправляет и как это выключить —
  [`docs/reports.md`](docs/reports.md); отдельная страница на сайте — до первого подписанного релиза.

## Лицензия

GNU Affero General Public License v3.0 only (`AGPL-3.0-only`) — [`LICENSE`](LICENSE).
Кто распространяет страж, в том числе изменённый, обязан дать получателям его исходный код
под той же лицензией; исходники каждой сборки — этот репозиторий. Сторонний код и данные —
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
