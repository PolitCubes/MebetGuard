# Подключение к лаунчеру

Страж встаёт на место `GravitGuard2.exe` через модуль `LauncherGuard_lmodule`: лаунчер
запускает обёртку с обычной командной строкой Java, обёртка запускает JVM сама.

## Что лаунчер передаёт обёртке

| Что | Откуда | Зачем |
|---|---|---|
| `JAVA_HOME` | `LauncherGuard_lmodule` (`systemEnv`) | папка Java клиента: обёртка грузит `bin\jli.dll` (Windows) или `lib/libjli.so`/`.dylib` по полному пути |
| командная строка Java | `ClientLauncherProcess` | разбирается средствами самого JDK (`JLI_CmdToArgs`), `@argfiles` выключены |
| `-Djava.library.path=` | `ClientLauncherProcess` | папка natives — для проверки прокси-DLL |
| `-Dmebet.errors=false` | настройки лаунчера (будущая галочка) | выключить канал «ошибки стража» |
| `-Dmebet.reports=false` | настройки лаунчера (будущая галочка) | выключить канал «отчёты стража» |
| `-Dmebet.title=…` | конфиг сервера (по желанию) | заголовок окна игры для сервера |
| `-Dmebet.icon=<путь .ico>` | конфиг сервера (по желанию) | значок окна игры; без него — значок exe |
| `-Dmebet.client=classic\|modern` | профиль (по желанию) | метка клиента в отчётах |

Все `-Dmebet.*` — обычные системные свойства JVM: если их не задать, ничего не ломается.
Свой `-agentpath:<агент>` обёртка добавляет сама, поэтому в конфиге модуля
`nativeAgent` пустой. Старый `-agentlib:…\GuardDLL` закроет клиент как чужой агент.

## Конфиг модуля

`LaunchServer/config/LauncherGuard/Config.json`:

```json
{
  "files": {
    "x86-64-mustdie": ["MebetGuard.exe", "MebetGuard.dll"],
    "x86-mustdie":    ["MebetGuard.exe", "MebetGuard.dll"],
    "arm64-mustdie":  ["MebetGuard.exe", "MebetGuard.dll"],
    "x86-64-linux":   ["MebetGuard", "libMebetGuard.so"],
    "arm64-linux":    ["MebetGuard", "libMebetGuard.so"],
    "x86-64-macosx":  ["MebetGuard", "libMebetGuard.dylib"],
    "arm64-macosx":   ["MebetGuard", "libMebetGuard.dylib"]
  },
  "exeFile": {
    "x86-64-mustdie": "MebetGuard.exe", "x86-mustdie": "MebetGuard.exe", "arm64-mustdie": "MebetGuard.exe",
    "x86-64-linux": "MebetGuard", "arm64-linux": "MebetGuard",
    "x86-64-macosx": "MebetGuard", "arm64-macosx": "MebetGuard"
  },
  "renameExeFile": true,
  "useClasspathProperty": true,
  "protectLauncher": false,
  "nativeAgent": {}
}
```

Файлы кладутся в `LaunchServer/launcher-pack/guard/<папка>/` из артефактов CI
(`mebet-<платформа>-release`). С `renameExeFile` exe называется `<projectName>.exe`
(`PolitCubes.exe`); агент обёртка ищет рядом по фиксированному имени.

## Коды выхода

Одна таблица — [`config/exit_codes.json`](../config/exit_codes.json); её читает окно
причины, и её же должен читать лаунчер, чтобы показать причину по коду выхода (ТЗ §16).
Коды 200–239: на Linux и macOS код выхода восьмибитный.

| Код | id | Причина |
|---|---|---|
| 200 | `internal_error` | Внутренняя ошибка стража |
| 201 | `agent_integrity` | Файлы стража повреждены |
| 202 | `java_not_found` | Java клиента не найдена |
| 203 | `dev_mode` | Windows в режиме разработчика |
| 204 | `virtual_machine` | Запуск в виртуальной машине |
| 205 | `wsl` | Запуск в WSL |
| 206 | `proxy_dll` | Посторонняя библиотека рядом с игрой |
| 207 | `extra_file` | Посторонний файл в папке стража |
| 208 | `foreign_agent_arg` | Изменённые параметры Java |
| 209 | `jvm_path` | Java загружена не из своей папки |
| 210 | `untrusted_module` | Неизвестная программа в игре |
| 211 | `denylisted_module` | Запрещённая программа в игре |
| 212 | `early_module` | Программа встроилась до стража |
| 213 | `foreign_thread` | Внедрённый код |
| 214 | `hidden_image` | Скрытый модуль |
| 215 | `foreign_code` | Посторонний код в памяти |
| 216 | `jvm_attach` | Подключение к Java игры |
| 217 | `jvm_agent_module` | Агент отладки в Java |
| 218 | `debugger` | Подключён отладчик |
| 219 | `hook_tampered` | Защита стража снята |
| 220 | `verify_timeout` | Проверка подписи не завершилась |
| 221 | `win7_no_sha2` | Нужно обновление Windows 7 |
| 222 | `catalog_unavailable` | Служба криптографии недоступна |
| 223 | `unknown_class` | Неизвестный класс в игре |
| 224 | `hardening_failed` | Не удалось включить защиту |
| 225 | `guard_stalled` | Страж остановлен (поток стража заморожен или убит) |
| 226 | `unsupported_path` | Путь, который Java не принимает: Windows — папка Java с символами вне кодовой страницы ANSI и без имени 8.3; macOS — `=` в пути к стражу |

## Правки лаунчера и профилей (ТЗ §16)

Страж закрывает свою часть сам; эти правки — на стороне лаунчера и профилей:

- `EnvHelper`: добавить `JAVA_TOOL_OPTIONS` и `JDK_JAVA_OPTIONS` (обёртка их и так чистит,
  но без стража — например, на неподдержанной архитектуре — они проходят).
- `LauncherGuard_lmodule`: перед распаковкой удалять из папки стража всё лишнее — иначе
  старые `GravitGuard2.exe` / `GuardDLL.dll` закроют клиент как посторонние файлы (207).
- Профили: `-XX:-EnableDynamicAgentLoading`; `-Dorg.lwjgl.opengl.libname` с полным путём к
  `opengl32.dll` из System32; `-Dsun.java2d.d3d=false`; токен ванильного главного класса
  в командной строке (`-DFabricMcEmu= net.minecraft.client.main.Main `) — для профиля
  NVIDIA, обёртка сама выставляет только `SHIM_MCCOMPAT`.
- Свой закреплённый `vulkan-1.dll` (≥ 1.3.234), иначе фильтры неявных слоёв не работают.
- LaunchServer: 32-битная Java 21 для Windows x86 и набор аргументов x86 без
  `-XX:+UseCompactObjectHeaders`.
- Лаунчер: показать причину закрытия по коду выхода, пока окно лаунчера открыто; экран
  первого запуска с политикой конфиденциальности и двумя галочками (ошибки / отчёты) —
  сначала макеты.
- Classic: предсобрать кэш `.fabric` вместе с миксинами и раздавать готовым.
- Незакрытый вопрос Launcher#47: на неподдержанной ОС/архитектуре модуль запускает клиент
  без стража.

## Тестовая сборка

`MEBET_BUILD_KIND=test` — для стенда: модули ВМ и WSL выключены; `devtest` — то же и без
проверки дев-режима (для CI). В обеих `MEBET_TEST_NO_UI=1` убирает окно причины. Такие сборки не
подписываются и игрокам не раздаются; CI выкладывает `devtest` (артефакты `bin-*-dev`), `test`
собирается вручную.

Окно причины закрытия в любой сборке ждёт игрока не дольше `close_window_max_ms` (60 с): потом
процесс завершается сам, с тем же кодом. Лаунчер получает код выхода в любом случае.
