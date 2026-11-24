# Third-party notices

Mebet Anticheat is our own code under the MIT license (see `LICENSE`). It uses or
derives from the following open-source work.

## Microsoft Detours — MIT

Used on Windows (x86, x64, ARM64) to install the six ntdll hooks of the agent.
Fetched at build time from https://github.com/microsoft/Detours at a pinned commit
(see `cmake/Detours.cmake`); only `detours.cpp`, `modules.cpp` and `disasm.cpp` are
compiled. Not modified.

```
Copyright (c) Microsoft Corporation.
MIT License
```

## GravitGuard — MIT

The Java start sequence in `src/windows/agent/launch/jli_launch.cpp` and
`src/posix/agent/jli_launch.cpp` follows the order of `GuardDLL/guard.cpp:run_java`
from GravitGuard 2 (load `jli.dll` by full path, `AddDllDirectory`, resolve the
`JLI_*` exports, `JLI_InitArgProcessing(JNI_FALSE, JNI_TRUE)`,
`JLI_CmdToArgs(GetCommandLineA())`, `JLI_GetStdArgs`, `JLI_Launch`). The code here is
written from scratch; no GravitGuard source file is copied.

```
MIT License

Copyright (c) 2021 GravitLauncher
```

## OpenJDK JNI / JVMTI headers — GPL-2.0 with Classpath Exception

`jni.h`, `jni_md.h` and `jvmti.h` are taken at build time from the JDK pointed to by
`JAVA_HOME`; they are not stored in this repository. The Classpath Exception allows
linking independent modules such as this agent.

## Root certificates

`config/roots/*.pem` are public root CA certificates exported from the Windows trusted
root store. They are public data, embedded so that chains can be built on Windows 7
without root updates.
