# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 PolitCubes
# Build and package one Windows guard variant. One call per build step so every instance is a
# separate, visible step in the single "windows" job.
param(
  [Parameter(Mandatory = $true)][ValidateSet('x64', 'Win32', 'ARM64')][string]$Platform,
  [Parameter(Mandatory = $true)][ValidateSet('release', 'test', 'devtest')][string]$Kind,
  [Parameter(Mandatory = $true)][string]$Dir  # x86-64-mustdie | x86-mustdie | arm64-mustdie
)
$ErrorActionPreference = 'Stop'
$b = "build/$Dir-$Kind"
# Quote the -D args: PowerShell does not expand $Kind in a bare token that starts with '-'.
cmake -S . -B $b -G "Visual Studio 17 2022" -A $Platform "-DMEBET_BUILD_KIND=$Kind" "-DMEBET_JAVA_HOME=$env:JAVA_HOME_21_X64"
if ($LASTEXITCODE) { throw "configure failed" }
cmake --build $b --config Release --parallel
if ($LASTEXITCODE) { throw "build failed" }

$out = "dist/$Kind/$Dir"
New-Item -ItemType Directory -Force $out, "dist/$Kind/symbols" | Out-Null
Copy-Item "$b/src/windows/Release/MebetGuard.exe", "$b/src/windows/Release/MebetGuard.dll" $out
Copy-Item "$b/src/windows/Release/*.pdb" "dist/$Kind/symbols"
Write-Host "built $Dir ($Kind):"
Get-FileHash "$out/*" -Algorithm SHA256 | Format-Table -AutoSize | Out-String -Width 200
