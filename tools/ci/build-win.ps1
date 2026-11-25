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

$arch = @{ 'x64' = 'x64'; 'Win32' = 'x86'; 'ARM64' = 'arm64' }[$Platform]
$variant = @{ 'release' = 'prod'; 'devtest' = 'dev' }[$Kind]
Write-Host "built windows $arch $variant:"
Get-FileHash "$out/*" -Algorithm SHA256 | Format-Table -AutoSize | Out-String -Width 200

# Collapsible entry on the run summary: what was built and its hashes.
if ($env:GITHUB_STEP_SUMMARY) {
    $rows = Get-ChildItem $out -File | ForEach-Object {
        $h = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.Substring(0, 16)
        "| ``$($_.Name)`` | $([math]::Round($_.Length / 1KB)) KB | ``$h…`` |"
    }
    $md = @("<details><summary>✅ <b>windows $arch $variant</b> — MSVC, Visual Studio 17 2022 -A $Platform, kind=$Kind</summary>",
            "", "| file | size | sha256 |", "|---|---|---|") + $rows + @("</details>", "")
    ($md -join "`n") | Add-Content -Path $env:GITHUB_STEP_SUMMARY -Encoding utf8
}
