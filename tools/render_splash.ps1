param(
  [string]$Root = (Split-Path -Parent $PSScriptRoot),
  [int]$Width = 300
)
# Renders assets/logo.svg to assets/splash/logo@100.png, @150, @200 with a transparent
# background, through headless Edge (or Chrome). Run after logo.svg or the splash size
# changes; the build turns the PNGs into premultiplied BGRA resources (tools/png_to_bgra.py).
# The width at 100 % is provisional until the splash mockup is chosen (ТЗ §4).
$ErrorActionPreference = 'Stop'
$edge = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
if (-not (Test-Path $edge)) { $edge = 'C:\Program Files\Microsoft\Edge\Application\msedge.exe' }
if (-not (Test-Path $edge)) { $edge = 'C:\Program Files\Google\Chrome\Application\chrome.exe' }
if (-not (Test-Path $edge)) { throw 'Edge or Chrome not found' }

$assets = Join-Path $Root 'assets'
$out = Join-Path $assets 'splash'
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('mebet-splash-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force $out, $tmp | Out-Null
$svg = Get-Content -Raw (Join-Path $assets 'logo.svg')
$m = [regex]::Match($svg, 'viewBox="0 0 ([0-9.]+) ([0-9.]+)"')
if (-not $m.Success) { throw 'logo.svg has no viewBox' }
$ratio = [double]$m.Groups[2].Value / [double]$m.Groups[1].Value

foreach ($scale in 100, 150, 200) {
  $w = [int][math]::Round($Width * $scale / 100)
  $h = [int][math]::Round($w * $ratio)
  $page = Join-Path $tmp ("splash$scale.html")
  $logo = (Join-Path $assets 'logo.svg') -replace '\\', '/'
  $html = '<!doctype html><html><head><meta charset="utf-8"><style>html,body{margin:0;background:transparent;overflow:hidden}' +
          'img{display:block;width:' + $w + 'px;height:' + $h + 'px}</style></head><body><img src="file:///' + $logo + '"></body></html>'
  [IO.File]::WriteAllText($page, $html, (New-Object Text.UTF8Encoding($false)))
  $png = Join-Path $out ("logo@$scale.png")
  if (Test-Path $png) { Remove-Item $png -Confirm:$false }
  $args = @('--headless=new', '--disable-gpu', '--hide-scrollbars', '--no-first-run', '--force-device-scale-factor=1',
            "--window-size=$w,$h", '--virtual-time-budget=3000', '--default-background-color=00000000',
            ('--screenshot="' + $png + '"'), ('"file:///' + ($page -replace '\\', '/') + '"'))
  Start-Process -FilePath $edge -ArgumentList $args -Wait -WindowStyle Hidden | Out-Null
  if (-not (Test-Path $png)) { throw "no screenshot: $png" }
  Write-Output "$png ${w}x$h"
}
Remove-Item -Recurse -Force $tmp -Confirm:$false
