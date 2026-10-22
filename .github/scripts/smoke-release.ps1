# Runs a built release archive the way a user would: unpack, `ppm init`, then `ppm run` on a
# console application, and requires that the application ran injected.
param(
    [Parameter(Mandatory)] [string] $Archive,
    [Parameter(Mandatory)] [ValidateSet("x64", "arm64")] [string] $Arch,
    [Parameter(Mandatory)] [string] $Tag
)

$ErrorActionPreference = "Stop"

$root = Join-Path $env:RUNNER_TEMP "ppm-smoke-$Arch"
if (Test-Path $root) { Remove-Item $root -Recurse -Force }
Expand-Archive -Path $Archive -DestinationPath $root
$env:PPM_ROOT = $root
$ppm = Join-Path $root "ppm.exe"

# Why: the binary must report the version it is released as (v0.1.1 shipped reporting 0.1.0).
$reported = (& $ppm --version | Select-Object -Last 1).Trim()
if ($LASTEXITCODE -ne 0) { throw "ppm --version exited $LASTEXITCODE" }
if ($reported -ne "ppm $($Tag.TrimStart('v'))") { throw "ppm reports '$reported' but is released as $Tag" }

& $ppm init
if ($LASTEXITCODE -ne 0) { throw "ppm init exited $LASTEXITCODE" }

# Why hostname.exe: a console application every Windows image ships in its native architecture,
# with one line of known output and no window.
$appDir = Join-Path $root "Apps/$Arch/Hostname"
New-Item -ItemType Directory -Path $appDir -Force | Out-Null
Copy-Item (Join-Path $env:SystemRoot "System32/hostname.exe") $appDir
@'
{
  "apps": {
    "hostname": {
      "name": "Hostname",
      "target_dir": "Hostname",
      "executable": "hostname.exe",
      "version_check": { "type": "github_release", "repo": "owner/repo" },
      "package": { "type": "zip" }
    }
  }
}
'@ | Set-Content -Path (Join-Path $root ".ppm/apps.json") -Encoding utf8

$output = & $ppm run hostname
if ($LASTEXITCODE -ne 0) { throw "ppm run exited $LASTEXITCODE" }
if (($output | Select-Object -Last 1).Trim() -ne $env:COMPUTERNAME) {
    throw "ppm run printed '$output', expected the host name '$env:COMPUTERNAME'"
}

$attached = Get-ChildItem (Join-Path $root ".ppm/logs") -Filter "redirector*" |
    Select-String -Pattern "redirector.dll attached to process" -SimpleMatch
if (-not $attached) { throw "the application ran, but the engine log shows no injection" }

Write-Output "Release archive for ${Arch}: version $Tag, init, run and injection verified"
