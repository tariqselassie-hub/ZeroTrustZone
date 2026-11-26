<#
.SYNOPSIS
  ZeroTrustZone (ZTZ) Installer / Updater / Uninstaller for Windows.
.EXAMPLE
  .\scripts\install.ps1 -WithService
  .\scripts\install.ps1 -Update
  .\scripts\install.ps1 -Uninstall
#>
param(
    [switch]$Update,
    [switch]$Uninstall,
    [switch]$WithService,
    [switch]$StrictShield,
    [switch]$PurgeKeys
)

$ErrorActionPreference = "Stop"
$RepoDir = Split-Path -Parent $PSScriptRoot
$Python = if ($env:PYTHON_BIN) { $env:PYTHON_BIN } else { "python" }

if ($Uninstall) {
    $argsList = @("-m", "ztz", "uninstall")
    if ($PurgeKeys) { $argsList += @("--purge-keys", "--yes") }
    & $Python @argsList
    & $Python -m pip uninstall -y ztz
    exit $LASTEXITCODE
}

if ($Update) {
    & $Python -m ztz update
    exit $LASTEXITCODE
}

& $Python -m pip install -e $RepoDir
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$installArgs = @("-m", "ztz", "install")
if ($WithService) { $installArgs += "--with-service" }
if ($StrictShield) { $installArgs += "--strict-shield" }
& $Python @installArgs
exit $LASTEXITCODE
