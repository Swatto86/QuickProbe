<#
.SYNOPSIS
    Build and launch the standalone QuickProbe Console executable.
.DESCRIPTION
    Builds quickprobe-console with Cargo, then starts the compiled exe.
    Defaults to a release build. Use -DebugBuild for a faster debug build.
.EXAMPLE
    .\build-console.ps1
.EXAMPLE
    .\build-console.ps1 -DebugBuild
#>

[CmdletBinding()]
param(
    [switch]$DebugBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = $PSScriptRoot
$manifestPath = Join-Path $repoRoot 'quickprobe-console\Cargo.toml'

if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "Could not find quickprobe-console\Cargo.toml from $repoRoot"
}

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "Cargo was not found on PATH. Install Rust or open a shell where cargo is available."
}

$profileName = if ($DebugBuild) { 'debug' } else { 'release' }
$cargoArgs = @('build', '--manifest-path', $manifestPath)
if (-not $DebugBuild) {
    $cargoArgs += '--release'
}

Write-Host "Building QuickProbe Console ($profileName)..." -ForegroundColor Cyan
& cargo @cargoArgs
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

$exePath = Join-Path $repoRoot "quickprobe-console\target\$profileName\quickprobe-console.exe"
if (-not (Test-Path -LiteralPath $exePath)) {
    throw "Build completed, but the console exe was not found: $exePath"
}

Write-Host "Opening $exePath" -ForegroundColor Green
Start-Process -FilePath $exePath -WorkingDirectory (Split-Path -Parent $exePath)
