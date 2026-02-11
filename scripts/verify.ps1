<#
.SYNOPSIS
    QuickProbe verification script — single source of truth for "repo is healthy".
.DESCRIPTION
    Runs format check, lint, tests, and build in order. Stops immediately on any failure.
    Exit code 0 = all checks passed. Non-zero = failure.
.EXAMPLE
    pwsh -File scripts/verify.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Section([string]$Title) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
}

function Invoke-Step([string]$Label, [scriptblock]$Action) {
    Write-Host ">> $Label" -ForegroundColor Yellow
    try {
        & $Action
        if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
            Write-Host "FAILED: $Label (exit code $LASTEXITCODE)" -ForegroundColor Red
            exit $LASTEXITCODE
        }
    }
    catch {
        Write-Host "FAILED: $Label" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        exit 1
    }
    Write-Host "PASSED: $Label" -ForegroundColor Green
    Write-Host ""
}

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (Test-Path (Join-Path $PSScriptRoot '..' 'src-tauri')) {
    $repoRoot = Split-Path -Parent $PSScriptRoot
}
Push-Location $repoRoot

try {
    # ── 1. Format Check ──────────────────────────────────────────────
    Write-Section "1/4 — Format Check"
    Invoke-Step "cargo fmt --check" {
        cargo fmt --check --manifest-path src-tauri/Cargo.toml
    }

    # ── 2. Lint / Static Analysis ─────────────────────────────────────
    Write-Section "2/4 — Lint (Clippy)"
    Invoke-Step "cargo clippy --lib -D warnings" {
        cargo clippy --lib --manifest-path src-tauri/Cargo.toml -- -D warnings
    }

    # ── 3. Tests ──────────────────────────────────────────────────────
    Write-Section "3/4 — Tests"
    Invoke-Step "cargo test --lib" {
        cargo test --lib --manifest-path src-tauri/Cargo.toml
    }

    # ── 4. Build (release) ────────────────────────────────────────────
    Write-Section "4/4 — Build (library, release mode)"
    Invoke-Step "cargo build --lib --release" {
        cargo build --lib --release --manifest-path src-tauri/Cargo.toml
    }

    # ── Summary ───────────────────────────────────────────────────────
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  ALL CHECKS PASSED" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    exit 0
}
finally {
    Pop-Location
}
