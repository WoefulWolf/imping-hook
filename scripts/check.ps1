# Runs the checks from the definition of done: formatting, clippy, tests and docs.
# Usage, from the repo root: powershell -ExecutionPolicy Bypass -File scripts/check.ps1

$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)

# Targets we test on. i686-pc-windows-msvc joins this list when 32-bit support starts.
$targets = @('x86_64-pc-windows-msvc')

function Invoke-Step([string]$name, [scriptblock]$command) {
    Write-Host "==> $name" -ForegroundColor Cyan
    & $command
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED: $name" -ForegroundColor Red
        exit $LASTEXITCODE
    }
}

Invoke-Step 'cargo fmt --check' { cargo fmt --all --check }

foreach ($target in $targets) {
    Invoke-Step "clippy ($target)" { cargo clippy --all-targets --target $target -- -D warnings }
    Invoke-Step "test ($target)" { cargo test --target $target }
}

$env:RUSTDOCFLAGS = '-D warnings'
Invoke-Step 'cargo doc' { cargo doc --no-deps }

Write-Host 'All checks passed.' -ForegroundColor Green
