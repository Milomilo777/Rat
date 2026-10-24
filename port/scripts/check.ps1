$ErrorActionPreference = "Stop"

Write-Host "Running checks for port..."

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location -Path "$scriptDir\.."

Write-Host "Checking formatting..."
cargo fmt --check

Write-Host "Checking clippy..."
cargo clippy --workspace --all-targets -- -D warnings

Write-Host "Running tests..."
cargo test --workspace

Write-Host "All checks passed."
