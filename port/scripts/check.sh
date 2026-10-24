#!/bin/bash
set -e

echo "Running checks for port..."

cd "$(dirname "$0")/.."

echo "Checking formatting..."
cargo fmt --check

echo "Checking clippy..."
cargo clippy --workspace --all-targets -- -D warnings

echo "Running tests..."
cargo test --workspace

echo "All checks passed."
