#!/bin/bash

set -e

echo "================================="
echo " AegisForge Full Development Check"
echo "================================="
echo

echo "[1/8] Checking formatting..."
cargo fmt --check

echo
echo "[2/8] Running cargo check..."
cargo check

echo
echo "[3/8] Running Rust tests..."
cargo test

echo
echo "[4/8] Building AegisForge..."
cargo build

echo
echo "[5/8] Testing help..."
./target/debug/af --help

echo
echo "[6/8] Testing version..."
./target/debug/af --version

echo
echo "[7/8] Testing valid scans..."

./target/debug/af scan Cargo.toml
./target/debug/af scan src

echo
echo "[8/8] Testing invalid path..."

set +e
./target/debug/af scan fake-path
EXIT_CODE=$?
set -e

if [ "$EXIT_CODE" -ne 1 ]; then
    echo "FAILED: expected exit code 1, got $EXIT_CODE"
    exit 1
fi

echo
echo "================================="
echo " ALL AEGISFORGE CHECKS PASSED"
echo "================================="