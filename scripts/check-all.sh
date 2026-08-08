#!/bin/bash

set -e

echo "================================="
echo " AegisForge Full Development Check"
echo "================================="
echo

echo "[1/9] Checking formatting..."
cargo fmt --check

echo
echo "[2/9] Running cargo check..."
cargo check

echo
echo "[3/9] Running Rust tests..."
cargo test

echo
echo "[4/9] Building AegisForge..."
cargo build

echo
echo "[5/9] Testing help..."
./target/debug/af --help

echo
echo "[6/9] Testing version..."
./target/debug/af --version

echo
echo "[7/9] Testing valid scans..."
./target/debug/af scan Cargo.toml
./target/debug/af scan src

echo
echo "[8/9] Testing artifact metadata..."
./target/debug/af scan Cargo.toml

echo
echo "[9/9] Testing invalid path..."

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