#!/usr/bin/env bash
# Rust line coverage for the workspace (needs: cargo install cargo-llvm-cov;
# rustup component add llvm-tools-preview). The loopback capture test runs
# only where this user may capture (calm_bpf group on a Mac); else it skips.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo llvm-cov --workspace --summary-only "$@"
