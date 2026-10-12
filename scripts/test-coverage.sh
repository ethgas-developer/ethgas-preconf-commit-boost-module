#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# Exclude only test implementation; every production source stays in the denominator.
cargo llvm-cov --all-targets --locked \
  --ignore-filename-regex '(^|/)tests/' \
  --fail-under-lines 95 --fail-under-regions 95 --fail-under-functions 95 \
  --json --output-path target/coverage.json "$@"
cargo llvm-cov report --ignore-filename-regex '(^|/)tests/' \
  --html --output-dir target/coverage
