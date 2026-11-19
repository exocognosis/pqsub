#!/usr/bin/env bash
# One-command pqsub demo: delegate, attack, gate, then audit with the independent verifier.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${1:-demo-banking-out}"

cargo build --release --locked --quiet
cargo run --release --locked --quiet --example banking_demo -p pqsub-cli -- "$OUT"

echo
echo "== 4. Anyone with root.pub audits the transcript offline (independent verifier) =="
./target/release/pqsub-verify audit --root "$OUT/root.pub" "$OUT/transcript.pqst" --require-authorized
