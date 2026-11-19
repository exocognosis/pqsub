#!/usr/bin/env bash
# One-command pqsub demo: delegate, attack, gate, then audit with the independent verifier.
#
#   ./examples/demo-banking.sh [OUT_DIR]
#   PQSUB_PACE=1 ./examples/demo-banking.sh   # paced output, for reading along or a manual recording
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${1:-demo-banking-out}"
PACE="${PQSUB_PACE:-0}"

cargo build --release --locked --quiet
cargo build --release --locked --quiet --example banking_demo -p pqsub-cli

# When pacing, reveal output line by line; section headers wait for the narration to change.
pace() {
  if [ "$PACE" = "0" ]; then cat; return; fi
  while IFS= read -r line; do
    case "$line" in
      "== 1."*) sleep 0.5 ;;
      "== 2."*) sleep 7.5 ;;
      "== 3."*) sleep 8.5 ;;
      "== 4."*) sleep 5.0 ;;
      "") ;;
      wrote*) sleep 3.0 ;;
      *) sleep 1.8 ;;
    esac
    printf '%s\n' "$line"
  done
}

# pipefail keeps the verifier's exit status (2 if an executed call was unauthorized).
{
  ./target/release/examples/banking_demo "$OUT"
  echo
  echo "== 4. Anyone with root.pub audits the transcript offline (independent verifier) =="
  ./target/release/pqsub-verify audit --root "$OUT/root.pub" "$OUT/transcript.pqst" --require-authorized
} | pace
