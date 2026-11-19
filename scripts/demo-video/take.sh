#!/usr/bin/env bash
# Director for the pqsub demo video. Never appears on camera.
#   scripts/demo-video/take.sh still  # one frame of the window content area, to check framing
#   scripts/demo-video/take.sh dry    # rehearsal: opens the window, runs the demo, no capture
#   scripts/demo-video/take.sh take   # one continuous take -> demo-takes/<stamp>/raw.mkv
# Hands off keyboard and mouse while the window is up. Use AC power and Do Not Disturb.
set -euo pipefail
MODE="${1:-dry}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
HERE="$REPO/scripts/demo-video"
ROOT="$REPO/demo-takes"
TAKE="$ROOT/$(date +%Y%m%d-%H%M%S)-$MODE"
STAGE="$ROOT/stage"
SCREEN="Capture screen 0"
# Window bounds in points (x1 y1 x2 y2): 1610 x 906 content area (16:9) below a 28 pt title bar.
BX1=50 BY1=60 BX2=1660 BY2=994 TITLE=28

now() { perl -MTime::HiRes=time -e 'printf "%.3f\n", time'; }
log() { echo "[take] $*"; }

# --- stage: fresh state, only what appears on camera ------------------------------
(cd "$REPO" && cargo build --release --locked --quiet \
  && cargo build --release --locked --quiet --example banking_demo -p pqsub-cli)
rm -rf "$STAGE"; mkdir -p "$STAGE" "$TAKE"
cp "$REPO/target/release/examples/banking_demo" "$REPO/target/release/pqsub-verify" "$STAGE/"
(cd "$REPO/target/release" && shasum -a 256 examples/banking_demo pqsub-verify) > "$TAKE/SHA256SUMS.build"
(cd "$STAGE" && shasum -a 256 banking_demo pqsub-verify) > "$TAKE/SHA256SUMS.stage"
diff <(awk '{print $1}' "$TAKE/SHA256SUMS.build") <(awk '{print $1}' "$TAKE/SHA256SUMS.stage") >/dev/null \
  || { log "staged binaries do not match the build"; exit 1; }
log "staged binaries verified (sha256)"

# --- window -------------------------------------------------------------------------
caffeinate -dimsu -w $$ &
OUT=$(osascript "$HERE/window.applescript" "$HERE/demo.sh" "$STAGE" "$TAKE" $BX1 $BY1 $BX2 $BY2)
WID="${OUT%%$'\t'*}" TTY="${OUT##*$'\t'}"
log "window id $WID tty $TTY"
touch "$TAKE/sized"
front_ok() {
  [ "$(osascript -e 'tell application "Terminal" to get frontmost')" = "true" ] &&
  [ "$(osascript -e 'tell application "Terminal" to get tty of selected tab of front window')" = "$TTY" ]
}
close_window() {
  # Let the demo shell finish (or stop it), then close; Terminal only asks when something still runs.
  local t="${TTY#/dev/}"
  pkill -INT -t "$t" sleep 2>/dev/null || true
  for _ in $(seq 40); do
    [ -z "$(ps -t "$t" -o comm= 2>/dev/null | grep -vE '^(login|-?bash)$')" ] && break; sleep 0.5
  done
  pkill -t "$t" bash 2>/dev/null || true
  for _ in $(seq 20); do [ -z "$(ps -t "$t" -o pid= 2>/dev/null)" ] && break; sleep 0.25; done
  osascript -e "tell application \"Terminal\" to close window id $WID" >/dev/null 2>&1 || true
}
for _ in $(seq 100); do [ -f "$TAKE/ready" ] && break; sleep 0.1; done
[ -f "$TAKE/ready" ] || { log "demo never became ready"; exit 1; }
front_ok || { log "demo window is not in front"; exit 1; }
log "terminal rows: $(cat "$TAKE/rows")"

SCALE=2
# Content area in pixels, inset to drop the 1-2 px window border, kept at exactly 16:9.
CW=$(((BX2 - BX1) * SCALE - 20)); CH=$((CW * 9 / 16))
printf '{"crop":[%d,%d,%d,%d],"scale":%d}\n' \
  $((BX1 * SCALE + 10)) $(((BY1 + TITLE) * SCALE + 6)) $CW $CH $SCALE > "$TAKE/geometry.json"

if [ "$MODE" = "still" ]; then
  # One frame of the demo window's content area (ready state, before any output) to check framing.
  read -r CX CY CW CH < <(python3 -c 'import json,sys;print(*json.load(open(sys.argv[1]))["crop"])' "$TAKE/geometry.json")
  ffmpeg -loglevel error -f avfoundation -capture_cursor 0 -framerate 30 -pixel_format nv12 -i "$SCREEN:none" \
    -frames:v 1 -vf "crop=$CW:$CH:$CX:$CY" "$TAKE/still.png"
  close_window
  log "still: $TAKE/still.png"
  exit 0
fi
if [ "$MODE" = "dry" ]; then
  touch "$TAKE/go"
  while ! grep -q '^end ' "$TAKE/marks" 2>/dev/null; do front_ok || log "WARNING: window lost focus"; sleep 0.5; done
  log "dry run complete: $(tr '\n' ' ' < "$TAKE/marks")"
  close_window
  exit 0
fi

# --- capture ------------------------------------------------------------------------
LAUNCH=$(now)
ffmpeg -loglevel error -f avfoundation -capture_cursor 0 -framerate 30 -pixel_format nv12 \
  -i "$SCREEN:none" -c:v libx264 -preset ultrafast -crf 16 -pix_fmt yuv420p "$TAKE/raw.mkv" &
FF=$!
echo "$LAUNCH" > "$TAKE/launch"
sleep 2
touch "$TAKE/go"
abort() {
  log "ABORT: $1"; kill -INT $FF 2>/dev/null || true; wait $FF 2>/dev/null || true
  rm -f "$TAKE/raw.mkv"; exit 1
}
while ! grep -q '^end ' "$TAKE/marks" 2>/dev/null; do
  kill -0 $FF 2>/dev/null || abort "ffmpeg exited early"
  front_ok || abort "demo window lost focus"
  sleep 0.5
done
sleep 1
kill -INT $FF; wait $FF || true
close_window
log "take complete: $TAKE/raw.mkv"
echo "$TAKE"
