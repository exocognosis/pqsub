#!/usr/bin/env bash
# Privacy check for a rendered video before sharing.
#   scripts/demo-video/privacy_check.sh VIDEO.mp4 WORK_DIR
# Runs: (1) bright-panel scan on every frame, (2) OCR at 2 fps with macOS Vision and a
# grep for sensitive strings, (3) contact sheets at 1 fps for a visual pass.
# Reports exactly which checks ran; it is not a frame-by-frame visual review.
set -euo pipefail
VIDEO="$1" WORK="$2"
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$WORK/ocr" "$WORK/sheets"
fail=0

# (1) Bright panels: notifications and stray windows are light; the demo is dark.
# signalstats YHIGH = 90th-percentile luma per frame. Cards and captions stay well below.
ffmpeg -loglevel error -i "$VIDEO" -vf "signalstats,metadata=print:key=lavfi.signalstats.YHIGH:file=$WORK/yhigh.txt" -f null -
frames=$(grep -c 'YHIGH' "$WORK/yhigh.txt")
bright=$(awk -F= '/YHIGH/ && $2+0 > 120 {n++} END {print n+0}' "$WORK/yhigh.txt")
echo "[1] bright-panel scan: $frames frames, $bright with 90th-percentile luma > 120"
[ "$bright" -eq 0 ] || fail=1

# (2) OCR at 2 fps.
ffmpeg -loglevel error -i "$VIDEO" -vf fps=2 "$WORK/ocr/f%04d.png"
[ -x "$WORK/ocr-bin" ] || swiftc -O "$HERE/ocr.swift" -o "$WORK/ocr-bin"
"$WORK/ocr-bin" "$WORK"/ocr/f*.png > "$WORK/ocr.txt"
n_img=$(ls "$WORK"/ocr/f*.png | wc -l | tr -d ' ')
user=$(id -un); host=$(scutil --get LocalHostName 2>/dev/null || hostname -s); comp=$(scutil --get ComputerName 2>/dev/null || true)
hits=$(USER_="$user" HOST_="$host" COMP_="${comp:-}" python3 - "$WORK/ocr.txt" <<'PY'
import os, re, sys
pats = [re.escape(v) for v in (os.environ["USER_"], os.environ["HOST_"], os.environ["COMP_"]) if v]
pats += [r"/Users/", r"/home/", r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", r"passw(or)?d", r"token", r"secret",
         r"BEGIN [A-Z ]*KEY", r"api[_-]?key", r"Last login", r"notification",
         r"[\w.+-]+@[\w-]+\.(com|net|org|io)", r"github\.com/(?!exocognosis/pqsub)"]
rx = re.compile("|".join(pats), re.I)
allowed = re.compile(r"@(acme|evil)\.com", re.I)
for line in open(sys.argv[1]):
    if rx.search(line) and not (allowed.search(line) and not rx.search(allowed.sub("", line))):
        print(line.rstrip())
PY
)
echo "[2] OCR: $n_img frames at 2 fps, $(wc -l < "$WORK/ocr.txt" | tr -d ' ') text lines; pattern hits (excluding the demo's own acme.com/evil.com addresses):"
if [ -n "$hits" ]; then echo "$hits" | head -40; fail=1; else echo "    none"; fi

# (3) Contact sheets at 1 fps (5x4 tiles) for a visual pass.
ffmpeg -loglevel error -i "$VIDEO" -vf "fps=1,scale=384:-1,tile=5x4" "$WORK/sheets/sheet%02d.png"
echo "[3] contact sheets: $(ls "$WORK"/sheets/*.png | wc -l | tr -d ' ') in $WORK/sheets (1 frame per second) -- review them"
exit $fail
