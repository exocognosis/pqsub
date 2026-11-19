#!/bin/bash
# On-camera script for the pqsub demo video. Runs inside the recorded Terminal window:
#   exec /bin/bash --noprofile --norc demo.sh STAGE_DIR TAKE_DIR
# Every command shown is typed character by character and then executed with eval.
# Output of the first command is revealed line by line (presentation pacing only).
set -u
STAGE="$1" TAKE="$2"
cd "$STAGE" || exit 1
PS1='$ '
now() { perl -MTime::HiRes=time -e 'printf "%.3f\n", time'; }
mark() { echo "$1 $(now)" >> "$TAKE/marks"; }
# Sleep until T seconds after shot1.
at() { perl -MTime::HiRes=time,sleep -e '$d=$ARGV[0]-(time-$ARGV[1]); sleep($d) if $d>0' "$1" "$T0"; }
type_cmd() {
  printf '$ '
  local i
  for ((i = 0; i < ${#1}; i++)); do printf '%s' "${1:i:1}"; sleep 0.028; done
  sleep 0.5
  printf '\n'
}
pace() {
  while IFS= read -r line; do
    case "$line" in
      "== 2."*) at 12; mark shot2 ;;
      "== 3."*) at 28; mark shot3 ;;
      "== "*) sleep 0.3 ;;
      "") ;;
      wrote*) sleep 2.5 ;;
      *) sleep 1.9 ;;
    esac
    printf '%s\n' "$line"
  done
}

clear; printf '\e[3J'   # hide the launch command line at once
# The director resizes the window after launch; wait for that before measuring rows.
while [ ! -f "$TAKE/sized" ]; do sleep 0.05; done
sleep 0.3
ROWS=$(tput lines)
clear; printf '\e[3J'
printf '\e[1;%dr' $((ROWS - 6))   # keep the bottom 6 rows free for captions
printf '\e[H'
echo "$ROWS" > "$TAKE/rows"
touch "$TAKE/ready"
while [ ! -f "$TAKE/go" ]; do sleep 0.05; done
sleep 1

T0=$(now); mark shot1
cmd='./banking_demo out'
type_cmd "$cmd"
eval "$cmd" | pace

at 44; mark shot4
cmd='./pqsub-verify audit --root out/root.pub out/transcript.pqst --require-authorized'
type_cmd "$cmd"
eval "$cmd" | while IFS= read -r line; do sleep 1.6; printf '%s\n' "$line"; done

at 68; mark shot5
at 82; mark end
sleep 15   # ffmpeg stops ~1 s after "end"; the shell exit never reaches the recording
