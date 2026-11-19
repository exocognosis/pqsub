# Demo video pipeline (macOS)

Records the README demo as one continuous take of a real Terminal window, then composites and privacy-checks it.

| Step | Command | What it does |
|---|---|---|
| Framing | `scripts/demo-video/take.sh still` | Opens the demo window and saves one frame of its content area |
| Rehearsal | `scripts/demo-video/take.sh dry` | Runs the whole demo with no capture and prints the timing marks |
| Take | `scripts/demo-video/take.sh take` | Captures `Capture screen 0` with ffmpeg into `demo-takes/<stamp>/raw.mkv` |
| Composite | `python3 scripts/demo-video/composite.py demo-takes/<take>` | Crops, adds cards and captions, writes `docs/media/pqsub-demo*.mp4`, `.srt`, teleprompter |
| Privacy | `scripts/demo-video/privacy_check.sh docs/media/pqsub-demo.mp4 <work>` | Bright-panel scan, OCR at 2 fps (macOS Vision) with a sensitive-string grep, contact sheets at 1 fps |

- [`demo.sh`](demo.sh) runs inside the recorded window. It types each command and then `eval`s it, so every command shown is the command executed. It also writes timing marks that place the captions.
- [`take.sh`](take.sh) is the director:
  - stages fresh binaries and checks their checksums
  - opens the window with the `pqc-demo` Terminal profile and tracks it by tty
  - checks every 0.5 s that the window is in front; on failure it aborts and deletes the capture
- The raw capture (`demo-takes/`, gitignored) shows the menu bar and the title bar. Keep it for re-renders and never share it. Changing a caption only needs a re-render, not a new take.
- Requirements: ffmpeg with libx264, Pillow, Xcode command-line tools (for `swiftc`), Screen Recording permission, and Automation permission for Terminal. During a take, use AC power, turn on Do Not Disturb, and keep your hands off the keyboard and mouse.
