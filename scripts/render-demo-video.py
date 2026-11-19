"""Render the pqsub banking demo video from the demo's captured terminal output.

usage (macOS, needs Pillow and ffmpeg with libx264):
    ./examples/demo-banking.sh > /tmp/demo.txt && python3 scripts/render-demo-video.py /tmp/demo.txt docs/media
Produces OUT_DIR/pqsub-demo.mp4 (narration burned in), pqsub-demo-clean.mp4 and pqsub-demo.srt.
"""
import os, subprocess, sys
from PIL import Image, ImageDraw, ImageFont

W, H = 1920, 1080
BG = (13, 17, 23)
FG = (201, 209, 217)
DIM = (110, 118, 129)
CYAN = (88, 196, 220)
GREEN = (63, 185, 80)
RED = (248, 81, 73)
AMBER = (210, 153, 34)
MONO = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", 23)
SANS = ImageFont.truetype("/System/Library/Fonts/SFNS.ttf", 42)
LH, PADX, PADY = 31, 70, 48
PROMPT = "$ ./examples/demo-banking.sh"

src, out_dir = sys.argv[1], sys.argv[2]
lines = open(src).read().rstrip("\n").split("\n")
sec = {}  # section number -> index of its header line
for i, l in enumerate(lines):
    if l.startswith("== ") and l[3].isdigit():
        sec[int(l[3])] = i

def color(l):
    if l.startswith("== "):
        return CYAN
    if "REFUSED" in l:
        return RED
    if l.startswith("BLOCKED"):
        return AMBER
    if "EXECUTED" in l or l.startswith(("VALID", "PROVED")):
        return GREEN
    if "injected" in l:
        return AMBER
    if l.startswith(("wrote", "bank ledger")):
        return DIM
    return FG

NARR = [
    (0, 12, "Authority is delegated once, then only narrowed."),
    (12, 28, "A prompt-injected agent asks for a payment outside its grant."),
    (28, 45, "The executor gate blocks it. The agent never touches the credentials."),
    (45, 70, "Anyone with the root public key can audit the transcript offline."),
    (70, 85, "Post-quantum signatures. Attenuated grants. Executor-side enforcement."),
]

def frame(prompt, shown, narration):
    im = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(im)
    y = PADY
    d.text((PADX, y), prompt, font=MONO, fill=GREEN if prompt == PROMPT else FG)
    y += LH * 1.4
    for l in lines[:shown]:
        d.text((PADX, y), l, font=MONO, fill=color(l))
        y += LH
    if narration:
        tw = d.textlength(narration, font=SANS)
        bh = 96
        band = Image.new("RGBA", (W, bh), (0, 0, 0, 200))
        im.paste(band, (0, H - bh), band)
        d.text(((W - tw) / 2, H - bh + 24), narration, font=SANS, fill=(240, 240, 240))
    return im

# Timeline: (start_seconds, prompt_text, visible_line_count)
events = []
t = 0.4
for k in range(2, len(PROMPT) + 1, 2):
    events.append((t, PROMPT[:k], 0)); t += 0.06
events.append((t, PROMPT, 0))
def reveal(start, first, last, step):
    return [(start + step * j, PROMPT, n) for j, n in enumerate(range(first, last + 1))]
events += reveal(3.0, sec[1] + 1, sec[2] - 1, 2.2)       # grant chain
events += reveal(13.0, sec[2] + 1, sec[3] - 1, 2.0)      # agent requests
events += reveal(29.0, sec[3] + 1, sec[4] - 1, 2.0)      # gate decisions
events += reveal(46.0, sec[4] + 1, len(lines), 2.4)      # independent audit
END = 85.0

def build(path, narrate):
    tmp = os.path.join(out_dir, "frames")
    os.makedirs(tmp, exist_ok=True)
    # cut points: every event and narration boundary
    cuts = sorted({e[0] for e in events} | {0.0} | {a for a, _, _ in NARR})
    state = ("$ ", 0)
    segs = []
    for i, c in enumerate(cuts):
        for e in events:
            if e[0] <= c:
                state = (e[1], e[2])
        nar = next((s for a, b, s in NARR if a <= c < b), "") if narrate else ""
        f = os.path.join(tmp, f"{'n' if narrate else 'c'}{i:04d}.png")
        frame(state[0], state[1], nar).save(f)
        nxt = cuts[i + 1] if i + 1 < len(cuts) else END
        segs.append((f, round(nxt * 30) - round(c * 30)))
    p = subprocess.Popen(["ffmpeg", "-y", "-loglevel", "error", "-f", "image2pipe", "-framerate", "30",
                          "-c:v", "png", "-i", "-", "-vf", "format=yuv420p", "-c:v", "libx264",
                          "-preset", "slow", "-crf", "20", "-tune", "stillimage", "-movflags", "+faststart", path],
                         stdin=subprocess.PIPE)
    for f, n in segs:
        data = open(f, "rb").read()
        for _ in range(n):
            p.stdin.write(data)
    p.stdin.close()
    if p.wait() != 0:
        raise SystemExit("ffmpeg failed")

def srt():
    ts = lambda s: f"00:{int(s // 60):02d}:{int(s % 60):02d},000"
    return "".join(f"{i}\n{ts(a)} --> {ts(b)}\n{s}\n\n" for i, (a, b, s) in enumerate(NARR, 1))

build(os.path.join(out_dir, "pqsub-demo.mp4"), True)
build(os.path.join(out_dir, "pqsub-demo-clean.mp4"), False)
open(os.path.join(out_dir, "pqsub-demo.srt"), "w").write(srt())
frame(PROMPT, len(lines), NARR[3][2]).save(os.path.join(out_dir, "pqsub-demo-poster.png"))
print("done")
