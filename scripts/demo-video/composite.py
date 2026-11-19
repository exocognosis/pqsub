"""Composite a take into the final demo video.

    python3 scripts/demo-video/composite.py demo-takes/<take> [--out docs/media]

Reads raw.mkv, marks, launch and geometry.json from the take directory. Writes
pqsub-demo.mp4 (captions burned in), pqsub-demo-clean.mp4 (no captions),
pqsub-demo.srt and pqsub-demo-teleprompter.txt. Captions and cards are rendered
with Pillow (no drawtext needed). Needs ffmpeg with libx264.
"""
import argparse, io, json, os, subprocess, tempfile, textwrap
from PIL import Image, ImageDraw, ImageFont

W, H, STRIP, FPS = 1920, 1080, 140, 30
INTRO, OUTRO, XF = 3.0, 3.5, 0.5
NARR = [  # (from mark, to mark, caption)
    ("shot1", "shot2", "Authority is delegated once, then only narrowed."),
    ("shot2", "shot3", "A prompt-injected agent asks for a payment outside its grant."),
    ("shot3", "shot4", "The executor gate blocks it. The agent never touches the credentials."),
    ("shot4", "shot5", "Anyone with the root public key can audit the transcript offline."),
    ("shot5", "end", "Post-quantum signatures. Attenuated grants. Executor-side enforcement."),
]
CLAIM = ("If tools are reachable only through executors that run the gate, then a prompt-injected "
         "agent cannot cause a side effect outside the authority delegated to it, and a third "
         "party can verify this from the transcript.")
SANS = "/System/Library/Fonts/SFNS.ttf"
MONO = "/System/Library/Fonts/Menlo.ttc"
NORM = f"fps={FPS},format=yuv420p,setsar=1,settb=1/{FPS}"


def font(path, size):
    return ImageFont.truetype(path, size)


def caption_png(text):
    im = Image.new("RGB", (W, STRIP), (0, 0, 0))
    if text:
        d = ImageDraw.Draw(im)
        f = font(SANS, 40)
        tw = d.textlength(text, font=f)
        x, y = (W - tw) / 2, (STRIP - 48) / 2
        d.rounded_rectangle((x - 28, y - 14, x + tw + 28, y + 62), radius=10, fill=(28, 28, 30))
        d.text((x, y), text, font=f, fill=(238, 238, 238))
    b = io.BytesIO(); im.save(b, "PNG"); return b.getvalue()


def card(path, title, lines, mono_line=None):
    im = Image.new("RGB", (W, H), (0, 0, 0))
    d = ImageDraw.Draw(im)
    ft, fb, fm = font(SANS, 96), font(SANS, 44), font(MONO, 38)
    blocks = [(title, ft, (255, 255, 255), 130)] + [(l, fb, (210, 210, 210), 64) for l in lines]
    if mono_line:
        blocks.append((mono_line, fm, (88, 196, 220), 80))
    total = sum(h for *_, h in blocks)
    y = (H - total) / 2
    for text, f, c, h in blocks:
        d.text(((W - d.textlength(text, font=f)) / 2, y), text, font=f, fill=c)
        y += h
    im.save(path)


def first_change(raw, crop, start, seconds=20):
    """Video time of the first frame (after `start`) whose crop region differs from the first."""
    x, y, w, h = crop
    cmd = ["ffmpeg", "-loglevel", "error", "-ss", f"{start}", "-i", raw, "-t", f"{seconds}",
           "-vf", f"crop={w}:{h}:{x}:{y},scale=160:90,format=gray", "-f", "rawvideo", "-"]
    data = subprocess.run(cmd, capture_output=True, check=True).stdout
    n = 160 * 90
    frames = [data[i:i + n] for i in range(0, len(data) - n + 1, n)]
    base = frames[0]
    for i, f in enumerate(frames):
        if sum(abs(a - b) for a, b in zip(f[::7], base[::7])) > 400:
            return start + i / FPS
    return None


def ts(t):
    ms = int(round(t * 1000))
    return f"{ms // 3600000:02d}:{ms // 60000 % 60:02d}:{ms // 1000 % 60:02d},{ms % 1000:03d}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("take")
    ap.add_argument("--out", default="docs/media")
    a = ap.parse_args()
    take = a.take
    marks = dict(l.split() for l in open(os.path.join(take, "marks")))
    marks = {k: float(v) for k, v in marks.items()}
    geo = json.load(open(os.path.join(take, "geometry.json")))
    raw = os.path.join(take, "raw.mkv")
    launch = float(open(os.path.join(take, "launch")).read())

    # Sync: video_time = host_time - offset. Start from the ffmpeg launch time, then
    # refine with the first frame that changes (the prompt appearing at shot1).
    offset = launch
    seen = first_change(raw, geo["crop"], max(0.0, marks["shot1"] - launch - 3))
    if seen is not None and abs((marks["shot1"] - seen) - launch) < 2:
        offset = marks["shot1"] - seen
    print(f"sync offset vs launch: {offset - launch:+.3f} s")
    start = marks["shot1"] - offset - 0.5
    length = marks["end"] - offset - start
    rel = {k: v - offset - start for k, v in marks.items()}

    os.makedirs(a.out, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        # caption track, same length as the terminal segment
        caps = [(rel[s], rel[e], caption_png(t)) for s, e, t in NARR]
        blank = caption_png("")
        capf = os.path.join(tmp, "captions.mp4")
        p = subprocess.Popen(["ffmpeg", "-y", "-loglevel", "error", "-f", "image2pipe", "-framerate", str(FPS),
                              "-c:v", "png", "-i", "-", "-c:v", "libx264", "-crf", "16", "-pix_fmt", "yuv420p", capf],
                             stdin=subprocess.PIPE)
        for i in range(int(round(length * FPS))):
            t = i / FPS
            p.stdin.write(next((png for s, e, png in caps if s <= t < e), blank))
        p.stdin.close(); p.wait()

        intro, outro = os.path.join(tmp, "intro.png"), os.path.join(tmp, "outro.png")
        card(intro, "pqsub", ["Can anyone prove an AI agent stayed", "within the authority it was delegated?"])
        card(outro, "pqsub", textwrap.wrap(CLAIM, 62), "github.com/exocognosis/pqsub")

        x, y, w, h = geo["crop"]
        term = (f"[0:v]trim=start={start:.3f}:duration={length:.3f},setpts=PTS-STARTPTS,"
                f"crop={w}:{h}:{x}:{y},scale={W}:{H}:flags=lanczos,{NORM}[t0]")
        cards = f"[2:v]{NORM}[in];[3:v]{NORM}[out]"
        o1 = INTRO - XF
        o2 = o1 + length - XF
        for name, burn in [("pqsub-demo.mp4", True), ("pqsub-demo-clean.mp4", False)]:
            mid = (f"[t0][1:v]overlay=0:{H - STRIP}:shortest=1,{NORM}[t]" if burn else "[t0]null[t]")
            graph = (f"{term};{mid};{cards};[in][t]xfade=transition=fade:duration={XF}:offset={o1:.3f}[a];"
                     f"[a][out]xfade=transition=fade:duration={XF}:offset={o2:.3f}[v]")
            subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", raw, "-i", capf,
                            "-loop", "1", "-framerate", str(FPS), "-t", str(INTRO), "-i", intro,
                            "-loop", "1", "-framerate", str(FPS), "-t", str(OUTRO), "-i", outro,
                            "-f", "lavfi", "-i", "anullsrc=r=48000:cl=stereo",
                            "-filter_complex", graph, "-map", "[v]", "-map", "4:a",
                            "-c:v", "libx264", "-preset", "slow", "-crf", "18", "-tune", "stillimage",
                            "-c:a", "aac", "-b:a", "32k", "-shortest", "-movflags", "+faststart",
                            os.path.join(a.out, name)], check=True)

    sched = [(o1 + rel[s], o1 + rel[e], t) for s, e, t in NARR]
    with open(os.path.join(a.out, "pqsub-demo.srt"), "w") as f:
        for i, (s, e, t) in enumerate(sched, 1):
            f.write(f"{i}\n{ts(s)} --> {ts(e)}\n{t}\n\n")
    with open(os.path.join(a.out, "pqsub-demo-teleprompter.txt"), "w") as f:
        for s, e, t in sched:
            f.write(f"[{s:5.1f}s - {e:5.1f}s]  {t}\n")
    total = INTRO + length + OUTRO - 2 * XF
    print(f"terminal segment {length:.1f} s, total {total:.1f} s -> {a.out}")


if __name__ == "__main__":
    main()
