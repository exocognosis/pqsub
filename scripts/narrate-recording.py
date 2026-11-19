"""Add burned-in narration to a QuickTime screen recording of the pqsub demo.

Record the terminal while running `PQSUB_PACE=1 ./examples/demo-banking.sh`, then:

    python3 scripts/narrate-recording.py RECORDING.mov --start SECONDS [--out docs/media]

--start is the time in the recording at which you pressed Return on the command
(scrub the .mov in QuickTime to find it). Needs Pillow and ffmpeg with libx264.

Writes OUT/pqsub-demo.mp4 (narration burned in, 1080p H.264, no audio) and
OUT/pqsub-demo-clean.mp4 (same cut, no narration). The terminal is scaled to fit
above a dedicated caption strip, so narration never covers terminal text.
"""
import argparse, io, os, subprocess, tempfile
from PIL import Image, ImageDraw, ImageFont

W, H, STRIP = 1920, 1080, 110
LEAD, LENGTH = 0.5, 85.0  # seconds kept before the command starts; total length
NARR = [
    (0, 12, "Authority is delegated once, then only narrowed."),
    (12, 28, "A prompt-injected agent asks for a payment outside its grant."),
    (28, 45, "The executor gate blocks it. The agent never touches the credentials."),
    (45, 70, "Anyone with the root public key can audit the transcript offline."),
    (70, 85, "Post-quantum signatures. Attenuated grants. Executor-side enforcement."),
]
FONT = ImageFont.truetype("/System/Library/Fonts/SFNS.ttf", 42)


def caption_png(text):
    im = Image.new("RGB", (W, STRIP), (0, 0, 0))
    d = ImageDraw.Draw(im)
    tw = d.textlength(text, font=FONT)
    d.text(((W - tw) / 2, (STRIP - 50) / 2), text, font=FONT, fill=(240, 240, 240))
    buf = io.BytesIO()
    im.save(buf, "PNG")
    return buf.getvalue()


def caption_track(path, shift):
    """Encode the caption strip as its own 30 fps video, LENGTH seconds long."""
    blank = caption_png("")
    pngs = [(s + shift, e + shift, caption_png(t)) for s, e, t in NARR]
    p = subprocess.Popen(["ffmpeg", "-y", "-loglevel", "error", "-f", "image2pipe", "-framerate", "30",
                          "-c:v", "png", "-i", "-", "-c:v", "libx264", "-crf", "18", "-pix_fmt", "yuv420p", path],
                         stdin=subprocess.PIPE)
    for f in range(round(LENGTH * 30)):
        t = f / 30
        p.stdin.write(next((png for s, e, png in pngs if s <= t < e), blank))
    p.stdin.close()
    if p.wait() != 0:
        raise SystemExit("ffmpeg failed (caption track)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("recording")
    ap.add_argument("--start", type=float, required=True)
    ap.add_argument("--out", default="docs/media")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    t0 = max(0.0, a.start - LEAD)
    shift = a.start - t0  # narration times are relative to pressing Return
    term = (f"[0:v]trim=start={t0}:duration={LENGTH},setpts=PTS-STARTPTS,fps=30,"
            f"scale={W}:{H - STRIP}:force_original_aspect_ratio=decrease:flags=lanczos,"
            f"pad={W}:{H - STRIP}:(ow-iw)/2:(oh-ih)/2:color=black,setsar=1,format=yuv420p[t]")
    enc = ["-c:v", "libx264", "-preset", "slow", "-crf", "20", "-pix_fmt", "yuv420p",
           "-movflags", "+faststart", "-an"]
    with tempfile.TemporaryDirectory() as tmp:
        cap = os.path.join(tmp, "captions.mp4")
        caption_track(cap, shift)
        for name, strip in [("pqsub-demo.mp4", "[1:v]setsar=1,format=yuv420p[c]"),
                            ("pqsub-demo-clean.mp4", f"color=black:s={W}x{STRIP}:r=30:d={LENGTH},format=yuv420p[c]")]:
            graph = f"{term};{strip};[t][c]vstack=inputs=2:shortest=1[o]"
            subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", a.recording, "-i", cap,
                            "-filter_complex", graph, "-map", "[o]", *enc, os.path.join(a.out, name)], check=True)
    print(f"wrote {a.out}/pqsub-demo.mp4 and {a.out}/pqsub-demo-clean.mp4")


if __name__ == "__main__":
    main()
