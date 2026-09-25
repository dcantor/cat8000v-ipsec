#!/usr/bin/env python3
"""The bits every portal recording needs: the caption banner, the callout, the cursor, frame capture and the encode.

record.py (the full product tour) predates this and carries its own copies; record_workflows.py (the walkthrough that
matches docs/portal-workflows.pptx) uses these. Both drive the real portal with Playwright and assemble the frames with
ffmpeg's concat demuxer, so a scene's length is decided when it is recorded rather than by a fixed frame rate."""
import io
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from PIL import Image

OVERLAY = """
() => {
  if (document.getElementById('demo-cap')) return;
  const s = document.createElement('style'); s.textContent = `
    #demo-cap { position:fixed; left:0; right:0; bottom:0; padding:14px 24px 16px; background:rgba(11,16,32,.94); color:#fff;
                font:600 19px/1.3 system-ui,sans-serif; z-index:99999; display:none; pointer-events:none; box-shadow:0 -4px 20px rgba(0,0,0,.28) }
    #demo-cap small { display:block; font-weight:400; font-size:14.5px; color:#cbd5e1; margin-top:4px }
    #demo-cap .n { display:inline-block; background:#c2410c; color:#fff; font-size:12px; font-weight:700; padding:1px 9px;
                   border-radius:999px; margin-right:10px; vertical-align:middle }
    #demo-cur { position:fixed; width:22px; height:22px; z-index:100000; pointer-events:none; transform:translate(-3px,-2px);
                transition:left .35s ease, top .35s ease; display:none }
    #demo-note { position:fixed; z-index:99998; background:#c2410c; color:#fff; font:600 13.5px/1.25 system-ui,sans-serif;
                 padding:6px 10px; border-radius:6px; max-width:340px; pointer-events:none; box-shadow:0 2px 10px rgba(0,0,0,.3); display:none }
    #demo-note:after { content:''; position:absolute; left:-8px; top:10px; border:6px solid transparent; border-right-color:#c2410c; border-left:0 }
    .demo-ring { outline:3px solid #c2410c !important; outline-offset:2px; border-radius:6px }`;
  document.head.appendChild(s);
  const c = document.createElement('div'); c.id = 'demo-cap'; document.body.appendChild(c);
  const n = document.createElement('div'); n.id = 'demo-note'; document.body.appendChild(n);
  const m = document.createElement('div'); m.id = 'demo-cur';
  m.innerHTML = '<svg viewBox="0 0 24 24" width="22" height="22"><path d="M4 2l14 11-6 1 4 7-3 1-4-7-5 4z" fill="#111" stroke="#fff" stroke-width="1.5"/></svg>';
  document.body.appendChild(m);
}"""


class Recorder:
    """Holds the frames and the scene counter; every helper takes the page it is driving."""

    def __init__(self, width=1400, height=860):
        self.frames, self.scene, self.width, self.height = [], 0, width, height

    # ---- overlay -------------------------------------------------------------------------------------------
    def overlay(self, page): page.evaluate(OVERLAY)

    def caption(self, page, title, sub="", numbered=True):
        self.overlay(page)
        if numbered: self.scene += 1
        page.evaluate("([t, s, n]) => { const c = document.getElementById('demo-cap');"
                      " c.innerHTML = (n ? '<span class=n>' + n + '</span>' : '') + t + (s ? '<small>' + s + '</small>' : '');"
                      " c.style.display = 'block'; }", [title, sub, self.scene if numbered else 0])

    def note(self, page, sel, text):
        self.overlay(page)
        el = page.locator(sel).first
        try: el.scroll_into_view_if_needed(timeout=5000); b = el.bounding_box()
        except Exception: return                                  # noqa: BLE001 — a callout is never worth failing for
        if not b: return
        x, y = b["x"] + b["width"] + 14, b["y"] + max(0, b["height"] / 2 - 16)
        if x > self.width - 360: x, y = max(10, b["x"] - 360), b["y"] + b["height"] + 10
        page.evaluate("([x, y, t]) => { const n = document.getElementById('demo-note'); n.textContent = t;"
                      " n.style.left = x + 'px'; n.style.top = y + 'px'; n.style.display = 'block'; }", [x, y, text])
        el.evaluate("e => e.classList.add('demo-ring')")

    def note_off(self, page):
        page.evaluate("() => { const n = document.getElementById('demo-note'); if (n) n.style.display = 'none';"
                      " document.querySelectorAll('.demo-ring').forEach(e => e.classList.remove('demo-ring')); }")

    # ---- frames --------------------------------------------------------------------------------------------
    def snap(self, page, seconds=1.0):
        self.frames.append((Image.open(io.BytesIO(page.screenshot())).convert("RGB"), seconds))

    def hold(self, page, seconds, step=0.5):
        for _ in range(max(1, int(seconds / step))): self.snap(page, step); time.sleep(step)

    # ---- interaction ---------------------------------------------------------------------------------------
    def move_to(self, page, sel):
        el = page.locator(sel).first; el.scroll_into_view_if_needed(); b = el.bounding_box()
        if b:
            page.evaluate("([x, y]) => { const m = document.getElementById('demo-cur'); m.style.display = 'block';"
                          " m.style.left = x + 'px'; m.style.top = y + 'px'; }",
                          [b["x"] + b["width"] / 2, b["y"] + b["height"] / 2])
            el.evaluate("e => e.classList.add('demo-ring')"); time.sleep(0.35); self.snap(page, 0.6)
        return el

    def click(self, page, sel, settle=0.8):
        el = self.move_to(page, sel); el.click(); time.sleep(settle)
        el.evaluate("e => e.classList.remove('demo-ring')") if el else None
        self.overlay(page); self.snap(page, 0.9)

    def scroll_to(self, page, sel, block="start", settle=0.6):
        page.evaluate("([s, b]) => { const e = document.querySelector(s); if (e) e.scrollIntoView({block: b}); }", [sel, block])
        time.sleep(settle)

    # ---- output --------------------------------------------------------------------------------------------
    def write_mp4(self, out: Path, fps=15, crf=21):
        try:
            import imageio_ffmpeg; ffmpeg = imageio_ffmpeg.get_ffmpeg_exe()
        except ImportError:
            ffmpeg = shutil.which("ffmpeg")
        if not ffmpeg: raise SystemExit("no ffmpeg (webapp/.venv/bin/pip install imageio-ffmpeg)")
        tmp = Path(tempfile.mkdtemp(prefix="demo-frames-")); lines = []
        for i, (f, d) in enumerate(self.frames):
            f.save(tmp / f"f{i:04d}.png"); lines += [f"file 'f{i:04d}.png'", f"duration {max(0.08, d):.3f}"]
        lines.append(f"file 'f{len(self.frames) - 1:04d}.png'")     # the concat demuxer wants the last file twice
        (tmp / "list.txt").write_text("\n".join(lines) + "\n")
        subprocess.run([ffmpeg, "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", str(tmp / "list.txt"),
                        "-vf", f"fps={fps},format=yuv420p,scale=trunc(iw/2)*2:trunc(ih/2)*2", "-c:v", "libx264",
                        "-preset", "slow", "-crf", str(crf), "-movflags", "+faststart", str(out)], check=True)
        shutil.rmtree(tmp)
        return out

    def write_gif(self, out: Path, width=960):
        imgs = [f.resize((width, int(f.height * width / f.width)), Image.LANCZOS) for f, _ in self.frames]
        durs = [max(80, int(d * 1000)) for _, d in self.frames]
        pal = imgs[0].quantize(colors=256, method=Image.Quantize.MEDIANCUT)
        q = [im.quantize(colors=256, palette=pal, dither=Image.Dither.NONE) for im in imgs]
        q[0].save(out, save_all=True, append_images=q[1:], duration=durs, loop=0, optimize=True)
        return out, sum(durs) / 1000
