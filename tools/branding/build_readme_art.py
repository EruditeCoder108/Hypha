# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Build Hypha's code-drawn README illustration and lightweight GIF.

Requires Pillow. No screenshots, contact data, external services, or raster logo
edits are used. The approved Hypha logo is referenced separately by README.md.
The animation explains a handoff; it is not a radio or performance simulation.
"""

from pathlib import Path
import math
from xml.sax.saxutils import escape

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "assets/readme"
W, H, SCALE = 1200, 480, 2
INK = "#16241f"
MUTED = "#697b72"
BG = "#f7faf8"
MINT = "#83e3b6"
GREEN = "#166c48"
FAINT = "#d9e5de"
NODES = [(570, 130), (695, 88), (852, 94), (973, 124), (1100, 154),
         (1140, 300), (1034, 359), (866, 354), (696, 346), (556, 316)]
EDGES = [(0, 1), (1, 2), (2, 3), (3, 4), (4, 5), (5, 6), (6, 7),
         (7, 8), (8, 9), (9, 0), (1, 8), (2, 7), (3, 6), (0, 2), (7, 9)]
SENDER, COURIER, RECIPIENT = (625, 239), (827, 239), (1030, 239)
CURVES = [(SENDER, (724, 130), COURIER), (COURIER, (932, 339), RECIPIENT)]
STATES = ["01 / ENCRYPT + HAND OFF", "02 / HOLD UNTIL AN ENCOUNTER",
          "03 / RECIPIENT DECRYPTS", "04 / RETURN A GENUINE RECEIPT"]


def point(curve, t):
    a, b, c = curve
    return ((1-t)**2*a[0] + 2*(1-t)*t*b[0] + t*t*c[0],
            (1-t)**2*a[1] + 2*(1-t)*t*b[1] + t*t*c[1])


def font(size, bold=False):
    candidates = [Path("C:/Windows/Fonts") / ("seguisb.ttf" if bold else "segoeui.ttf"),
                  Path("/usr/share/fonts/truetype/dejavu") /
                  ("DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf")]
    for candidate in candidates:
        if candidate.exists():
            return ImageFont.truetype(str(candidate), size * SCALE)
    raise RuntimeError("Install Segoe UI or DejaVu Sans to rebuild the artwork")


FONTS = {size: font(size, bold) for size, bold in
         [(12, True), (13, True), (15, False), (17, False), (19, False), (58, True)]}


def render(progress=0):
    canvas = Image.new("RGB", (W*SCALE, H*SCALE), BG)
    draw = ImageDraw.Draw(canvas)

    def line(points, fill, width=1):
        draw.line([(round(x*SCALE), round(y*SCALE)) for x, y in points], fill=fill,
                  width=round(width*SCALE), joint="curve")

    def circle(x, y, r, fill=None, outline=None, width=1):
        draw.ellipse(((x-r)*SCALE, (y-r)*SCALE, (x+r)*SCALE, (y+r)*SCALE),
                     fill=fill, outline=outline, width=round(width*SCALE))

    def text(x, y, value, size, fill=INK, anchor=None):
        draw.text((x*SCALE, y*SCALE), value, fill=fill, font=FONTS[size], anchor=anchor)

    draw.rounded_rectangle((SCALE, SCALE, (W-1)*SCALE, (H-1)*SCALE), radius=22*SCALE,
                           outline=FAINT, width=SCALE)
    circle(67, 55, 4, GREEN)
    text(81, 45, "OFFLINE BY DESIGN", 13, GREEN)
    text(60, 114, "Messages move.", 58)
    text(60, 182, "Even offline.", 58)
    text(64, 278, "Private conversations, carried by nearby", 19, MUTED)
    text(64, 306, "phones and fixed courier nodes.", 19, MUTED)
    text(64, 365, "NO INTERNET. NO CENTRAL MESSAGE SERVER.", 12, GREEN)

    for a, b in EDGES:
        line([NODES[a], NODES[b]], FAINT)
    for a, b in [(NODES[0], SENDER), (NODES[8], SENDER), (NODES[2], COURIER),
                 (NODES[7], COURIER), (NODES[4], RECIPIENT), (NODES[6], RECIPIENT)]:
        line([a, b], FAINT)
    for x, y in NODES:
        circle(x, y, 3.5, "#a9c0b1")
    for curve in CURVES:
        line([point(curve, i/90) for i in range(91)], "#9ab9a8", 2)
    stage = min(3, int(progress*4))
    local = progress*4-stage
    active = [SENDER, COURIER, RECIPIENT, SENDER][stage]
    if stage == 0:
        packet = point(CURVES[0], min(1, local*1.2))
    elif stage == 1:
        packet = COURIER
    elif stage == 2:
        packet = point(CURVES[1], min(1, local*1.2))
    else:
        reverse = local*2
        packet = point(CURVES[1 if reverse < 1 else 0], 1-(reverse % 1))
    for node in (SENDER, COURIER, RECIPIENT):
        circle(*node, 24, BG, "#d0e2d7")
        circle(*node, 13, INK)
        circle(*node, 3, BG)
    circle(*active, 28 + 3*math.sin(local*math.pi), outline="#abdcc1", width=2)
    for x, label in [(625, "SENDER"), (827, "COURIER"), (1030, "RECIPIENT")]:
        draw.rounded_rectangle(((x-59)*SCALE, 279*SCALE, (x+59)*SCALE, 305*SCALE),
                               radius=6*SCALE, fill=BG)
        text(x, 291, label, 12, MUTED, "mm")
    px, py = packet
    circle(px, py, 17, BG)
    draw.rounded_rectangle(((px-11)*SCALE, (py-9)*SCALE, (px+11)*SCALE, (py+9)*SCALE),
                           radius=4*SCALE, fill=MINT, outline=GREEN, width=SCALE)
    if stage == 3:
        line([(px-5, py), (px-1, py+4), (px+6, py-4)], GREEN, 2)
    else:
        line([(px-7, py-4), (px, py+1), (px+7, py-4)], GREEN)
    text(827, 52, STATES[stage], 12, GREEN, "mm")
    text(827, 388, "Encrypted in transit. Opaque to couriers.", 15, MUTED, "mm")
    line([(36, 425), (1164, 425)], FAINT)
    text(64, 445, "01   DISCOVER NEARBY", 12, MUTED)
    text(415, 445, "02   STORE + CARRY + FORWARD", 12, MUTED)
    text(859, 445, "03   VERIFY DELIVERY", 12, MUTED)
    return canvas.resize((W, H), Image.Resampling.LANCZOS)


def svg():
    fragments = [f'''<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="480" viewBox="0 0 1200 480" role="img" aria-labelledby="title desc">
<title id="title">Hypha — messages move, even offline</title>
<desc id="desc">An illustrated encrypted message passes from sender to courier to recipient. A genuine receipt returns to the sender. This is a conceptual handoff, not a radio simulation.</desc>
<rect x="1" y="1" width="1198" height="478" rx="22" fill="{BG}" stroke="{FAINT}"/>
<g font-family="Segoe UI,DejaVu Sans,Arial,sans-serif">
<circle cx="67" cy="55" r="4" fill="{GREEN}"/>
<text x="81" y="59" fill="{GREEN}" font-size="13" font-weight="600" letter-spacing="1">OFFLINE BY DESIGN</text>
<g fill="{INK}" font-size="58" font-weight="600"><text x="60" y="170">Messages move.</text><text x="60" y="238">Even offline.</text></g>
<g fill="{MUTED}" font-size="19"><text x="64" y="298">Private conversations, carried by nearby</text><text x="64" y="326">phones and fixed courier nodes.</text></g>
<text x="64" y="379" fill="{GREEN}" font-size="12" font-weight="600">NO INTERNET. NO CENTRAL MESSAGE SERVER.</text>
<text x="827" y="56" text-anchor="middle" fill="{GREEN}" font-size="12" font-weight="600">ENCRYPT / CARRY / DELIVER / RECEIPT</text>''']
    for a, b in EDGES:
        x1, y1 = NODES[a]; x2, y2 = NODES[b]
        fragments.append(f'<path d="M{x1} {y1}L{x2} {y2}" stroke="{FAINT}"/>')
    for a, b in [(NODES[0], SENDER), (NODES[8], SENDER), (NODES[2], COURIER),
                 (NODES[7], COURIER), (NODES[4], RECIPIENT), (NODES[6], RECIPIENT)]:
        fragments.append(f'<path d="M{a[0]} {a[1]}L{b[0]} {b[1]}" stroke="{FAINT}"/>')
    for x, y in NODES:
        fragments.append(f'<circle cx="{x}" cy="{y}" r="3.5" fill="#a9c0b1"/>')
    for (x1, y1), (cx, cy), (x2, y2) in CURVES:
        fragments.append(f'<path d="M{x1} {y1}Q{cx} {cy} {x2} {y2}" fill="none" stroke="#9ab9a8" stroke-width="2"/>')
    for (x, y), label in [(SENDER, "SENDER"), (COURIER, "COURIER"), (RECIPIENT, "RECIPIENT")]:
        fragments.append(f'<circle cx="{x}" cy="{y}" r="24" fill="{BG}" stroke="#d0e2d7"/><circle cx="{x}" cy="{y}" r="13" fill="{INK}"/><circle cx="{x}" cy="{y}" r="3" fill="{BG}"/><rect x="{x-59}" y="279" width="118" height="26" rx="6" fill="{BG}"/><text x="{x}" y="295" text-anchor="middle" fill="{MUTED}" font-size="12" font-weight="600">{label}</text>')
    px, py = point(CURVES[0], .5)
    fragments.append(f'<circle cx="{px}" cy="{py}" r="17" fill="{BG}"/><rect x="{px-11}" y="{py-9}" width="22" height="18" rx="4" fill="{MINT}" stroke="{GREEN}"/><path d="M{px-7} {py-4}L{px} {py+1}L{px+7} {py-4}" fill="none" stroke="{GREEN}"/>')
    fragments.append(f'<text x="827" y="393" text-anchor="middle" fill="{MUTED}" font-size="15">Encrypted in transit. Opaque to couriers.</text><path d="M36 425H1164" stroke="{FAINT}"/>')
    for x, label in [(64, "01   DISCOVER NEARBY"), (415, "02   STORE + CARRY + FORWARD"), (859, "03   VERIFY DELIVERY")]:
        fragments.append(f'<text x="{x}" y="459" fill="{MUTED}" font-size="12" font-weight="600">{escape(label)}</text>')
    fragments.append('</g></svg>')
    return '\n'.join(fragments) + '\n'


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "hypha-network.svg").write_text(svg(), encoding="utf-8")
    frames = [render(i/80) for i in range(80)]
    palette = frames[0].quantize(colors=128, method=Image.Quantize.MEDIANCUT)
    indexed = [frame.quantize(palette=palette, dither=Image.Dither.NONE) for frame in frames]
    indexed[0].save(OUT / "hypha-network.gif", save_all=True, append_images=indexed[1:],
                    duration=100, loop=0, optimize=True, disposal=1)
    preview = ROOT / "artifacts/readme-preview"
    preview.mkdir(parents=True, exist_ok=True)
    frames[0].save(preview / "hero-poster.png")
    contact = Image.new("RGB", (1200, 480), "white")
    for index, frame_index in enumerate([8, 28, 48, 68]):
        contact.paste(frames[frame_index].resize((600, 240)), ((index % 2)*600, (index//2)*240))
    contact.save(preview / "animation-contact-sheet.png")
    print(f"Created SVG + 8-second GIF ({(OUT / 'hypha-network.gif').stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
