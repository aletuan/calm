"""Calm app icon. Run: python3 scripts/make-icon.py (needs Pillow), then copy the outputs
into apps/desktop/src-tauri/icons/ and calm-mark.png into apps/desktop/src/assets/.

Layout: Apple macOS template (1024 canvas, 824 squircle body at 100 px margin),
no pixel outside the squircle so macOS 26 does not jail it in a gray tile."""
import math
from PIL import Image, ImageDraw, ImageFilter, ImageChops

S = 4                      # supersampling
N = 1024 * S
BODY = 816 * S             # a hair inside Apple's 824 body
OFF = (N - BODY) // 2

def squircle_mask(size, n=5.0):
    m = Image.new("L", (size, size), 0)
    d = ImageDraw.Draw(m)
    r = size / 2
    pts = []
    for i in range(2000):
        t = 2 * math.pi * i / 2000
        c, s = math.cos(t), math.sin(t)
        x = r + r * math.copysign(abs(c) ** (2 / n), c)
        y = r + r * math.copysign(abs(s) ** (2 / n), s)
        pts.append((x, y))
    d.polygon(pts, fill=255)
    return m

def lerp(a, b, t):
    return tuple(round(a[i] + (b[i] - a[i]) * t) for i in range(3))

# Background: deep slate-teal, lighter at the top (Calm accent family, #82a6af).
TOP, BOTTOM = (38, 66, 75), (14, 26, 31)
bg = Image.new("RGB", (BODY, BODY))
px = ImageDraw.Draw(bg)
for y in range(BODY):
    px.line([(0, y), (BODY, y)], fill=lerp(TOP, BOTTOM, (y / BODY) ** 0.9))
# Soft glow behind the source dot.
glow = Image.new("L", (BODY, BODY), 0)
gd = ImageDraw.Draw(glow)
cx, cy = BODY // 2, int(BODY * 0.70)
gr = int(BODY * 0.42)
gd.ellipse([cx - gr, cy - gr, cx + gr, cy + gr], fill=70)
glow = glow.filter(ImageFilter.GaussianBlur(BODY * 0.12))
bg = Image.composite(Image.new("RGB", (BODY, BODY), (130, 166, 175)), bg, glow)

art = Image.new("RGBA", (BODY, BODY), (0, 0, 0, 0))
ad = ImageDraw.Draw(art)
# Wi-Fi arcs as calm ripples: same stroke, fading outward.
W = int(BODY * 0.052)
for i, (rad, alpha) in enumerate([(0.17, 255), (0.29, 200), (0.41, 140)]):
    R = int(BODY * rad)
    box = [cx - R, cy - R, cx + R, cy + R]
    ad.arc(box, start=225, end=315, fill=(214, 233, 236, alpha), width=W)
# Round caps for each arc.
for rad, alpha in [(0.17, 255), (0.29, 200), (0.41, 140)]:
    R = int(BODY * rad) - W // 2
    for ang in (225, 315):
        a = math.radians(ang)
        x, y = cx + R * math.cos(a), cy + R * math.sin(a)
        ad.ellipse([x - W / 2, y - W / 2, x + W / 2, y + W / 2], fill=(214, 233, 236, alpha))
D = int(BODY * 0.062)
ad.ellipse([cx - D, cy - D, cx + D, cy + D], fill=(236, 244, 245, 255))

tile = bg.convert("RGBA")
tile.alpha_composite(art)
# Subtle top inner highlight, kept inside the shape.
hl = Image.new("L", (BODY, BODY), 0)
ImageDraw.Draw(hl).rectangle([0, 0, BODY, int(BODY * 0.5)], fill=18)
hl = hl.filter(ImageFilter.GaussianBlur(BODY * 0.08))
tile = Image.composite(Image.new("RGBA", (BODY, BODY), (255, 255, 255, 255)), tile, hl)

mask = squircle_mask(BODY)
tile.putalpha(mask)
canvas = Image.new("RGBA", (N, N), (0, 0, 0, 0))
canvas.alpha_composite(tile, (OFF, OFF))
icon = canvas.resize((1024, 1024), Image.LANCZOS)
icon.save("icon.png")

# Sidebar mark: the body only, cropped tight (no transparent margin).
body = tile.resize((128, 128), Image.LANCZOS)
body.save("calm-mark.png")

for size, name in [(32, "32x32.png"), (128, "128x128.png"), (256, "128x128@2x.png")]:
    icon.resize((size, size), Image.LANCZOS).save(name)
icon.save("icon.icns", sizes=[(16, 16), (32, 32), (64, 64), (128, 128), (256, 256), (512, 512), (1024, 1024)])
icon.save("icon.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])

# Check: nothing outside Apple's 824 squircle body.
apple = Image.new("L", (1024, 1024), 0)
apple.paste(squircle_mask(824), (100, 100))
outside = ImageChops.subtract(icon.getchannel("A"), apple)
print("pixels outside template:", sum(1 for v in outside.getdata() if v > 8), "bbox", icon.getchannel("A").getbbox())
