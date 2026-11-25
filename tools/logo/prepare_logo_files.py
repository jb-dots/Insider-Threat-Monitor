"""Generate official HuliCAP logo files per user specification from assets/logo.jpg.

Outputs:
- assets/logo_white.png (full line art in white on transparent background, 4% padding)
- assets/logo_black.png (full line art in #111111 on transparent background, 4% padding)
- assets/icon_white.png (icon mark only in white on transparent background, square, 4% padding)
- assets/icon_black.png (icon mark only in #111111 on transparent background, square, 4% padding)
- assets/favicon.png (icon_black composited on solid white background for browser tab favicon)
"""

from PIL import Image
import numpy as np
from pathlib import Path

assets_dir = Path("assets")
source_img = Image.open(assets_dir / "logo.jpg").convert("L")
arr = np.array(source_img, dtype=np.float32)

# Find active area bounding box
threshold = 20.0
active = arr > threshold
rows = np.any(active, axis=1)
cols = np.any(active, axis=0)

ymin, ymax = np.where(rows)[0][[0, -1]]
xmin, xmax = np.where(cols)[0][[0, -1]]
W = xmax - xmin + 1
H = ymax - ymin + 1
print(f"Full logo bbox: ({xmin}, {ymin}) to ({xmax}, {ymax}), W={W}, H={H}")

# Separate mark from text
col_sums = active.sum(axis=0)
gap_indices = np.where(col_sums[380:460] == 0)[0] + 380
split_x = int(np.median(gap_indices))
print(f"Icon mark split at x={split_x}")

mark_active = active[:, :split_x]
m_rows = np.any(mark_active, axis=1)
m_cols = np.any(mark_active, axis=0)
m_ymin, m_ymax = np.where(m_rows)[0][[0, -1]]
m_xmin, m_xmax = np.where(m_cols)[0][[0, -1]]
Wm = m_xmax - m_xmin + 1
Hm = m_ymax - m_ymin + 1
print(f"Icon mark bbox: ({m_xmin}, {m_ymin}) to ({m_xmax}, {m_ymax}), Wm={Wm}, Hm={Hm}")

# 1. Full logo crops
full_crop = arr[ymin:ymax+1, xmin:xmax+1]

# 4% padding for full logo
pad_x = int(round(W * 0.04))
pad_y = int(round(H * 0.04))
print(f"Full logo padding: pad_x={pad_x}, pad_y={pad_y}")

def create_rgba(crop_arr, pad_x, pad_y, color_rgb, square=False):
    ch, cw = crop_arr.shape
    # Smooth brightness-to-alpha mapping
    # Noise below 10 is clamped to 0, values from 10 to 240 smoothly mapped to 0..255
    alpha_core = np.clip((crop_arr - 10.0) / (240.0 - 10.0) * 255.0, 0.0, 255.0).astype(np.uint8)
    
    if square:
        side_art = max(cw, ch)
        total_side = side_art + max(pad_x, pad_y) * 2
        alpha = np.zeros((total_side, total_side), dtype=np.uint8)
        ox = (total_side - cw) // 2
        oy = (total_side - ch) // 2
        alpha[oy:oy+ch, ox:ox+cw] = alpha_core
    else:
        out_w = cw + pad_x * 2
        out_h = ch + pad_y * 2
        alpha = np.zeros((out_h, out_w), dtype=np.uint8)
        alpha[pad_y:pad_y+ch, pad_x:pad_x+cw] = alpha_core
        
    r = np.full_like(alpha, color_rgb[0])
    g = np.full_like(alpha, color_rgb[1])
    b = np.full_like(alpha, color_rgb[2])
    return Image.fromarray(np.stack([r, g, b, alpha], axis=-1), mode="RGBA")

# Generate logo_white.png and logo_black.png
logo_white = create_rgba(full_crop, pad_x, pad_y, (255, 255, 255), square=False)
logo_black = create_rgba(full_crop, pad_x, pad_y, (17, 17, 17), square=False)

logo_white.save(assets_dir / "logo_white.png", "PNG", optimize=True)
logo_black.save(assets_dir / "logo_black.png", "PNG", optimize=True)
print(f"Saved logo_white.png: {logo_white.size}")
print(f"Saved logo_black.png: {logo_black.size}")

# 2. Icon-only mark crops
mark_crop = arr[m_ymin:m_ymax+1, m_xmin:m_xmax+1]
S = max(Wm, Hm)
pad_m = int(round(S * 0.04))
print(f"Icon mark padding: pad_m={pad_m}")

icon_white = create_rgba(mark_crop, pad_m, pad_m, (255, 255, 255), square=True)
icon_black = create_rgba(mark_crop, pad_m, pad_m, (17, 17, 17), square=True)

icon_white.save(assets_dir / "icon_white.png", "PNG", optimize=True)
icon_black.save(assets_dir / "icon_black.png", "PNG", optimize=True)
print(f"Saved icon_white.png: {icon_white.size}")
print(f"Saved icon_black.png: {icon_black.size}")

# 3. Favicon (icon_black on white square background for browser tab favicon)
fav_bg = Image.new("RGBA", icon_black.size, (255, 255, 255, 255))
fav_combined = Image.alpha_composite(fav_bg, icon_black).convert("RGB")
fav_combined.save(assets_dir / "favicon.png", "PNG", optimize=True)
print(f"Saved favicon.png: {fav_combined.size}")

print("All asset files generated successfully!")

