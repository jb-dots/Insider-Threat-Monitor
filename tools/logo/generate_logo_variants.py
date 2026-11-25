import numpy as np
from PIL import Image
from pathlib import Path

assets_dir = Path("assets")
source_path = assets_dir / "hulicap_logo_new_source.jpg"

img = Image.open(source_path).convert("RGB")
w, h = img.size
print(f"Source image loaded: {w}x{h}")

gray = img.convert("L")
arr = np.array(gray, dtype=np.float32)

# Find bounding boxes
# The image is black background (~0-10) and white line art (~150-255)
# Find row and col bounds where value > 30
threshold = 30
active = arr > threshold
rows = np.any(active, axis=1)
cols = np.any(active, axis=0)
ymin, ymax = np.where(rows)[0][[0, -1]]
xmin, xmax = np.where(cols)[0][[0, -1]]
print(f"Full logo bbox: xmin={xmin}, xmax={xmax}, ymin={ymin}, ymax={ymax}")
print(f"Full logo dimensions: width={xmax - xmin + 1}, height={ymax - ymin + 1}")

# Icon mark vs text split:
# Looking between x=380 and x=460 for where column sum is minimal / zero
col_sums = active.sum(axis=0)
gap_indices = np.where(col_sums[380:460] == 0)[0] + 380
print("Gap indices between mark and text:", gap_indices)
split_x = int(np.median(gap_indices))
print(f"Splitting icon mark at x <= {split_x}")

# Bbox of icon mark
mark_active = active[:, :split_x]
mark_rows = np.any(mark_active, axis=1)
mark_cols = np.any(mark_active, axis=0)
m_ymin, m_ymax = np.where(mark_rows)[0][[0, -1]]
m_xmin, m_xmax = np.where(mark_cols)[0][[0, -1]]
print(f"Mark bbox: xmin={m_xmin}, xmax={m_xmax}, ymin={m_ymin}, ymax={m_ymax} (w={m_xmax - m_xmin + 1}, h={m_ymax - m_ymin + 1})")

def make_transparent_png(cropped_gray, color_rgb=(255, 255, 255), padding=12, square=False):
    # cropped_gray is a PIL Image in mode 'L'
    # Use pixel values as alpha channel
    # Clean black background noise (values < 15 become 0 alpha)
    arr_l = np.array(cropped_gray, dtype=np.float32)
    
    # Smooth contrast curve for crisp edges without harsh cutoff:
    # 0..15 -> 0, 15..240 scaled to 0..255, 240..255 -> 255
    alpha = np.clip((arr_l - 12.0) / (240.0 - 12.0) * 255.0, 0.0, 255.0).astype(np.uint8)
    
    cw, ch = cropped_gray.size
    
    if square:
        side = max(cw, ch) + padding * 2
        new_alpha = np.zeros((side, side), dtype=np.uint8)
        ox = (side - cw) // 2
        oy = (side - ch) // 2
        new_alpha[oy:oy+ch, ox:ox+cw] = alpha
        out_w, out_h = side, side
        alpha = new_alpha
    else:
        out_w = cw + padding * 2
        out_h = ch + padding * 2
        new_alpha = np.zeros((out_h, out_w), dtype=np.uint8)
        new_alpha[padding:padding+ch, padding:padding+cw] = alpha
        alpha = new_alpha

    r = np.full_like(alpha, color_rgb[0])
    g = np.full_like(alpha, color_rgb[1])
    b = np.full_like(alpha, color_rgb[2])
    
    rgba = np.stack([r, g, b, alpha], axis=-1)
    return Image.fromarray(rgba, mode="RGBA")

# 1. Full logo crop
full_crop = gray.crop((xmin, ymin, xmax + 1, ymax + 1))

# 2. Mark crop
mark_crop = gray.crop((m_xmin, m_ymin, m_xmax + 1, m_ymax + 1))

# Generate assets:
# 1. hulicap_logo_full_opt.png (near-black #111111 for light form)
full_dark = make_transparent_png(full_crop, color_rgb=(17, 17, 17), padding=10, square=False)
full_dark.save(assets_dir / "hulicap_logo_full_opt.png", "PNG", optimize=True)
print("Saved hulicap_logo_full_opt.png:", full_dark.size)

# 2. hulicap_logo_white.png (pure white for dark backgrounds)
full_white = make_transparent_png(full_crop, color_rgb=(255, 255, 255), padding=10, square=False)
full_white.save(assets_dir / "hulicap_logo_white.png", "PNG", optimize=True)
print("Saved hulicap_logo_white.png:", full_white.size)

# 3. hulicap_logo_brand.png (white mark square for dark auth brand panel watermark)
mark_brand = make_transparent_png(mark_crop, color_rgb=(255, 255, 255), padding=16, square=True)
mark_brand.save(assets_dir / "hulicap_logo_brand.png", "PNG", optimize=True)
print("Saved hulicap_logo_brand.png:", mark_brand.size)

# 4. hulicap_logo_sidebar.png (white mark for dark sidebar header)
mark_sidebar = make_transparent_png(mark_crop, color_rgb=(255, 255, 255), padding=8, square=True)
mark_sidebar.save(assets_dir / "hulicap_logo_sidebar.png", "PNG", optimize=True)
print("Saved hulicap_logo_sidebar.png:", mark_sidebar.size)

# 5. hulicap_logo_mark.png (dark mark for light backgrounds)
mark_dark = make_transparent_png(mark_crop, color_rgb=(17, 17, 17), padding=16, square=True)
mark_dark.save(assets_dir / "hulicap_logo_mark.png", "PNG", optimize=True)
print("Saved hulicap_logo_mark.png:", mark_dark.size)

print("All logo assets generated successfully!")

