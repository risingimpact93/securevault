#!/usr/bin/env python3
"""Render a 1024x1024 SecureVault app icon: gold keyhole in a rounded shield."""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

SIZE = 1024
OUT = Path(__file__).resolve().parent / "icon-1024.png"


def cubic(
    p0: tuple[float, float],
    p1: tuple[float, float],
    p2: tuple[float, float],
    p3: tuple[float, float],
    n: int = 48,
) -> list[tuple[float, float]]:
    pts: list[tuple[float, float]] = []
    for i in range(n):
        t = i / (n - 1)
        u = 1 - t
        x = u**3 * p0[0] + 3 * u**2 * t * p1[0] + 3 * u * t**2 * p2[0] + t**3 * p3[0]
        y = u**3 * p0[1] + 3 * u**2 * t * p1[1] + 3 * u * t**2 * p2[1] + t**3 * p3[1]
        pts.append((x, y))
    return pts


def heater_shield(cx: float, top: float, bottom: float, half: float) -> list[tuple[float, float]]:
    """Classic rounded heater shield, point at the bottom."""
    left, right = cx - half, cx + half
    mid_y = top + (bottom - top) * 0.42
    top_y = top + 18
    # top edge left -> right
    top_edge = cubic((left + 36, top_y + 36), (left + 90, top), (right - 90, top), (right - 36, top_y + 36), 40)
    right_side = cubic(
        (right - 36, top_y + 36),
        (right + 8, mid_y),
        (cx + half * 0.55, bottom - 90),
        (cx, bottom),
        64,
    )
    left_side = cubic(
        (cx, bottom),
        (cx - half * 0.55, bottom - 90),
        (left - 8, mid_y),
        (left + 36, top_y + 36),
        64,
    )
    return top_edge + right_side[1:] + left_side[1:]


def main() -> None:
    img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    margin = 40
    draw.rounded_rectangle(
        [margin, margin, SIZE - margin, SIZE - margin],
        radius=228,
        fill=(16, 42, 35, 255),
    )

    outer = heater_shield(512, 150, 910, 330)
    inner = heater_shield(512, 178, 880, 300)
    draw.polygon(outer, fill=(36, 96, 78, 255))
    draw.line(outer + [outer[0]], fill=(212, 168, 75, 255), width=18, joint="curve")
    draw.line(inner + [inner[0]], fill=(240, 208, 120, 255), width=6, joint="curve")

    # Keyhole ring
    cx, cy, r = 512, 430, 96
    draw.ellipse([cx - r, cy - r, cx + r, cy + r], outline=(240, 208, 120, 255), width=38)
    draw.ellipse([cx - 40, cy - 40, cx + 40, cy + 40], fill=(16, 42, 35, 255))

    stem = [
        (cx - 26, cy + 28),
        (cx + 26, cy + 28),
        (cx + 34, cy + 218),
        (cx + 16, cy + 258),
        (cx - 16, cy + 258),
        (cx - 34, cy + 218),
    ]
    draw.polygon(stem, fill=(240, 208, 120, 255))

    glow = img.filter(ImageFilter.GaussianBlur(0.8))
    out = Image.alpha_composite(glow, img)
    out.save(OUT, "PNG")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
