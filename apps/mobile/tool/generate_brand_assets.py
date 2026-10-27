"""Generate deterministic Android and Flutter assets from Hypha's master mark."""

from pathlib import Path

from PIL import Image, ImageFilter, ImageOps


ROOT = Path(__file__).resolve().parents[1]
ANDROID_RES = ROOT / "android" / "app" / "src" / "main" / "res"
REFERENCE = ROOT / "assets" / "branding" / "hypha-mark-reference.png"
MASTER = ROOT / "assets" / "branding" / "hypha-mark-v3-flat.png"
ICON_BACKGROUND = (252, 252, 251, 255)
LAUNCHER_VISIBLE_FRACTION = 0.43
OPTICAL_BOLDEN_KERNEL_SIZE = 5

DENSITIES = {
    "mdpi": 48,
    "hdpi": 72,
    "xhdpi": 96,
    "xxhdpi": 144,
    "xxxhdpi": 192,
}


def resized(image: Image.Image, size: int) -> Image.Image:
    return image.resize((size, size), Image.Resampling.LANCZOS)


def monochrome(image: Image.Image) -> Image.Image:
    alpha = image.getchannel("A")
    white = Image.new("RGBA", image.size, (255, 255, 255, 0))
    white.putalpha(alpha)
    return white


def extract_reference_mark() -> Image.Image:
    """Preserve the approved mark and add only slight small-size optical weight."""
    reference = Image.open(REFERENCE).convert("RGB")
    grayscale = ImageOps.grayscale(reference)
    alpha = grayscale.point(
        lambda value: 0 if value >= 250 else min(255, (250 - value) * 4)
    )
    alpha = alpha.filter(ImageFilter.MaxFilter(OPTICAL_BOLDEN_KERNEL_SIZE))
    alpha = alpha.filter(ImageFilter.GaussianBlur(0.6))
    mark = Image.new("RGBA", reference.size, (0, 0, 0, 0))
    mark.putalpha(alpha)
    return mark


def fit_visible_mark(image: Image.Image, fraction: float) -> Image.Image:
    """Keep the visible mark inside every Android launcher mask safe zone."""
    bounds = image.getchannel("A").getbbox()
    if bounds is None:
        raise ValueError("The Hypha mark is fully transparent.")
    target = image.crop(bounds)
    max_extent = round(min(image.size) * fraction)
    target.thumbnail((max_extent, max_extent), Image.Resampling.LANCZOS)
    canvas = Image.new("RGBA", image.size, (0, 0, 0, 0))
    x = (image.width - target.width) // 2
    y = (image.height - target.height) // 2
    canvas.alpha_composite(target, (x, y))
    return canvas


def notification_mark(image: Image.Image, size: int) -> Image.Image:
    alpha = image.getchannel("A")
    bounds = alpha.getbbox()
    if bounds is None:
        raise ValueError("The Hypha mark is fully transparent.")
    cropped = monochrome(image).crop(bounds)
    target = round(size * 0.78)
    cropped.thumbnail((target, target), Image.Resampling.LANCZOS)
    canvas = Image.new("RGBA", (size, size), (255, 255, 255, 0))
    x = (size - cropped.width) // 2
    y = (size - cropped.height) // 2
    canvas.alpha_composite(cropped, (x, y))
    return canvas


def save(image: Image.Image, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    image.save(path, "PNG", optimize=True)


def main() -> None:
    flat_mark = extract_reference_mark()
    save(flat_mark, MASTER)

    flat_launcher_mark = fit_visible_mark(flat_mark, LAUNCHER_VISIBLE_FRACTION)
    app_icon = Image.new("RGBA", flat_mark.size, ICON_BACKGROUND)
    app_icon.alpha_composite(flat_launcher_mark)
    save(resized(app_icon, 1024), ROOT / "assets" / "branding" / "hypha-app-icon.png")

    white_launcher_mark = monochrome(flat_launcher_mark)

    for density, launcher_size in DENSITIES.items():
        mipmap = ANDROID_RES / f"mipmap-{density}"
        drawable = ANDROID_RES / f"drawable-{density}"

        save(resized(app_icon, launcher_size), mipmap / "ic_launcher.png")
        save(resized(app_icon, launcher_size), mipmap / "ic_launcher_round.png")

        adaptive_size = round(launcher_size * 2.25)
        save(
            resized(flat_launcher_mark, adaptive_size),
            mipmap / "ic_launcher_foreground.png",
        )
        save(
            resized(white_launcher_mark, adaptive_size),
            mipmap / "ic_launcher_monochrome.png",
        )

        notification_size = max(24, round(24 * launcher_size / 48))
        save(
            notification_mark(flat_mark, notification_size),
            drawable / "ic_stat_hypha.png",
        )

    print("Generated Hypha launcher, adaptive, themed, and notification assets.")


if __name__ == "__main__":
    main()
