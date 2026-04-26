"""Plain image I/O — never imports PIL.ImageMath, so CVE-2023-50447's
eval-based RCE has no path to fire."""
from PIL import Image


def make_thumbnail(src: str, dest: str, size: tuple[int, int] = (256, 256)) -> None:
    img = Image.open(src)
    img.thumbnail(size)
    img.save(dest)


def reformat(src: str, dest: str, fmt: str = "WEBP") -> None:
    Image.open(src).save(dest, format=fmt)
