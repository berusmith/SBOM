"""Image-math compute service that takes a user formula and evaluates it
across image bands — directly hits CVE-2023-50447's eval-style RCE."""
from PIL import Image, ImageMath


def apply_formula(image_path: str, formula: str) -> Image.Image:
    img = Image.open(image_path).convert("RGB")
    r, g, b = img.split()
    # ImageMath.eval(expression, env) is the CVE-2023-50447 trigger —
    # `formula` originates from the request body in this service.
    out = ImageMath.eval(formula, {"r": r, "g": g, "b": b})
    return Image.merge("RGB", (out, out, out))
