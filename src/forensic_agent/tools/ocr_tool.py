"""OCR tool — wraps Tesseract (de-facto standard OCR), with image preprocessing.

Reads text rendered inside an image (e.g. a flag rasterized into a recovered
PNG/JPEG). Preprocessing (grayscale/threshold, red-channel isolation, upscaling)
makes it robust to coloured text on noisy backgrounds. Read-only.
"""
from __future__ import annotations

import os
import re

from forensic_agent.core.environ import tesseract_path
from forensic_agent.core.toolkit import run_external, scratch_dir

try:
    from PIL import Image, ImageChops, ImageOps
    _HAVE_PIL = True
except Exception:
    _HAVE_PIL = False

try:
    import numpy as _np
    _HAVE_NP = True
except Exception:
    _HAVE_NP = False

_WL = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_-"

_DEFAULT_LANG = "eng"
#: Tesseract's own ``-l`` grammar: one traineddata name, or several joined by "+".
#: The value becomes an argv element, so it is bounded before it is passed rather
#: than after Tesseract has been asked to interpret it.
_LANG_CODE = re.compile(r"[A-Za-z0-9_]{1,32}(?:\+[A-Za-z0-9_]{1,32}){0,7}")


def _color_mask_variants(path):
    """Isolate coloured text (red/green/blue dominant) into a clean dark-on-light binary,
    robust to a black/white noisy background — makes OCR deterministic on coloured flags
    that channel-mixing alone cannot read. Needs numpy."""
    if not (_HAVE_NP and _HAVE_PIL):
        return []
    im = _np.asarray(Image.open(path).convert("RGB")).astype(int)
    R, G, B = im[:, :, 0], im[:, :, 1], im[:, :, 2]
    out = []
    for name, dom, others in (("red", R, _np.maximum(G, B)),
                              ("green", G, _np.maximum(R, B)),
                              ("blue", B, _np.maximum(R, G))):
        domness = dom - others
        for thr in (60, 90):
            mask = domness > thr
            if int(mask.sum()) < 8:          # nothing of that colour — skip
                continue
            arr = _np.where(mask, 0, 255).astype("uint8")   # text dark on white
            img = Image.fromarray(arr).resize((im.shape[1] * 3, im.shape[0] * 3))
            out.append((f"{name}mask{thr}", img))
    return out


def _variants(path):
    """Yield (name, PIL.Image) preprocessing variants to improve recognition."""
    im = Image.open(path).convert("RGB")
    gray = ImageOps.grayscale(im)
    out = [("gray", gray),
           ("gray_auto", ImageOps.autocontrast(gray)),
           ("gray_thresh", gray.point(lambda x: 0 if x < 110 else 255))]
    # isolate coloured text (red / green / blue dominant) — flags are often coloured
    r, g, b = im.split()
    for name, ch, others in (("red", r, ImageChops.lighter(g, b)),
                             ("green", g, ImageChops.lighter(r, b)),
                             ("blue", b, ImageChops.lighter(r, g))):
        iso = ImageOps.autocontrast(ImageChops.subtract(ch, others))
        binimg = iso.point(lambda x: 255 if x > 60 else 0)
        out.append((name + "_iso", binimg))
        out.append((name + "_iso_inv", ImageOps.invert(binimg)))
    # upscale every variant 2x (helps small/low-res text)
    scaled = [(n + "_2x", v.resize((max(1, v.width * 2), max(1, v.height * 2)))) for n, v in out]
    return out + scaled


def _alnum_score(t):
    """Score by count of alphanumeric characters — rewards clean text, ignores symbol noise."""
    return len(re.sub(r"[^A-Za-z0-9]", "", t or ""))


def _run_tess(ts, img_path, lang, whitelist=False):
    """Read one image at four page-segmentation modes; return (best text, ran)."""
    best = ""
    ran = False
    for psm in ("6", "7", "8", "11"):
        cmd = [ts, img_path, "stdout", "-l", lang, "--psm", psm]
        if whitelist:
            cmd += ["-c", "tessedit_char_whitelist=" + _WL]
        try:
            p = run_external(cmd, timeout=60, check=False)
        except Exception:
            continue
        # Tesseract exits non-zero when it cannot load the language data, and then
        # prints nothing. That is a reading it never took, not a page with no text
        # on it, and the two must not reach the caller as the same answer.
        if int(getattr(p, "returncode", 0) or 0) != 0:
            continue
        ran = True
        t = (p.stdout or "").strip()
        if _alnum_score(t) > _alnum_score(best):
            best = t
    return best, ran


def ocr_image(image_path: str, lang: str = "eng") -> dict:
    """Extract text rendered inside an image with Tesseract OCR, trying several
    preprocessing variants (grayscale/threshold, colour-channel isolation,
    upscaling) for robustness on coloured text and noisy backgrounds. Use to read
    a flag or note rasterized into a recovered image; if OCR finds nothing, fall
    back to vision_read. Read-only.

    Example: ocr_image("C:/tmp/recovered.png")

    Input: `image_path` is the image file; `lang` is the Tesseract language code
    (default "eng"). Read-only over the evidence.

    Returns: {"image", "variant" (winning preprocessing variant), "text",
    "lines"} when text is found, or {"image", "text": "", "note"} when nothing
    is recognized. On failure returns {"error"}.
    """
    if not image_path or not os.path.exists(image_path):
        return {"error": "image not found at the given path."}
    # A directory exists, so existence alone let one through to Tesseract, which
    # answered "no text was recognized" — a reading of an image, about something
    # that is not one. Its host-path siblings say "not a file"; so does this.
    if not os.path.isfile(image_path):
        return {"error": f"not a file: {image_path}"}
    TS = tesseract_path()
    if not TS:
        return {"error": "Tesseract OCR not found. Install Tesseract-OCR, add it to PATH, "
                         "or set DFA_TESSERACT. Run `dfir-agent --doctor`."}
    language = str(lang or "").strip() or _DEFAULT_LANG
    if not _LANG_CODE.fullmatch(language):
        return {"error": f"lang must be one or more Tesseract language codes, e.g. 'eng': {lang!r}"}
    candidates = []
    read_attempted = False

    def read(name, path, *, whitelist=False):
        nonlocal read_attempted
        text, ran = _run_tess(TS, path, language, whitelist=whitelist)
        read_attempted = read_attempted or ran
        candidates.append((name, text))

    # 1) raw image
    read("raw", image_path)
    # 2) preprocessed variants
    if _HAVE_PIL:
        with scratch_dir("forensic_agent_ocr_") as tmp:
            try:
                for name, img in _variants(image_path):
                    fp = os.path.join(tmp, name + ".png")
                    try:
                        img.save(fp)
                    except Exception:
                        continue
                    read(name, fp)
                # 3) colour-isolation masks read with an alphanumeric whitelist — deterministic
                #    reading of coloured text on a noisy background (e.g. a rasterized flag)
                for name, img in _color_mask_variants(image_path):
                    fp = os.path.join(tmp, name + ".png")
                    try:
                        img.save(fp)
                    except Exception:
                        continue
                    read(name, fp, whitelist=True)
            except Exception:
                pass
    if not read_attempted:
        return {"error": f"Tesseract could not read this image in language '{language}'. "
                         "Check that the language data is installed (`tesseract --list-langs`); "
                         "nothing was recognized because nothing was read."}
    # pick the variant with the most alphanumeric characters (clean text beats symbol noise)
    best_name, best = max(candidates, key=lambda c: _alnum_score(c[1]))
    if not best.strip():
        return {"image": os.path.basename(image_path), "text": "", "lang": language,
                "note": "no text recognized even after preprocessing (try a vision model)."}
    return {"image": os.path.basename(image_path), "variant": best_name, "lang": language,
            "text": best[:4000],
            "lines": [ln for ln in best.splitlines() if ln.strip()][:50]}
