# -*- coding: utf-8 -*-
"""PNG, JPG, JPEG, and GIF site logo validation, normalization, and domain matching."""

import base64
import ctypes
import hashlib
import io
import math
import os
import re
import shutil
import struct
import sys
import tempfile
import zlib
from typing import Any, Dict, List, Optional, Tuple

from .assets import ALLOWED_IMAGE_EXTS, ALLOWED_IMAGE_MIMES, POPULAR_SITE_LOGOS
from .paths import LOGOS_DIR

try:
    from PIL import Image, ImageOps, ImageTk
    HAS_PILLOW = True
except ImportError:
    Image = None  # type: ignore
    ImageOps = None  # type: ignore
    ImageTk = None  # type: ignore
    HAS_PILLOW = False


class _GdiplusStartupInput(ctypes.Structure):
    _fields_ = [
        ("GdiplusVersion", ctypes.c_uint32),
        ("DebugEventCallback", ctypes.c_void_p),
        ("SuppressBackgroundThread", ctypes.c_int),
        ("SuppressExternalCodecs", ctypes.c_int),
    ]


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    ]


_PNG_CLSID = _GUID(
    0x557CF406,
    0x1A04,
    0x11D3,
    (ctypes.c_ubyte * 8)(0x9A, 0x73, 0x00, 0x00, 0xF8, 0x1E, 0xF3, 0x2E),
)


class _PropertyItem(ctypes.Structure):
    _fields_ = [
        ("id", ctypes.c_uint32),
        ("length", ctypes.c_uint32),
        ("type", ctypes.c_uint16),
        ("value", ctypes.c_void_p),
    ]


class ImageValidator:
    """Validates, normalizes (including JPG/JPEG -> PNG), and persists site logos & person avatars."""

    HAS_PILLOW = HAS_PILLOW
    MIME_TO_EXT = {
        "image/png": ".png",
        "image/jpeg": ".jpg",
        "image/gif": ".gif",
    }
    _GDIP_INIT_DONE = False

    @staticmethod
    def detect_mime(raw: bytes, filename: str = "") -> Optional[str]:
        ext = os.path.splitext(filename.lower())[1]
        if ext and ext not in ALLOWED_IMAGE_EXTS:
            return None
        if raw.startswith(b"\x89PNG\r\n\x1a\n"):
            return "image/png"
        if raw.startswith(b"\xff\xd8\xff"):
            return "image/jpeg"
        if raw.startswith((b"GIF87a", b"GIF89a")):
            return "image/gif"
        return None

    @classmethod
    def _ensure_gdip_signatures(cls, gdip: Any) -> None:
        if cls._GDIP_INIT_DONE:
            return
        gdip.GdiplusStartup.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(_GdiplusStartupInput), ctypes.c_void_p]
        gdip.GdiplusStartup.restype = ctypes.c_int
        gdip.GdiplusShutdown.argtypes = [ctypes.c_void_p]
        gdip.GdiplusShutdown.restype = None
        gdip.GdipLoadImageFromFile.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p)]
        gdip.GdipLoadImageFromFile.restype = ctypes.c_int
        gdip.GdipGetImageWidth.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        gdip.GdipGetImageWidth.restype = ctypes.c_int
        gdip.GdipGetImageHeight.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        gdip.GdipGetImageHeight.restype = ctypes.c_int
        gdip.GdipGetPropertyItemSize.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
        gdip.GdipGetPropertyItemSize.restype = ctypes.c_int
        gdip.GdipGetPropertyItem.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
        gdip.GdipGetPropertyItem.restype = ctypes.c_int
        gdip.GdipImageRotateFlip.argtypes = [ctypes.c_void_p, ctypes.c_int]
        gdip.GdipImageRotateFlip.restype = ctypes.c_int
        gdip.GdipCreateBitmapFromScan0.argtypes = [
            ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)
        ]
        gdip.GdipCreateBitmapFromScan0.restype = ctypes.c_int
        gdip.GdipGetImageGraphicsContext.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        gdip.GdipGetImageGraphicsContext.restype = ctypes.c_int
        gdip.GdipSetInterpolationMode.argtypes = [ctypes.c_void_p, ctypes.c_int]
        gdip.GdipSetInterpolationMode.restype = ctypes.c_int
        gdip.GdipDrawImageRectI.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int]
        gdip.GdipDrawImageRectI.restype = ctypes.c_int
        gdip.GdipDeleteGraphics.argtypes = [ctypes.c_void_p]
        gdip.GdipDeleteGraphics.restype = ctypes.c_int
        gdip.GdipSaveImageToFile.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.POINTER(_GUID), ctypes.c_void_p]
        gdip.GdipSaveImageToFile.restype = ctypes.c_int
        gdip.GdipDisposeImage.argtypes = [ctypes.c_void_p]
        gdip.GdipDisposeImage.restype = ctypes.c_int
        cls._GDIP_INIT_DONE = True

    @classmethod
    def _windows_convert_to_png(cls, raw: bytes, src_ext: str = ".jpg", max_dim: int = 256) -> Optional[bytes]:
        if sys.platform != "win32":
            return None
        try:
            gdip = ctypes.windll.gdiplus
            cls._ensure_gdip_signatures(gdip)
        except Exception:
            return None

        token = ctypes.c_void_p()
        startup = _GdiplusStartupInput(1, None, 0, 0)
        if gdip.GdiplusStartup(ctypes.byref(token), ctypes.byref(startup), None) != 0:
            return None

        tmpdir = tempfile.mkdtemp(prefix="passpy_img_")
        src_img = ctypes.c_void_p()
        scaled_img = ctypes.c_void_p()
        gfx = ctypes.c_void_p()
        try:
            in_path = os.path.join(tmpdir, f"input{src_ext}")
            out_path = os.path.join(tmpdir, "output.png")
            with open(in_path, "wb") as fh:
                fh.write(raw)
            if gdip.GdipLoadImageFromFile(in_path, ctypes.byref(src_img)) != 0 or not src_img:
                return None

            # Apply EXIF orientation tag (0x0112) when present (phone cameras, etc.)
            try:
                prop_sz = ctypes.c_uint32(0)
                if gdip.GdipGetPropertyItemSize(src_img, 0x0112, ctypes.byref(prop_sz)) == 0 and prop_sz.value >= ctypes.sizeof(_PropertyItem):
                    buf = ctypes.create_string_buffer(prop_sz.value)
                    if gdip.GdipGetPropertyItem(src_img, 0x0112, prop_sz.value, buf) == 0:
                        item = ctypes.cast(buf, ctypes.POINTER(_PropertyItem)).contents
                        if item.value and item.length >= 2:
                            orient = ctypes.cast(item.value, ctypes.POINTER(ctypes.c_uint16)).contents.value
                            rot_map = {2: 4, 3: 2, 4: 6, 5: 5, 6: 1, 7: 7, 8: 3}
                            rf = rot_map.get(orient)
                            if rf is not None:
                                gdip.GdipImageRotateFlip(src_img, rf)
            except Exception:
                pass

            w_val = ctypes.c_uint32(0)
            h_val = ctypes.c_uint32(0)
            gdip.GdipGetImageWidth(src_img, ctypes.byref(w_val))
            gdip.GdipGetImageHeight(src_img, ctypes.byref(h_val))
            iw, ih = max(1, int(w_val.value)), max(1, int(h_val.value))

            if max(iw, ih) > max_dim:
                scale = max_dim / float(max(iw, ih))
                nw = max(1, int(round(iw * scale)))
                nh = max(1, int(round(ih * scale)))
            else:
                nw, nh = iw, ih

            save_target = src_img
            # Normalize to clean 32bppARGB (non-interlaced RGBA PNG)
            if gdip.GdipCreateBitmapFromScan0(nw, nh, 0, 0x26200A, None, ctypes.byref(scaled_img)) == 0 and scaled_img:
                if gdip.GdipGetImageGraphicsContext(scaled_img, ctypes.byref(gfx)) == 0 and gfx:
                    gdip.GdipSetInterpolationMode(gfx, 7)
                    if gdip.GdipDrawImageRectI(gfx, src_img, 0, 0, nw, nh) == 0:
                        save_target = scaled_img

            if gdip.GdipSaveImageToFile(save_target, out_path, ctypes.byref(_PNG_CLSID), None) != 0:
                return None
            if os.path.isfile(out_path):
                with open(out_path, "rb") as out_fh:
                    return out_fh.read()
        except Exception:
            return None
        finally:
            # Dispose GDI+ images BEFORE removing tmpdir to prevent Win32 open file-handle locks
            if gfx:
                try:
                    gdip.GdipDeleteGraphics(gfx)
                except Exception:
                    pass
            if scaled_img:
                try:
                    gdip.GdipDisposeImage(scaled_img)
                except Exception:
                    pass
            if src_img:
                try:
                    gdip.GdipDisposeImage(src_img)
                except Exception:
                    pass
            if token:
                try:
                    gdip.GdiplusShutdown(token)
                except Exception:
                    pass
            shutil.rmtree(tmpdir, ignore_errors=True)
        return None

    @classmethod
    def convert_to_png_bytes(cls, raw: bytes, src_ext: str = ".jpg", max_dim: int = 256) -> Optional[bytes]:
        if HAS_PILLOW and Image is not None:
            try:
                with Image.open(io.BytesIO(raw)) as img:
                    if ImageOps is not None:
                        img = ImageOps.exif_transpose(img)
                    img.load()
                    if img.mode not in ("RGB", "RGBA"):
                        img = img.convert("RGBA")
                    if max(img.size) > max_dim:
                        img.thumbnail((max_dim, max_dim))
                    buf = io.BytesIO()
                    img.save(buf, format="PNG", optimize=True)
                    return buf.getvalue()
            except Exception:
                pass
        return cls._windows_convert_to_png(raw, src_ext=src_ext, max_dim=max_dim)

    @staticmethod
    def circularize_png_bytes(raw: bytes, size: int) -> Optional[bytes]:
        """Fast pure-Python center-cropped circular RGBA PNG resizer (zero external deps)."""
        if not raw.startswith(b"\x89PNG\r\n\x1a\n") or size <= 0:
            return None
        try:
            pos = 8
            w = h = bd = ct = interlace = 0
            plte = b""
            trns = b""
            idat = bytearray()
            while pos + 8 <= len(raw):
                length, ctype = struct.unpack(">I4s", raw[pos : pos + 8])
                data = raw[pos + 8 : pos + 8 + length]
                pos += 12 + length
                if ctype == b"IHDR":
                    w, h, bd, ct, _cm, _fm, interlace = struct.unpack(">IIBBBBB", data[:13])
                elif ctype == b"PLTE":
                    plte = data
                elif ctype == b"tRNS":
                    trns = data
                elif ctype == b"IDAT":
                    idat.extend(data)
                elif ctype == b"IEND":
                    break
            if w <= 0 or h <= 0 or bd != 8 or interlace != 0 or ct not in (0, 2, 3, 4, 6):
                return None

            bpp = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[ct]
            dec = zlib.decompress(bytes(idat))
            stride = w * bpp
            if len(dec) < h * (stride + 1):
                return None

            rgba = bytearray(w * h * 4)
            prev = bytearray(stride)
            idx = 0
            for y in range(h):
                ft = dec[idx]
                idx += 1
                row = bytearray(dec[idx : idx + stride])
                idx += stride
                if ft == 1:
                    for x in range(bpp, stride):
                        row[x] = (row[x] + row[x - bpp]) & 0xFF
                elif ft == 2:
                    for x in range(stride):
                        row[x] = (row[x] + prev[x]) & 0xFF
                elif ft == 3:
                    for x in range(stride):
                        a = row[x - bpp] if x >= bpp else 0
                        row[x] = (row[x] + ((a + prev[x]) >> 1)) & 0xFF
                elif ft == 4:
                    for x in range(stride):
                        a = row[x - bpp] if x >= bpp else 0
                        b = prev[x]
                        c = prev[x - bpp] if x >= bpp else 0
                        p = a + b - c
                        pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                        pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                        row[x] = (row[x] + pr) & 0xFF
                prev = row

                out_off = y * w * 4
                if ct == 6:
                    rgba[out_off : out_off + w * 4] = row
                elif ct == 2:
                    for x in range(w):
                        o = out_off + x * 4
                        s3 = x * 3
                        rgba[o], rgba[o + 1], rgba[o + 2], rgba[o + 3] = row[s3], row[s3 + 1], row[s3 + 2], 255
                elif ct == 0:
                    for x in range(w):
                        v = row[x]
                        o = out_off + x * 4
                        rgba[o], rgba[o + 1], rgba[o + 2], rgba[o + 3] = v, v, v, 255
                elif ct == 4:
                    for x in range(w):
                        v, a = row[x * 2], row[x * 2 + 1]
                        o = out_off + x * 4
                        rgba[o], rgba[o + 1], rgba[o + 2], rgba[o + 3] = v, v, v, a
                elif ct == 3:
                    plen = len(plte)
                    tlen = len(trns)
                    for x in range(w):
                        pi = row[x]
                        o = out_off + x * 4
                        if pi * 3 + 2 < plen:
                            rgba[o] = plte[pi * 3]
                            rgba[o + 1] = plte[pi * 3 + 1]
                            rgba[o + 2] = plte[pi * 3 + 2]
                        rgba[o + 3] = trns[pi] if pi < tlen else 255

            # Precompute horizontal/vertical interpolation LUTs for fast circular cropping
            side = min(w, h)
            ox = (w - side) * 0.5
            oy = (h - side) * 0.5
            cx = size * 0.5
            cy = size * 0.5
            radius = cx - 0.5
            sub = 2 if side > size * 1.5 else 1
            sub_inv = 1.0 / (sub * sub)

            x_lut = []
            for dx in range(size):
                row_s = []
                for sx in range(sub):
                    fx = ox + ((dx + (sx + 0.5) / sub) / size) * side - 0.5
                    x0 = max(0, min(w - 1, int(math.floor(fx))))
                    x1 = max(0, min(w - 1, x0 + 1))
                    tx = max(0.0, min(1.0, fx - x0))
                    row_s.append((x0 * 4, x1 * 4, 1.0 - tx, tx))
                x_lut.append(row_s)

            y_lut = []
            for dy in range(size):
                row_s = []
                for sy in range(sub):
                    fy = oy + ((dy + (sy + 0.5) / sub) / size) * side - 0.5
                    y0 = max(0, min(h - 1, int(math.floor(fy))))
                    y1 = max(0, min(h - 1, y0 + 1))
                    ty = max(0.0, min(1.0, fy - y0))
                    row_s.append((y0 * w * 4, y1 * w * 4, 1.0 - ty, ty))
                y_lut.append(row_s)

            out_raw = bytearray()
            mv = memoryview(rgba)
            for dy in range(size):
                out_raw.append(0)
                dy_off = (dy + 0.5) - cy
                ys = y_lut[dy]
                for dx in range(size):
                    dist = math.hypot((dx + 0.5) - cx, dy_off)
                    if dist >= radius + 0.5:
                        out_raw.extend((0, 0, 0, 0))
                        continue
                    mask = 1.0 if dist <= radius - 0.5 else max(0.0, min(1.0, radius + 0.5 - dist))
                    xs = x_lut[dx]
                    sr = sg = sb = sa = 0.0
                    for r0, r1, wy0, wy1 in ys:
                        for c0, c1, wx0, wx1 in xs:
                            i00 = r0 + c0
                            i10 = r0 + c1
                            i01 = r1 + c0
                            i11 = r1 + c1
                            w00 = wx0 * wy0
                            w10 = wx1 * wy0
                            w01 = wx0 * wy1
                            w11 = wx1 * wy1
                            sr += mv[i00] * w00 + mv[i10] * w10 + mv[i01] * w01 + mv[i11] * w11
                            sg += mv[i00 + 1] * w00 + mv[i10 + 1] * w10 + mv[i01 + 1] * w01 + mv[i11 + 1] * w11
                            sb += mv[i00 + 2] * w00 + mv[i10 + 2] * w10 + mv[i01 + 2] * w01 + mv[i11 + 2] * w11
                            sa += mv[i00 + 3] * w00 + mv[i10 + 3] * w10 + mv[i01 + 3] * w01 + mv[i11 + 3] * w11
                    out_raw.extend((
                        min(255, int(round(sr * sub_inv))),
                        min(255, int(round(sg * sub_inv))),
                        min(255, int(round(sb * sub_inv))),
                        min(255, int(round(sa * sub_inv * mask))),
                    ))

            def _chunk(tag: bytes, cdata: bytes) -> bytes:
                return struct.pack(">I", len(cdata)) + tag + cdata + struct.pack(">I", zlib.crc32(tag + cdata) & 0xFFFFFFFF)

            ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
            return b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", zlib.compress(bytes(out_raw), 6)) + _chunk(b"IEND", b"")
        except Exception:
            return None

    @classmethod
    def ensure_tk_compatible_b64(cls, b64_data: str, max_dim: int = 160) -> str:
        """Converts stored JPEG base64 into PNG base64 when needed so Tk PhotoImage always displays it."""
        if not b64_data:
            return ""
        try:
            raw = base64.b64decode(b64_data)
        except Exception:
            return b64_data
        if raw.startswith(b"\xff\xd8\xff"):
            png_raw = cls.convert_to_png_bytes(raw, src_ext=".jpg", max_dim=max_dim)
            if png_raw:
                return base64.b64encode(png_raw).decode("ascii")
        return b64_data

    @classmethod
    def validate_and_encode(cls, file_path: str, max_bytes: int = 2 * 1024 * 1024, max_dim: int = 256) -> Tuple[str, str]:
        ext = os.path.splitext(file_path.lower())[1]
        if ext not in ALLOWED_IMAGE_EXTS:
            raise ValueError("Only PNG, JPG, JPEG, and GIF image files are allowed.")
        with open(file_path, "rb") as fh:
            raw = fh.read()
        if not raw:
            raise ValueError("Selected image file is empty.")
        if len(raw) > max_bytes:
            raise ValueError("Image size must not exceed 2 MB.")
        mime = cls.detect_mime(raw, file_path)
        if mime not in ALLOWED_IMAGE_MIMES:
            raise ValueError("Invalid image header. Only valid PNG, JPG, JPEG, or GIF files are accepted.")

        if mime != "image/gif":
            src_ext = ".jpg" if mime == "image/jpeg" else ".png"
            png_raw = cls.convert_to_png_bytes(raw, src_ext=src_ext, max_dim=max_dim)
            if png_raw:
                raw = png_raw
                mime = "image/png"
        return mime, base64.b64encode(raw).decode("ascii")

    @classmethod
    def save_logo_file(cls, b64_data: str, mime_type: str, stem: str, logos_dir: str = LOGOS_DIR) -> str:
        """Writes an uploaded logo image into vault_data/logos/ and returns its filename."""
        if not b64_data:
            return ""
        ext = cls.MIME_TO_EXT.get(mime_type, ".png")
        safe_stem = re.sub(r"[^a-zA-Z0-9_-]", "", stem)[:48] or hashlib.sha1(b64_data[:64].encode("ascii", "ignore")).hexdigest()[:12]
        filename = f"{safe_stem}{ext}"
        os.makedirs(logos_dir, exist_ok=True)
        target = os.path.join(logos_dir, filename)
        raw = base64.b64decode(b64_data)
        with open(target, "wb") as fh:
            fh.write(raw)
        return filename

    @staticmethod
    def load_logo_b64(filename: str, logos_dir: str = LOGOS_DIR) -> str:
        if not filename:
            return ""
        safe_name = os.path.basename(filename)
        path = os.path.join(logos_dir, safe_name)
        if not os.path.isfile(path):
            return ""
        try:
            with open(path, "rb") as fh:
                return base64.b64encode(fh.read()).decode("ascii")
        except OSError:
            return ""

    @staticmethod
    def delete_logo_file(filename: str, logos_dir: str = LOGOS_DIR) -> None:
        if not filename:
            return
        safe_name = os.path.basename(filename)
        path = os.path.join(logos_dir, safe_name)
        try:
            if os.path.isfile(path):
                os.remove(path)
        except OSError:
            pass

    @staticmethod
    def match_logo_key(
        site_url: str,
        title: str = "",
        custom_logos: Optional[List[Dict[str, str]]] = None,
    ) -> str:
        haystack = f"{site_url} {title}".lower()
        if custom_logos:
            for cl in custom_logos:
                domains = [d.strip().lower() for d in cl.get("domain", "").split(",") if d.strip()]
                if any(re.search(rf"(^|[^a-z0-9]){re.escape(d)}($|[^a-z0-9])", haystack) for d in domains):
                    return f"custom:{cl['id']}"
        for key, info in POPULAR_SITE_LOGOS.items():
            domains = [d.strip() for d in info["domains"].split(",") if d.strip()]
            if any(re.search(rf"(^|[^a-z0-9]){re.escape(d)}($|[^a-z0-9])", haystack) for d in domains):
                return key
        return "globe"
