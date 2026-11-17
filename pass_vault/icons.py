# -*- coding: utf-8 -*-
"""Persistent Tkinter PhotoImage cache and badge renderer for Pass.py."""

import base64
import hashlib
import io
from typing import Any, Dict, List, Optional

from .assets import EMBEDDED_ICONS
from .image_validator import HAS_PILLOW, Image, ImageTk, ImageValidator
from .paths import AVATARS_DIR
from .theme import FONT_UI

try:
    from PIL import ImageDraw, ImageOps  # type: ignore
except ImportError:
    ImageDraw = None  # type: ignore
    ImageOps = None  # type: ignore

try:
    import tkinter as tk
    HAS_TKINTER = True
except ImportError:
    tk = None  # type: ignore
    HAS_TKINTER = False


class IconLibrary:
    """Persistent Icon & Brand PhotoImage cache (prevents GC icon disappearing)."""

    def __init__(self) -> None:
        self._ui_cache: Dict[str, Any] = {}
        self._logo_cache: Dict[str, Any] = {}

    def clear_logo_cache(self) -> None:
        if len(self._logo_cache) > 128:
            self._logo_cache.clear()

    def get_ui_icon(self, name: str) -> Optional[Any]:
        b64 = EMBEDDED_ICONS.get("ui", {}).get(name)
        if not b64 or not HAS_TKINTER or tk is None:
            return None
        if name not in self._ui_cache:
            try:
                self._ui_cache[name] = tk.PhotoImage(data=b64)
            except Exception:
                return None
        return self._ui_cache[name]

    def get_named_photo(self, key: str) -> Optional[Any]:
        b64 = EMBEDDED_ICONS.get(key)
        if not b64 or not isinstance(b64, str) or not HAS_TKINTER or tk is None:
            return None
        cache_key = f"__named_{key}__"
        if cache_key not in self._ui_cache:
            try:
                self._ui_cache[cache_key] = tk.PhotoImage(data=b64)
            except Exception:
                return None
        return self._ui_cache[cache_key]

    def get_app_icon(self) -> Optional[Any]:
        return self.get_named_photo("appIcon")

    def get_person_avatar_photo(
        self,
        person: Optional[Dict[str, str]] = None,
        size: int = 24,
        fallback_ui_icon: str = "user",
        raw_b64: str = "",
    ) -> Optional[Any]:
        if not HAS_TKINTER or tk is None:
            return None

        resolved_b64 = raw_b64
        if not resolved_b64 and person is not None:
            resolved_b64 = person.get("avatar_b64", "")
            if not resolved_b64 and person.get("avatar_file"):
                resolved_b64 = ImageValidator.load_logo_b64(person["avatar_file"], logos_dir=AVATARS_DIR)

        if not resolved_b64:
            return self.get_ui_icon(fallback_ui_icon)

        cache_key = f"avatar_{hashlib.sha1(resolved_b64[:96].encode('ascii', 'ignore')).hexdigest()}_{len(resolved_b64)}_{size}"
        if cache_key in self._logo_cache:
            return self._logo_cache[cache_key]

        try:
            raw = base64.b64decode(resolved_b64)
            if HAS_PILLOW and Image is not None and ImageTk is not None:
                with Image.open(io.BytesIO(raw)) as img:
                    img = img.convert("RGBA")
                    resample = getattr(getattr(Image, "Resampling", Image), "LANCZOS", Image.BICUBIC)
                    if ImageOps is not None:
                        img = ImageOps.fit(img, (size, size), method=resample)
                    else:
                        img = img.resize((size, size), resample)
                    if ImageDraw is not None:
                        mask = Image.new("L", (size, size), 0)
                        draw = ImageDraw.Draw(mask)
                        draw.ellipse((0, 0, size - 1, size - 1), fill=255)
                        img.putalpha(mask)
                    photo = ImageTk.PhotoImage(img)
                    self._logo_cache[cache_key] = photo
                    return photo

            if raw.startswith(b"\xff\xd8\xff"):
                converted = ImageValidator.ensure_tk_compatible_b64(resolved_b64)
                if converted and converted != resolved_b64:
                    resolved_b64 = converted
                    raw = base64.b64decode(resolved_b64)

            if raw.startswith(b"\x89PNG\r\n\x1a\n"):
                circ_png = ImageValidator.circularize_png_bytes(raw, size)
                if circ_png:
                    photo = tk.PhotoImage(data=base64.b64encode(circ_png).decode("ascii"))
                    self._logo_cache[cache_key] = photo
                    return photo

            if raw.startswith(b"\x89PNG\r\n\x1a\n") or raw.startswith((b"GIF87a", b"GIF89a")):
                photo = tk.PhotoImage(data=resolved_b64)
                max_dim = max(photo.width(), photo.height(), 1)
                if max_dim > size:
                    factor = max(1, round(max_dim / size))
                    if factor > 1:
                        photo = photo.subsample(factor, factor)
                pw, ph = photo.width(), photo.height()
                if pw > 2 and ph > 2:
                    cx, cy = pw * 0.5, ph * 0.5
                    rad = min(pw, ph) * 0.5
                    for py in range(ph):
                        for px in range(pw):
                            if ((px + 0.5 - cx) ** 2 + (py + 0.5 - cy) ** 2) > (rad * rad):
                                photo.transparency_set(px, py, True)
                self._logo_cache[cache_key] = photo
                return photo
        except Exception:
            pass
        return self.get_ui_icon(fallback_ui_icon)

    def get_logo_photo(
        self,
        logo_key: str,
        custom_logo_b64: str,
        custom_logos: List[Dict[str, str]],
        size: int = 40,
        custom_logo_file: str = "",
    ) -> Optional[Any]:
        if not HAS_TKINTER or tk is None:
            return None

        resolved_b64 = custom_logo_b64
        if not resolved_b64 and custom_logo_file:
            resolved_b64 = ImageValidator.load_logo_b64(custom_logo_file)
        if not resolved_b64 and logo_key.startswith("custom:"):
            cid = logo_key.split(":", 1)[1]
            match = next((cl for cl in custom_logos if cl["id"] == cid), None)
            if match:
                resolved_b64 = match.get("data_b64", "") or ImageValidator.load_logo_b64(match.get("file_name", ""))

        if not resolved_b64:
            resolved_b64 = EMBEDDED_ICONS.get("site", {}).get(logo_key) or EMBEDDED_ICONS.get("site", {}).get("globe", "")

        if not resolved_b64:
            return None

        cache_key = f"{hashlib.sha1(resolved_b64[:96].encode('ascii', 'ignore')).hexdigest()}_{len(resolved_b64)}_{size}"
        if cache_key in self._logo_cache:
            return self._logo_cache[cache_key]

        try:
            raw = base64.b64decode(resolved_b64)
            if HAS_PILLOW and Image is not None and ImageTk is not None:
                with Image.open(io.BytesIO(raw)) as img:
                    img = img.convert("RGBA")
                    img.thumbnail((size, size))
                    photo = ImageTk.PhotoImage(img)
                    self._logo_cache[cache_key] = photo
                    return photo

            if raw.startswith(b"\xff\xd8\xff"):
                converted = ImageValidator.ensure_tk_compatible_b64(resolved_b64)
                if converted and converted != resolved_b64:
                    resolved_b64 = converted
                    raw = base64.b64decode(resolved_b64)

            if raw.startswith(b"\x89PNG\r\n\x1a\n") or raw.startswith((b"GIF87a", b"GIF89a")):
                photo = tk.PhotoImage(data=resolved_b64)
                max_dim = max(photo.width(), photo.height(), 1)
                if max_dim > size:
                    factor = max(1, round(max_dim / size))
                    if factor > 1:
                        photo = photo.subsample(factor, factor)
                self._logo_cache[cache_key] = photo
                return photo
        except Exception:
            return None
        return None

    def create_badge_label(
        self,
        parent: Any,
        logo_key: str,
        custom_logo_b64: str,
        custom_logos: List[Dict[str, str]],
        size: int = 38,
        custom_logo_file: str = "",
    ) -> Any:
        photo = self.get_logo_photo(logo_key, custom_logo_b64, custom_logos, size=size, custom_logo_file=custom_logo_file)
        if photo is not None:
            lbl = tk.Label(parent, image=photo, bg=parent["bg"], bd=0)
            lbl._img_ref = photo
            return lbl
        return tk.Label(
            parent,
            text="IMG" if (custom_logo_b64 or custom_logo_file) else logo_key[:3].upper(),
            font=(FONT_UI, 9, "bold"),
            bg="#ECFDF5",
            fg="#059669",
            width=4,
            height=2,
        )


LogoRenderer = IconLibrary
