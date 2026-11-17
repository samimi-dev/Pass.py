# -*- coding: utf-8 -*-
"""Material Design 3 Light & Dark theme tokens for Pass.py."""

from typing import Dict


class ThemeManager:
    """Centralized color tokens and typography definitions."""

    THEMES: Dict[str, Dict[str, str]] = {
        "light": {
            "bg": "#F4F8F6",
            "surface": "#FFFFFF",
            "surface_alt": "#EBF5F0",
            "border": "#D5E5DC",
            "text": "#111827",
            "muted": "#4B5563",
            "primary": "#059669",
            "primary_fg": "#FFFFFF",
            "accent": "#EA580C",
            "accent_bg": "#FFF7ED",
            "danger": "#DC2626",
            "success": "#059669",
        },
        "dark": {
            "bg": "#0A120F",
            "surface": "#111C18",
            "surface_alt": "#182722",
            "border": "#223930",
            "text": "#ECFDF5",
            "muted": "#9CA3AF",
            "primary": "#059669",
            "primary_fg": "#FFFFFF",
            "accent": "#FB923C",
            "accent_bg": "#2A180D",
            "danger": "#DC2626",
            "success": "#10B981",
        },
    }
    FONT_UI = "Segoe UI"
    FONT_MONO = "Consolas"
    APP_VERSION = "v1.0.0"

    @classmethod
    def color(cls, theme_name: str, key: str) -> str:
        return cls.THEMES.get(theme_name, cls.THEMES["light"])[key]

    @staticmethod
    def lerp_hex(c1: str, c2: str, t: float) -> str:
        t_clamped = max(0.0, min(1.0, float(t)))
        if c1.upper() == c2.upper() or t_clamped <= 0.0:
            return c1 if t_clamped <= 0.0 else c2
        if t_clamped >= 1.0:
            return c2
        s1 = c1.lstrip("#")
        s2 = c2.lstrip("#")
        if len(s1) != 6 or len(s2) != 6:
            return c2
        r1, g1, b1 = int(s1[0:2], 16), int(s1[2:4], 16), int(s1[4:6], 16)
        r2, g2, b2 = int(s2[0:2], 16), int(s2[2:4], 16), int(s2[4:6], 16)
        r = round(r1 + (r2 - r1) * t_clamped)
        g = round(g1 + (g2 - g1) * t_clamped)
        b = round(b1 + (b2 - b1) * t_clamped)
        return f"#{r:02X}{g:02X}{b:02X}"

    @classmethod
    def interpolated_palette(cls, from_theme: str, to_theme: str, t: float) -> Dict[str, str]:
        p_from = cls.THEMES.get(from_theme, cls.THEMES["light"])
        p_to = cls.THEMES.get(to_theme, cls.THEMES["light"])
        return {key: cls.lerp_hex(p_from[key], p_to[key], t) for key in p_to}


THEMES = ThemeManager.THEMES
FONT_UI = ThemeManager.FONT_UI
FONT_MONO = ThemeManager.FONT_MONO
APP_VERSION = ThemeManager.APP_VERSION
