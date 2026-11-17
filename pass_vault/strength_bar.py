# -*- coding: utf-8 -*-
"""Reusable color-coded password strength indicator bar widget."""

from typing import Any, List, Optional

from .password_generator import PasswordGeneratorService
from .theme import FONT_UI, ThemeManager

try:
    import tkinter as tk
except ImportError:
    tk = None  # type: ignore


class PasswordStrengthBar:
    """Color-coded 4-segment password strength indicator."""

    def __init__(self, parent: Any, theme_name: str, bg_color: Optional[str] = None) -> None:
        bg = bg_color or ThemeManager.color(theme_name, "surface")
        muted = ThemeManager.color(theme_name, "muted")
        self._border = ThemeManager.color(theme_name, "border")
        self.frame = tk.Frame(parent, bg=bg)
        top_row = tk.Frame(self.frame, bg=bg)
        top_row.pack(fill="x", pady=(0, 4))
        tk.Label(top_row, text="Password Strength:", font=(FONT_UI, 8, "bold"), bg=bg, fg=muted).pack(side="left")
        self._lbl = tk.Label(top_row, text="Empty", font=(FONT_UI, 8, "bold"), bg=bg, fg=muted)
        self._lbl.pack(side="right")

        bar_row = tk.Frame(self.frame, bg=bg)
        bar_row.pack(fill="x")
        self._segs: List[Any] = []
        for idx in range(4):
            seg = tk.Frame(bar_row, bg=self._border, height=5)
            seg.pack(side="left", fill="x", expand=True, padx=(0 if idx == 0 else 4, 0))
            self._segs.append(seg)

    def update(self, pw: str) -> None:
        name, color, level = PasswordGeneratorService.evaluate_strength(pw)
        text = f"{name} ({len(pw)} chars)" if pw else "Empty"
        self._lbl.configure(text=text, fg=color)
        for i, seg in enumerate(self._segs):
            seg.configure(bg=color if i < level else self._border)
