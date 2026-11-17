# -*- coding: utf-8 -*-
"""Graphical rounded Light/Dark Day-Night theme switcher widget."""

from typing import Any, Callable

from .icons import IconLibrary
from .theme import APP_VERSION, FONT_UI, ThemeManager

try:
    import tkinter as tk
except ImportError:
    tk = None  # type: ignore


class ThemeSwitchWidget:
    """Graphical Light/Dark toggle widget with version footer for sidebar."""

    def __init__(
        self,
        parent: Any,
        icons: IconLibrary,
        theme_name: str,
        collapsed: bool,
        on_select_theme: Callable[[str], None],
    ) -> None:
        self._icons = icons
        self._collapsed = collapsed
        self._on_select = on_select_theme
        self._badge_btn: Optional[Any] = None
        self._canvas: Optional[Any] = None
        self._img_item: Optional[int] = None
        self._light_txt_item: Optional[int] = None
        self._dark_txt_item: Optional[int] = None

        surface = ThemeManager.color(theme_name, "surface")
        text_col = ThemeManager.color(theme_name, "text")
        muted_col = ThemeManager.color(theme_name, "muted")

        if collapsed:
            badge_key = "themeBadgeDark" if theme_name == "dark" else "themeBadgeLight"
            photo = icons.get_named_photo(badge_key)
            if photo is not None:
                btn = tk.Button(
                    parent,
                    image=photo,
                    command=lambda: on_select_theme("dark" if theme_name == "light" else "light"),
                    bg=surface,
                    activebackground=surface,
                    bd=0,
                    highlightthickness=0,
                    cursor="hand2",
                )
                btn._img_ref = photo
                btn.pack(anchor="center")
                self._badge_btn = btn
            self._ver_lbl = tk.Label(
                parent,
                text=APP_VERSION,
                font=(FONT_UI, 8),
                bg=surface,
                fg=muted_col,
            )
            self._ver_lbl.pack(anchor="center", pady=(4, 0))
            return

        photo = icons.get_named_photo("themeSwitchDark" if theme_name == "dark" else "themeSwitchLight")
        canvas = tk.Canvas(
            parent,
            width=208,
            height=44,
            bg=surface,
            highlightthickness=0,
            bd=0,
            cursor="hand2",
        )
        canvas.pack(anchor="center", pady=(0, 4))
        self._canvas = canvas
        if photo is not None:
            canvas._img_ref = photo
            self._img_item = canvas.create_image(104, 22, image=photo, anchor="center")
            is_light = theme_name == "light"
            self._light_txt_item = canvas.create_text(
                62, 22, text="Light",
                font=(FONT_UI, 9, "bold" if is_light else "normal"),
                fill="#111827" if is_light else muted_col,
            )
            self._dark_txt_item = canvas.create_text(
                164, 22, text="Dark",
                font=(FONT_UI, 9, "bold" if not is_light else "normal"),
                fill="#ECFDF5" if not is_light else muted_col,
            )
        else:
            canvas.create_text(104, 22, text=f"Theme: {theme_name.title()}", fill=text_col, font=(FONT_UI, 9, "bold"))

        canvas.bind("<Button-1>", lambda event: on_select_theme("light" if event.x < 104 else "dark"))
        self._ver_lbl = tk.Label(
            parent,
            text=APP_VERSION,
            font=(FONT_UI, 8),
            bg=surface,
            fg=muted_col,
        )
        self._ver_lbl.pack(anchor="center", pady=(2, 0))

    def update_theme_visual(self, target_theme: str, surface_hex: str, muted_hex: str, swap_graphic: bool = False) -> None:
        if hasattr(self, "_ver_lbl") and self._ver_lbl.winfo_exists():
            self._ver_lbl.configure(bg=surface_hex, fg=muted_hex)
        if self._collapsed:
            if self._badge_btn is not None and self._badge_btn.winfo_exists():
                self._badge_btn.configure(bg=surface_hex, activebackground=surface_hex)
                if swap_graphic:
                    badge_key = "themeBadgeDark" if target_theme == "dark" else "themeBadgeLight"
                    photo = self._icons.get_named_photo(badge_key)
                    if photo is not None:
                        self._badge_btn.configure(
                            image=photo,
                            command=lambda: self._on_select("dark" if target_theme == "light" else "light"),
                        )
                        self._badge_btn._img_ref = photo
            return

        if self._canvas is not None and self._canvas.winfo_exists():
            self._canvas.configure(bg=surface_hex)
            if swap_graphic:
                is_light = target_theme == "light"
                photo = self._icons.get_named_photo("themeSwitchLight" if is_light else "themeSwitchDark")
                if photo is not None and self._img_item is not None:
                    self._canvas._img_ref = photo
                    self._canvas.itemconfigure(self._img_item, image=photo)
                if self._light_txt_item is not None:
                    self._canvas.itemconfigure(
                        self._light_txt_item,
                        font=(FONT_UI, 9, "bold" if is_light else "normal"),
                        fill="#111827" if is_light else muted_hex,
                    )
                if self._dark_txt_item is not None:
                    self._canvas.itemconfigure(
                        self._dark_txt_item,
                        font=(FONT_UI, 9, "bold" if not is_light else "normal"),
                        fill="#ECFDF5" if not is_light else muted_hex,
                    )
