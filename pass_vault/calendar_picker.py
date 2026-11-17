# -*- coding: utf-8 -*-
"""Interactive modal Calendar Date Picker widget (YYYY-MM-DD)."""

import calendar
import datetime
from typing import Any, Callable, Tuple

from .theme import FONT_UI, ThemeManager

try:
    import tkinter as tk
except ImportError:
    tk = None  # type: ignore


class CalendarDatePicker:
    """Modal Calendar Date Picker for credential Created Date fields."""

    @staticmethod
    def parse_initial_date(raw: str) -> datetime.date:
        clean = (raw or "").strip()
        if clean:
            try:
                return datetime.date.fromisoformat(clean)
            except ValueError:
                pass
        return datetime.date.today()

    @staticmethod
    def step_month(year: int, month: int, delta: int) -> Tuple[int, int]:
        total = year * 12 + (month - 1) + delta
        ny, nm0 = divmod(total, 12)
        return ny, nm0 + 1

    @classmethod
    def open(
        cls,
        parent_dialog: Any,
        theme_name: str,
        initial_str: str,
        on_picked: Callable[[str], None],
        center_fn: Callable[[Any, int, int, Any], None],
    ) -> None:
        selected_date = cls.parse_initial_date(initial_str)
        today = datetime.date.today()
        state = {"year": selected_date.year, "month": selected_date.month}

        c_bg = ThemeManager.color(theme_name, "surface")
        c_alt = ThemeManager.color(theme_name, "surface_alt")
        c_text = ThemeManager.color(theme_name, "text")
        c_muted = ThemeManager.color(theme_name, "muted")
        c_pri = ThemeManager.color(theme_name, "primary")
        c_pri_fg = ThemeManager.color(theme_name, "primary_fg")
        c_acc = ThemeManager.color(theme_name, "accent")

        pop = tk.Toplevel(parent_dialog)
        pop.title("Select Date")
        pop.configure(bg=c_bg)
        pop.transient(parent_dialog)
        center_fn(pop, 320, 345, parent_dialog)
        pop.grab_set()

        def _restore_grab(e: Any) -> None:
            if e.widget is pop and parent_dialog.winfo_exists():
                try:
                    parent_dialog.grab_set()
                except Exception:
                    pass

        pop.bind("<Destroy>", _restore_grab)

        nav = tk.Frame(pop, bg=c_bg, padx=12, pady=10)
        nav.pack(fill="x")
        title_lbl = tk.Label(nav, text="", font=(FONT_UI, 11, "bold"), bg=c_bg, fg=c_text)
        grid_frame = tk.Frame(pop, bg=c_bg, padx=12, pady=4)
        grid_frame.pack(fill="both", expand=True)

        def pick(d: datetime.date) -> None:
            on_picked(d.isoformat())
            pop.destroy()

        def render_month() -> None:
            for w in grid_frame.winfo_children():
                w.destroy()
            y, m = state["year"], state["month"]
            title_lbl.configure(text=f"{calendar.month_name[m]} {y}")

            for col_i, wk in enumerate(["Mo", "Tu", "We", "Th", "Fr", "Sa", "Su"]):
                tk.Label(grid_frame, text=wk, font=(FONT_UI, 8, "bold"), bg=c_bg, fg=c_muted, width=4).grid(row=0, column=col_i, pady=(0, 4))

            cal = calendar.Calendar(firstweekday=0)
            for r_i, week in enumerate(cal.monthdatescalendar(y, m), start=1):
                for c_i, day in enumerate(week):
                    in_month = day.month == m
                    is_sel = day == selected_date
                    is_today = day == today
                    bg_btn = c_pri if is_sel else (c_alt if in_month else c_bg)
                    fg_btn = c_pri_fg if is_sel else (c_acc if is_today else (c_text if in_month else c_muted))
                    b = tk.Button(
                        grid_frame,
                        text=str(day.day),
                        command=lambda d=day: pick(d),
                        font=(FONT_UI, 9, "bold" if (is_sel or is_today) else "normal"),
                        bg=bg_btn,
                        fg=fg_btn,
                        activebackground=c_pri,
                        activeforeground=c_pri_fg,
                        relief="flat",
                        width=3,
                        pady=3,
                        cursor="hand2",
                    )
                    b.grid(row=r_i, column=c_i, padx=2, pady=2)

        def move(delta_months: int) -> None:
            ny, nm = cls.step_month(state["year"], state["month"], delta_months)
            state["year"], state["month"] = ny, nm
            render_month()

        tk.Button(nav, text="<<", command=lambda: move(-12), bg=c_alt, fg=c_text, relief="flat", width=3, cursor="hand2").pack(side="left", padx=(0, 3))
        tk.Button(nav, text="<", command=lambda: move(-1), bg=c_alt, fg=c_text, relief="flat", width=3, cursor="hand2").pack(side="left")
        title_lbl.pack(side="left", expand=True)
        tk.Button(nav, text=">", command=lambda: move(1), bg=c_alt, fg=c_text, relief="flat", width=3, cursor="hand2").pack(side="right")
        tk.Button(nav, text=">>", command=lambda: move(12), bg=c_alt, fg=c_text, relief="flat", width=3, cursor="hand2").pack(side="right", padx=(3, 0))

        foot = tk.Frame(pop, bg=c_bg, padx=12, pady=10)
        foot.pack(fill="x", side="bottom")
        tk.Button(foot, text="Today", command=lambda: pick(today), font=(FONT_UI, 9, "bold"), bg=c_pri, fg=c_pri_fg, relief="flat", padx=12, pady=5, cursor="hand2").pack(side="left")
        tk.Button(foot, text="Clear", command=lambda: (on_picked(""), pop.destroy()), font=(FONT_UI, 9), bg=c_alt, fg=c_text, relief="flat", padx=12, pady=5, cursor="hand2").pack(side="left", padx=6)
        tk.Button(foot, text="Cancel", command=pop.destroy, font=(FONT_UI, 9), bg=c_alt, fg=c_text, relief="flat", padx=12, pady=5, cursor="hand2").pack(side="right")
        render_month()
