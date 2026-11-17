# -*- coding: utf-8 -*-
"""Bounded downward-only scroll & auto-hiding scrollbar manager."""

from typing import Any, Callable, Optional


class ScrollHelper:
    """Prevents unwanted upward scrolling and hides scrollbars unless content overflows."""

    @staticmethod
    def compute_wheel_step(num: Optional[int], delta: int, top_frac: float, bot_frac: float) -> int:
        if top_frac <= 0.001 and bot_frac >= 0.999:
            return 0
        if num == 4:
            step = -1
        elif num == 5:
            step = 1
        elif delta:
            step = int(-1 * (delta / 120))
            if step == 0:
                step = -1 if delta > 0 else 1
        else:
            return 0
        if step < 0 and top_frac <= 0.001:
            return 0
        if step > 0 and bot_frac >= 0.999:
            return 0
        return step

    @staticmethod
    def bind_bounded_scroll(
        canvas: Any,
        body: Any,
        scrollbar: Any,
        register_cb: Callable[[Any], None],
    ) -> None:
        win_id = canvas.create_window((0, 0), window=body, anchor="nw")
        pack_state = {"shown": False}

        def sync_layout(_event: Any = None) -> None:
            try:
                if not canvas.winfo_exists() or not body.winfo_exists():
                    return
                cw = max(1, canvas.winfo_width())
                ch = max(1, canvas.winfo_height())
                canvas.itemconfigure(win_id, width=cw)
                req_h = max(0, body.winfo_reqheight())
                canvas.configure(scrollregion=(0, 0, cw, max(req_h, ch)))
                needs_scroll = req_h > (ch + 2)
                if needs_scroll and not pack_state["shown"]:
                    scrollbar.pack(side="right", fill="y")
                    pack_state["shown"] = True
                elif not needs_scroll and pack_state["shown"]:
                    scrollbar.pack_forget()
                    pack_state["shown"] = False
                    canvas.yview_moveto(0.0)
                elif not needs_scroll:
                    canvas.yview_moveto(0.0)
            except Exception:
                pass

        body.bind("<Configure>", sync_layout)
        canvas.bind("<Configure>", sync_layout)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        canvas.after_idle(sync_layout)
        register_cb(canvas)
