# -*- coding: utf-8 -*-
"""Main PassVaultApp desktop window, lock screen, unified sidebar, list & detail panes."""

import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from .dialogs_entries import VaultEntryDialogsMixin
from .dialogs_security import VaultSecurityDialogsMixin
from .icons import IconLibrary
from .recovery import RecoveryEmailService
from .repository import VaultRepository
from .scroll_helper import ScrollHelper
from .security import SecurityService
from .strength_bar import PasswordStrengthBar
from .theme import FONT_MONO, FONT_UI, ThemeManager
from .theme_switch import ThemeSwitchWidget
from .windows_auth import WindowsAuthService

try:
    import tkinter as tk
    from tkinter import messagebox, ttk
    HAS_TKINTER = True
except ImportError:
    tk = None  # type: ignore
    messagebox = None  # type: ignore
    ttk = None  # type: ignore
    HAS_TKINTER = False

_TK_BASE = tk.Tk if HAS_TKINTER and tk is not None else object


class PassVaultApp(VaultEntryDialogsMixin, VaultSecurityDialogsMixin, _TK_BASE):  # type: ignore[misc]
    """Pure Python OOP Desktop Application for Pass.py."""

    def __init__(self) -> None:
        if not HAS_TKINTER or tk is None:
            raise RuntimeError("Tkinter is required to run the Pass.py desktop UI.")
        super().__init__()
        self.title("Pass.py — Offline Encrypted Password Manager")
        self.geometry("1200x740")
        self.minsize(900, 540)

        self.db = VaultRepository()
        self.logos = IconLibrary()
        self.dek: Optional[bytes] = None
        self.entries: List[Dict[str, Any]] = []
        self.people: List[Dict[str, str]] = []
        self.categories: List[str] = []
        self.custom_logos: List[Dict[str, str]] = []
        self.selected_entry_id: Optional[str] = None
        self.reveal_password = False
        self.sidebar_collapsed = False
        self.people_expanded = True
        self.active_sidebar_item = "all"
        self._people_anim_job: Optional[str] = None
        self._people_clip: Optional[Any] = None
        self._people_inner: Optional[Any] = None
        self._people_chevron_btn: Optional[Any] = None
        self._people_all_row: Optional[Any] = None
        self._sb_canvas: Optional[Any] = None
        self._theme_anim_job: Optional[str] = None
        self._theme_switch_widget: Optional[Any] = None
        self._brand_lockup_lbl: Optional[Any] = None
        self._secret_val_lbl: Optional[Any] = None
        self._secret_toggle_btn: Optional[Any] = None
        self._secret_raw_val: str = ""
        self._last_copied_secret: str = ""

        app_icon = self.logos.get_app_icon()
        if app_icon is not None:
            self._app_icon_ref = app_icon
            self.iconphoto(True, app_icon)

        self.filter_favorites = False
        self.filter_person = "all"
        self.filter_category = "all"
        self.filter_tag = "all"
        self.sort_by = "updated_desc"
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._on_search_changed())

        settings = self.db.get_settings() if self.db.is_initialized() else {}
        self.theme_name = settings.get("theme", "light")
        self.last_activity = time.monotonic()
        self._clipboard_clear_job: Optional[str] = None
        self._wheel_canvases: List[Any] = []
        self.bind_all("<Any-KeyPress>", self._mark_activity)
        self.bind_all("<Any-ButtonPress>", self._mark_activity)
        self.bind_all("<MouseWheel>", self._dispatch_mousewheel)
        self.bind_all("<Button-4>", self._dispatch_mousewheel)
        self.bind_all("<Button-5>", self._dispatch_mousewheel)
        for _seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self.bind_class("TCombobox", _seq, self._on_combobox_mousewheel)
        self.protocol("WM_DELETE_WINDOW", self._on_close_requested)

        self._apply_ttk_theme()
        self.main_container = tk.Frame(self, bg=self._c("bg"))
        self.main_container.pack(fill="both", expand=True)

        self.show_lock_screen()
        self.after(5000, self._check_auto_lock)

    def _clear_secret_clipboard(self) -> None:
        if self._clipboard_clear_job is not None:
            try:
                self.after_cancel(self._clipboard_clear_job)
            except Exception:
                pass
            self._clipboard_clear_job = None
        if self._last_copied_secret:
            try:
                if self.clipboard_get() == self._last_copied_secret:
                    self.clipboard_clear()
            except Exception:
                pass
            self._last_copied_secret = ""

    def _on_close_requested(self) -> None:
        settings = self.db.get_settings() if self.db.is_initialized() else {}
        if bool(settings.get("confirm_on_close", True)):
            if not messagebox.askyesno("Confirm Exit", "Are you sure you want to exit Pass.py?", parent=self):
                return
        self._clear_secret_clipboard()
        self._secret_raw_val = ""
        self.dek = None
        try:
            self.db.conn.close()
        except Exception:
            pass
        self.destroy()

    def _c(self, key: str) -> str:
        return ThemeManager.color(self.theme_name, key)

    def _icon(self, name: str) -> Optional[Any]:
        return self.logos.get_ui_icon(name)

    def _btn(self, parent: Any, icon_name: Optional[str] = None, custom_image: Optional[Any] = None, **kwargs: Any) -> Any:
        icon = custom_image if custom_image is not None else (self._icon(icon_name) if icon_name else None)
        if icon is not None:
            kwargs["image"] = icon
            if "text" in kwargs and "compound" not in kwargs:
                kwargs["compound"] = "left"
        kwargs.setdefault("activebackground", kwargs.get("bg", self._c("surface_alt")))
        kwargs.setdefault("activeforeground", kwargs.get("fg", self._c("text")))
        btn = tk.Button(parent, **kwargs)
        if icon is not None:
            btn._img_ref = icon
        return btn

    def _on_combobox_mousewheel(self, event: Any) -> str:
        self._dispatch_mousewheel(event)
        return "break"

    def _dispatch_mousewheel(self, event: Any) -> None:
        try:
            self._wheel_canvases = [c for c in self._wheel_canvases if c.winfo_exists()]
            if not self._wheel_canvases:
                return
            widget = self.winfo_containing(event.x_root, event.y_root)
            if widget is None:
                return
            grabbed = self.grab_current()
            grab_top = grabbed.winfo_toplevel() if grabbed is not None else None
            if grab_top is not None and widget.winfo_toplevel() is not grab_top:
                return

            if isinstance(widget, tk.Text):
                t_top, t_bot = widget.yview()
                step = ScrollHelper.compute_wheel_step(getattr(event, "num", None), getattr(event, "delta", 0), t_top, t_bot)
                if step != 0:
                    widget.yview_scroll(step, "units")
                    return

            canvas_set = set(self._wheel_canvases)
            cur = widget
            target = None
            while cur is not None:
                if cur in canvas_set:
                    target = cur
                    break
                cur = getattr(cur, "master", None)
            if target is None:
                return

            top_frac, bot_frac = target.yview()
            step = ScrollHelper.compute_wheel_step(
                getattr(event, "num", None),
                getattr(event, "delta", 0),
                top_frac,
                bot_frac,
            )
            if step != 0:
                target.yview_scroll(step, "units")
        except Exception:
            pass

    def _enable_mousewheel(self, canvas: Any, scope: Any) -> None:
        if canvas not in self._wheel_canvases:
            self._wheel_canvases.append(canvas)
        scope.bind(
            "<Destroy>",
            lambda e: self._wheel_canvases.remove(canvas)
            if e.widget is scope and canvas in self._wheel_canvases
            else None,
        )

    def _apply_ttk_theme(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(
            "TCombobox",
            fieldbackground=self._c("surface_alt"),
            background=self._c("surface"),
            foreground=self._c("text"),
            arrowcolor=self._c("primary"),
            bordercolor=self._c("border"),
            padding=5,
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", self._c("surface_alt"))],
            foreground=[("readonly", self._c("text"))],
        )

    def _mark_activity(self, _event: Any = None) -> None:
        self.last_activity = time.monotonic()

    def _check_auto_lock(self) -> None:
        if self.dek is not None:
            settings = self.db.get_settings()
            minutes = int(settings.get("auto_lock_minutes", 5) or 0)
            if minutes > 0 and (time.monotonic() - self.last_activity) >= minutes * 60:
                self.lock_vault()
        self.after(5000, self._check_auto_lock)

    def clear_container(self) -> None:
        for w in self.main_container.winfo_children():
            w.destroy()

    def lock_vault(self) -> None:
        for job_attr in ("_theme_anim_job", "_people_anim_job"):
            job = getattr(self, job_attr, None)
            if job is not None:
                try:
                    self.after_cancel(job)
                except Exception:
                    pass
                setattr(self, job_attr, None)
        for child in list(self.winfo_children()):
            if isinstance(child, tk.Toplevel):
                try:
                    child.destroy()
                except Exception:
                    pass
        self._clear_secret_clipboard()
        self._secret_raw_val = ""
        self._secret_val_lbl = None
        self._secret_toggle_btn = None
        self.dek = None
        self.entries = []
        self.selected_entry_id = None
        self.reveal_password = False
        self.show_lock_screen()

    def _center_dialog(self, dlg: Any, width: int, height: int, parent: Optional[Any] = None) -> None:
        anchor = parent or self
        try:
            anchor.update_idletasks()
            px = anchor.winfo_rootx()
            py = anchor.winfo_rooty()
            pw = anchor.winfo_width()
            ph = anchor.winfo_height()
            if pw < 50 or ph < 50:
                sw, sh = dlg.winfo_screenwidth(), dlg.winfo_screenheight()
                x = max(0, (sw - width) // 2)
                y = max(0, (sh - height) // 2)
            else:
                x = px + (pw - width) // 2
                y = py + (ph - height) // 2
            sw, sh = dlg.winfo_screenwidth(), dlg.winfo_screenheight()
            x = max(12, min(x, max(12, sw - width - 12)))
            y = max(12, min(y, max(12, sh - height - 40)))
            dlg.geometry(f"{width}x{height}+{x}+{y}")
        except Exception:
            dlg.geometry(f"{width}x{height}")

    def _create_strength_meter(self, parent: Any, bg_color: Optional[str] = None) -> Tuple[Callable[[str], None], Any]:
        bar = PasswordStrengthBar(parent, self.theme_name, bg_color)
        return bar.update, bar.frame

    def _create_scrollable_dialog(self, title: str, width: int, height: int, has_footer: bool = False) -> Tuple[Any, Any, Optional[Any]]:
        dlg = tk.Toplevel(self)
        dlg.title(title)
        dlg.minsize(400, 340)
        dlg.configure(bg=self._c("surface"))
        dlg.transient(self)
        self._center_dialog(dlg, width, height, parent=self)
        dlg.grab_set()

        footer = None
        if has_footer:
            footer = tk.Frame(dlg, bg=self._c("surface"), padx=20, pady=12)
            footer.pack(side="bottom", fill="x")
            tk.Frame(dlg, bg=self._c("border"), height=1).pack(side="bottom", fill="x")

        outer = tk.Frame(dlg, bg=self._c("surface"))
        outer.pack(side="top", fill="both", expand=True)

        canvas = tk.Canvas(outer, bg=self._c("surface"), highlightthickness=0, bd=0)
        scrollbar = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        body = tk.Frame(canvas, bg=self._c("surface"), padx=22, pady=16)

        ScrollHelper.bind_bounded_scroll(
            canvas,
            body,
            scrollbar,
            lambda c: self._enable_mousewheel(c, dlg),
        )
        return dlg, body, footer

    def _show_recovery_key_modal(self, recovery_key: str, masked_email: str, parent_win: Optional[Any] = None) -> None:
        host = parent_win or self
        pop = tk.Toplevel(self)
        pop.title("Save Your Recovery Key")
        pop.configure(bg=self._c("surface"))
        pop.transient(host)
        self._center_dialog(pop, 450, 290, parent=host)
        pop.grab_set()

        def _restore_grab(e: Any) -> None:
            if e.widget is pop and parent_win is not None and parent_win.winfo_exists():
                try:
                    parent_win.grab_set()
                except Exception:
                    pass

        pop.bind("<Destroy>", _restore_grab)

        tk.Label(pop, text="Recovery Key Generated", font=(FONT_UI, 14, "bold"), bg=self._c("surface"), fg=self._c("primary")).pack(pady=(18, 6))
        tk.Label(
            pop,
            text=f"Recovery Email: {masked_email}\nWrite down or copy this Recovery Key. It is NEVER stored in plain text.",
            font=(FONT_UI, 9),
            bg=self._c("surface"),
            fg=self._c("muted"),
            wraplength=400,
            justify="center",
        ).pack(padx=20, pady=(0, 12))

        tk.Label(
            pop,
            text=recovery_key,
            font=(FONT_MONO, 14, "bold"),
            bg=self._c("surface_alt"),
            fg=self._c("text"),
            pady=12,
            padx=14,
        ).pack(fill="x", padx=28, pady=(0, 14))

        btn_row = tk.Frame(pop, bg=self._c("surface"))
        btn_row.pack(fill="x", padx=28)
        self._btn(
            btn_row,
            icon_name="copy",
            text="  Copy Recovery Key",
            command=lambda: self.copy_text(recovery_key, clear_after=60, parent=pop),
            font=(FONT_UI, 9, "bold"),
            bg=self._c("surface_alt"),
            fg=self._c("text"),
            relief="flat",
            padx=12,
            pady=8,
            cursor="hand2",
        ).pack(side="left", fill="x", expand=True, padx=(0, 6))
        tk.Button(
            btn_row,
            text="Done",
            command=pop.destroy,
            font=(FONT_UI, 9, "bold"),
            bg=self._c("primary"),
            fg=self._c("primary_fg"),
            relief="flat",
            padx=18,
            pady=8,
            cursor="hand2",
        ).pack(side="right")

    # ------------------------------------------------------------------
    # Lock / Setup Screen (Clean Logo + Email Recovery)
    # ------------------------------------------------------------------
    def _render_brand_lockup(self, parent: Any, large: bool = True) -> Any:
        is_dark = self.theme_name == "dark"
        key = ("brandLogoLargeDark" if is_dark else "brandLogoLarge") if large else ("brandLogoSmallDark" if is_dark else "brandLogoSmall")
        wordmark = self.logos.get_named_photo(key)
        if wordmark is not None:
            lbl = tk.Label(parent, image=wordmark, bg=self._c("surface"), bd=0)
            lbl._img_ref = wordmark
            lbl._brand_large = large
            self._brand_lockup_lbl = lbl
            return lbl
        row = tk.Frame(parent, bg=self._c("surface"))
        f_size = 24 if large else 15
        tk.Label(row, text="Pass", font=(FONT_UI, f_size, "bold"), bg=self._c("surface"), fg=self._c("primary")).pack(side="left")
        tk.Label(row, text=".py", font=(FONT_UI, f_size, "bold"), bg=self._c("surface"), fg=self._c("accent")).pack(side="left")
        return row

    def show_lock_screen(self) -> None:
        self.clear_container()
        self.main_container.configure(bg=self._c("bg"))

        card = tk.Frame(
            self.main_container,
            bg=self._c("surface"),
            highlightbackground=self._c("border"),
            highlightthickness=1,
            padx=36,
            pady=28,
        )
        card.place(relx=0.5, rely=0.5, anchor="center", width=470)

        initialized = self.db.is_initialized()
        meta = self.db.get_meta() or {}
        auth_mode = meta.get("auth_mode", "custom")

        self._render_brand_lockup(card, large=True).pack(pady=(0, 10))

        subtitle = (
            "Create your vault"
            if not initialized
            else ("Unlock with Windows password" if auth_mode == "windows" else "Enter your password")
        )
        tk.Label(card, text=subtitle, font=(FONT_UI, 10), bg=self._c("surface"), fg=self._c("text"), wraplength=390).pack(pady=(2, 12))

        mode_var = tk.StringVar(value=auth_mode)
        win_user_row = tk.Frame(card, bg=self._c("surface_alt"), padx=12, pady=7)
        win_user_icon = self._icon("user")
        if win_user_icon is not None:
            wu_ic = tk.Label(win_user_row, image=win_user_icon, bg=self._c("surface_alt"))
            wu_ic._img_ref = win_user_icon
            wu_ic.pack(side="left", padx=(0, 6))
        tk.Label(
            win_user_row,
            text=f"User: {WindowsAuthService.current_username()}",
            font=(FONT_UI, 9, "bold"),
            bg=self._c("surface_alt"),
            fg=self._c("text"),
            anchor="w",
        ).pack(side="left", fill="x", expand=True)

        recovery_wrap = tk.Frame(card, bg=self._c("surface"))
        recovery_email_var = tk.StringVar()
        if not initialized:
            tk.Label(
                recovery_wrap,
                text="Recovery Email (optional, for Forgot Password):",
                font=(FONT_UI, 8, "bold"),
                bg=self._c("surface"),
                fg=self._c("muted"),
                anchor="w",
            ).pack(fill="x", pady=(6, 2))
            tk.Entry(
                recovery_wrap,
                textvariable=recovery_email_var,
                font=(FONT_UI, 10),
                bg=self._c("surface_alt"),
                fg=self._c("text"),
                insertbackground=self._c("primary"),
                relief="flat",
            ).pack(fill="x", ipady=7)

        def active_hint() -> str:
            active_m = auth_mode if initialized else mode_var.get()
            if not initialized and active_m == "custom":
                return "English letters & numbers (min 2 chars)"
            return ""

        def sync_mode_widgets(*_args: Any) -> None:
            if mode_var.get() == "windows":
                win_user_row.pack(fill="x", pady=(0, 10), before=pw_entry)
                if not initialized:
                    recovery_wrap.pack_forget()
            else:
                win_user_row.pack_forget()
                if not initialized:
                    recovery_wrap.pack(fill="x", pady=(0, 8), before=status_lbl)
            check_live_ascii()

        if not initialized:
            mode_frame = tk.Frame(card, bg=self._c("surface"))
            mode_frame.pack(fill="x", pady=(0, 10))
            for text_lbl, val in [("Custom Password", "custom"), ("Windows Password", "windows")]:
                tk.Radiobutton(
                    mode_frame,
                    text=text_lbl,
                    variable=mode_var,
                    value=val,
                    command=sync_mode_widgets,
                    font=(FONT_UI, 10),
                    bg=self._c("surface"),
                    fg=self._c("text"),
                    activebackground=self._c("surface"),
                    activeforeground=self._c("text"),
                    selectcolor=self._c("surface_alt"),
                    highlightthickness=0,
                    bd=0,
                    padx=6,
                    pady=4,
                    anchor="w",
                    cursor="hand2",
                ).pack(side="left", expand=True, fill="x")

        pw_var = tk.StringVar()
        pw_entry = tk.Entry(
            card,
            textvariable=pw_var,
            show="•",
            font=(FONT_UI, 11),
            bg=self._c("surface_alt"),
            fg=self._c("text"),
            insertbackground=self._c("primary"),
            relief="flat",
        )
        pw_entry.pack(fill="x", ipady=10, padx=2, pady=(0, 6))
        pw_entry.focus_set()

        if (not initialized and mode_var.get() == "windows") or (initialized and auth_mode == "windows"):
            win_user_row.pack(fill="x", pady=(0, 10), before=pw_entry)

        status_lbl = tk.Label(card, text=active_hint(), font=(FONT_UI, 9), bg=self._c("surface"), fg=self._c("muted"), wraplength=390)
        status_lbl.pack(pady=(2, 8))

        if not initialized and mode_var.get() == "custom":
            recovery_wrap.pack(fill="x", pady=(0, 8), before=status_lbl)

        def check_live_ascii(*_args: Any) -> None:
            active_m = auth_mode if initialized else mode_var.get()
            if active_m == "windows":
                status_lbl.configure(text=active_hint(), fg=self._c("muted"))
                return
            val = pw_var.get()
            if val and not SecurityService.is_english_password(val, allow_spaces=False):
                status_lbl.configure(
                    text="Use English keyboard characters & numbers only (no Persian or spaces).",
                    fg=self._c("danger"),
                )
            else:
                status_lbl.configure(text=active_hint(), fg=self._c("muted"))

        pw_var.trace_add("write", check_live_ascii)

        def handle_submit(_e: Any = None) -> None:
            pw = pw_var.get()
            active_mode = auth_mode if initialized else mode_var.get()
            try:
                SecurityService.validate_login_password(pw, auth_mode=active_mode, label="Password")
                generated_rec: Optional[Tuple[str, str]] = None
                if not initialized:
                    rec_email = recovery_email_var.get().strip() if active_mode == "custom" else ""
                    if rec_email:
                        RecoveryEmailService.normalize_email(rec_email)
                    self.dek = self.db.create_vault(pw, auth_mode=active_mode)
                    if rec_email and self.dek is not None:
                        rec_key = self.db.configure_recovery(self.dek, rec_email)
                        generated_rec = (rec_key, self.db.get_recovery_info().get("email_masked", rec_email))
                else:
                    self.dek = self.db.unlock(pw)
                self._mark_activity()
                self.show_vault_workspace()
                if generated_rec is not None:
                    self._show_recovery_key_modal(generated_rec[0], generated_rec[1])
            except Exception as exc:
                status_lbl.configure(text=str(exc), fg=self._c("danger"))

        pw_entry.bind("<Return>", handle_submit)

        btn_text = "Create Vault" if not initialized else "Unlock Vault"
        self._btn(
            card,
            icon_name="lock_white",
            text=f"  {btn_text}",
            command=handle_submit,
            font=(FONT_UI, 10, "bold"),
            bg=self._c("primary"),
            fg=self._c("primary_fg"),
            activebackground=self._c("primary"),
            activeforeground=self._c("primary_fg"),
            relief="flat",
            cursor="hand2",
            pady=10,
        ).pack(fill="x")

        if initialized and auth_mode == "custom":
            self._btn(
                card,
                icon_name="key",
                text="  Forgot Password?",
                command=self.open_forgot_password_dialog,
                font=(FONT_UI, 9, "bold"),
                bg=self._c("surface"),
                fg=self._c("primary"),
                activebackground=self._c("surface_alt"),
                activeforeground=self._c("primary"),
                relief="flat",
                pady=6,
                cursor="hand2",
            ).pack(fill="x", pady=(8, 0))

    # ------------------------------------------------------------------
    # Main Vault Workspace (Unified All Passwords + People Sub-tree)
    # ------------------------------------------------------------------
    def show_vault_workspace(self) -> None:
        self.reload_data()
        self._render_workspace_shell()

    def _render_workspace_shell(self) -> None:
        self.clear_container()
        self.main_container.configure(bg=self._c("bg"))

        self.paned = tk.PanedWindow(
            self.main_container,
            orient="horizontal",
            sashwidth=5,
            sashrelief="flat",
            bg=self._c("border"),
            bd=0,
        )
        self.paned.pack(fill="both", expand=True)

        sb_width = 72 if self.sidebar_collapsed else 254
        self.sidebar = tk.Frame(self.paned, bg=self._c("surface"), width=sb_width)
        self.list_pane = tk.Frame(self.paned, bg=self._c("bg"), width=350)
        self.detail_pane = tk.Frame(self.paned, bg=self._c("surface"))

        self.paned.add(self.sidebar, minsize=72 if self.sidebar_collapsed else 185, width=sb_width)
        self.paned.add(self.list_pane, minsize=280, width=350)
        self.paned.add(self.detail_pane, minsize=360)

        self._build_sidebar()
        self._build_list_pane()
        self.refresh_entry_list()
        self.render_detail_pane()

    def reload_data(self) -> None:
        if self.dek is None:
            return
        self.entries = self.db.list_entries(self.dek)
        self.people = self.db.list_people()
        self.categories = self.db.list_categories()
        self.custom_logos = self.db.list_custom_logos()
        self.logos.clear_logo_cache()

    def _on_data_mutated(self) -> None:
        settings = self.db.get_settings()
        if settings.get("local_auto_backup"):
            self.db.create_local_backup()
        if settings.get("online_auto_backup") and self.dek is not None:
            dek = self.dek
            threading.Thread(target=self._safe_online_backup, args=(dek,), daemon=True).start()

    def _safe_online_backup(self, dek: bytes) -> None:
        try:
            self.db.push_cloud_sync(dek, is_auto_backup=True)
        except Exception:
            pass

    def toggle_sidebar(self) -> None:
        self.sidebar_collapsed = not self.sidebar_collapsed
        self._render_workspace_shell()

    def _build_sidebar(self) -> None:
        if self._people_anim_job is not None:
            try:
                self.after_cancel(self._people_anim_job)
            except Exception:
                pass
            self._people_anim_job = None

        for w in self.sidebar.winfo_children():
            w.destroy()

        header = tk.Frame(
            self.sidebar,
            bg=self._c("surface"),
            padx=6 if self.sidebar_collapsed else 10,
            pady=12,
        )
        header.pack(side="top", fill="x")

        menu_btn = self._btn(
            header,
            icon_name="menu_28",
            command=self.toggle_sidebar,
            bg=self._c("surface"),
            activebackground=self._c("surface"),
            fg=self._c("text"),
            bd=0,
            highlightthickness=0,
            relief="flat",
            padx=10 if self.sidebar_collapsed else 2,
            pady=8 if self.sidebar_collapsed else 2,
            cursor="hand2",
        )
        if self.sidebar_collapsed:
            menu_btn.configure(anchor="center")
            menu_btn.pack(fill="x", anchor="center")
        else:
            menu_btn.pack(side="left")
            self._render_brand_lockup(header, large=False).pack(side="left", padx=6)
            self._btn(
                header,
                icon_name="lock_28",
                command=self.lock_vault,
                bg=self._c("surface"),
                activebackground=self._c("surface"),
                fg=self._c("text"),
                bd=0,
                highlightthickness=0,
                relief="flat",
                padx=2,
                pady=2,
                cursor="hand2",
            ).pack(side="right")

        bottom_bar = tk.Frame(self.sidebar, bg=self._c("surface"), padx=8, pady=10)
        bottom_bar.pack(side="bottom", fill="x")
        self._theme_switch_widget = ThemeSwitchWidget(
            bottom_bar,
            self.logos,
            self.theme_name,
            self.sidebar_collapsed,
            self.set_theme,
        )

        sb_outer = tk.Frame(self.sidebar, bg=self._c("surface"))
        sb_outer.pack(side="top", fill="both", expand=True)
        sb_canvas = tk.Canvas(sb_outer, bg=self._c("surface"), highlightthickness=0, bd=0)
        sb_scroll = ttk.Scrollbar(sb_outer, orient="vertical", command=sb_canvas.yview)
        sb_body = tk.Frame(sb_canvas, bg=self._c("surface"))
        self._sb_canvas = sb_canvas
        ScrollHelper.bind_bounded_scroll(
            sb_canvas,
            sb_body,
            sb_scroll,
            lambda c: self._enable_mousewheel(c, sb_outer),
        )

        def nav_btn(
            parent_box: Any,
            label: str,
            icon_key: str,
            cmd: Callable[[], None],
            active: bool = False,
            indent: int = 0,
            custom_image: Optional[Any] = None,
        ) -> None:
            text_val = "" if self.sidebar_collapsed else f"  {label}"
            btn_pady = 10 if self.sidebar_collapsed else 7
            pack_pady = 5 if self.sidebar_collapsed else 2
            self._btn(
                parent_box,
                icon_name=icon_key,
                custom_image=custom_image,
                text=text_val,
                compound="left" if not self.sidebar_collapsed else "center",
                command=cmd,
                anchor="center" if self.sidebar_collapsed else "w",
                font=(FONT_UI, 9, "bold" if active else "normal"),
                bg=self._c("surface_alt") if active else self._c("surface"),
                fg=self._c("text"),
                relief="flat",
                padx=10,
                pady=btn_pady,
                cursor="hand2",
            ).pack(fill="x", padx=(6 + indent, 6), pady=pack_pady)

        # 1. All Passwords (+ Smooth Animated People Sub-menu, open by default)
        if not self.sidebar_collapsed:
            all_active = self.active_sidebar_item == "all"
            all_row_bg = self._c("surface_alt") if all_active else self._c("surface")
            all_row = tk.Frame(sb_body, bg=all_row_bg)
            all_row.pack(fill="x", padx=6, pady=2)
            self._people_all_row = all_row

            self._btn(
                all_row,
                icon_name="vault",
                text="  All Passwords",
                compound="left",
                command=self._select_all_or_toggle_people,
                anchor="w",
                font=(FONT_UI, 9, "bold" if all_active else "normal"),
                bg=all_row_bg,
                fg=self._c("text"),
                bd=0,
                highlightthickness=0,
                relief="flat",
                padx=10,
                pady=7,
                cursor="hand2",
            ).pack(side="left", fill="x", expand=True)

            chev_btn = self._btn(
                all_row,
                icon_name="chevron_down" if self.people_expanded else "chevron_right",
                command=self._toggle_people_section,
                bg=all_row_bg,
                activebackground=all_row_bg,
                fg=self._c("text"),
                bd=0,
                highlightthickness=0,
                relief="flat",
                padx=6,
                pady=7,
                cursor="hand2",
            )
            chev_btn.pack(side="right")
            self._people_chevron_btn = chev_btn

            people_clip = tk.Frame(sb_body, bg=self._c("surface"))
            people_inner = tk.Frame(people_clip, bg=self._c("surface"))
            people_inner.pack(fill="x")
            for person in self.people:
                pid = person["id"]
                avatar_img = self.logos.get_person_avatar_photo(person, size=24, fallback_ui_icon="user")
                nav_btn(
                    people_inner,
                    person["name"],
                    "user",
                    lambda p=pid: self._set_filter(fav=False, person=p, nav_key=f"person:{p}"),
                    self.active_sidebar_item == f"person:{pid}",
                    indent=16,
                    custom_image=avatar_img,
                )
            nav_btn(
                people_inner,
                "Manage People",
                "users",
                lambda: self._open_sidebar_dialog("manage_people", self.open_people_manager),
                self.active_sidebar_item == "manage_people",
                indent=16,
            )
            people_inner.update_idletasks()
            target_h = max(people_inner.winfo_reqheight(), 1)
            people_clip.pack_propagate(False)
            people_clip.configure(height=target_h if self.people_expanded else 0)
            if self.people_expanded:
                people_clip.pack(fill="x")
            self._people_clip = people_clip
            self._people_inner = people_inner
        else:
            self._people_clip = None
            self._people_inner = None
            self._people_chevron_btn = None
            self._people_all_row = None
            nav_btn(sb_body, "All Passwords", "vault", lambda: self._set_filter(fav=False, person="all", nav_key="all"), self.active_sidebar_item == "all")

        # 2. Favorites
        nav_btn(sb_body, "Favorites", "star", lambda: self._set_filter(fav=True, person="all", nav_key="favorites"), self.active_sidebar_item == "favorites")

        # Divider ----
        tk.Frame(sb_body, bg=self._c("border"), height=1).pack(
            fill="x",
            padx=12,
            pady=10 if self.sidebar_collapsed else 8,
        )

        # 3. Generator -> Categories -> Default Logos -> Settings
        nav_btn(sb_body, "Generator", "wand", lambda: self._open_sidebar_dialog("generator", self.open_generator_dialog), self.active_sidebar_item == "generator")
        nav_btn(sb_body, "Categories", "folder", lambda: self._open_sidebar_dialog("categories", self.open_categories_manager), self.active_sidebar_item == "categories")
        nav_btn(sb_body, "Default Logos", "image", lambda: self._open_sidebar_dialog("logos", self.open_custom_logos_manager), self.active_sidebar_item == "logos")
        nav_btn(sb_body, "Settings", "settings", lambda: self._open_sidebar_dialog("settings", self.open_settings_dialog), self.active_sidebar_item == "settings")
        nav_btn(sb_body, "About", "info", lambda: self._open_sidebar_dialog("about", self.open_about_dialog), self.active_sidebar_item == "about")

    def _animate_people_drawer(self, expand: bool) -> None:
        clip = self._people_clip
        inner = self._people_inner
        all_row = self._people_all_row
        if clip is None or inner is None or not clip.winfo_exists():
            self._build_sidebar()
            return
        if self._people_anim_job is not None:
            try:
                self.after_cancel(self._people_anim_job)
            except Exception:
                pass
            self._people_anim_job = None

        if self._people_chevron_btn is not None and self._people_chevron_btn.winfo_exists():
            chev_icon = self._icon("chevron_down" if expand else "chevron_right")
            if chev_icon is not None:
                self._people_chevron_btn.configure(image=chev_icon)
                self._people_chevron_btn._img_ref = chev_icon

        inner.update_idletasks()
        target_h = max(inner.winfo_reqheight(), 1)
        start_h = clip.winfo_height() if clip.winfo_ismapped() else 0
        if expand and not clip.winfo_ismapped() and all_row is not None and all_row.winfo_exists():
            clip.configure(height=start_h)
            clip.pack(fill="x", after=all_row)
        end_h = target_h if expand else 0
        steps = 10

        def _step(idx: int) -> None:
            if not clip.winfo_exists():
                self._people_anim_job = None
                return
            t = idx / steps
            eased = 1.0 - (1.0 - t) ** 3
            cur_h = int(round(start_h + (end_h - start_h) * eased))
            clip.configure(height=max(0, cur_h))
            if self._sb_canvas is not None and self._sb_canvas.winfo_exists():
                self._sb_canvas.configure(scrollregion=self._sb_canvas.bbox("all"))
            if idx < steps:
                self._people_anim_job = self.after(14, lambda: _step(idx + 1))
            else:
                self._people_anim_job = None
                if not expand:
                    clip.pack_forget()
                if self._sb_canvas is not None and self._sb_canvas.winfo_exists():
                    self._sb_canvas.configure(scrollregion=self._sb_canvas.bbox("all"))

        _step(1)

    def _select_all_or_toggle_people(self) -> None:
        if self.active_sidebar_item == "all":
            self._toggle_people_section()
        else:
            self.people_expanded = True
            self._set_filter(fav=False, person="all", nav_key="all")

    def _open_sidebar_dialog(self, nav_key: str, opener: Callable[[], None]) -> None:
        self.active_sidebar_item = nav_key
        self._build_sidebar()
        opener()

    def _toggle_people_section(self) -> None:
        self.people_expanded = not self.people_expanded
        self._animate_people_drawer(self.people_expanded)

    def _set_filter(self, fav: bool, person: str, nav_key: str = "all") -> None:
        self.filter_favorites = fav
        self.filter_person = person
        self.active_sidebar_item = nav_key
        self._build_sidebar()
        self.refresh_entry_list()

    def _active_scope_label(self) -> str:
        if self.filter_favorites:
            return "Favorites (All People)"
        if self.filter_person != "all":
            pname = next((p["name"] for p in self.people if p["id"] == self.filter_person), "Unknown")
            return f"Person: {pname}"
        return "Person: All People"

    def _build_list_pane(self) -> None:
        for w in self.list_pane.winfo_children():
            w.destroy()

        top = tk.Frame(self.list_pane, bg=self._c("surface"), padx=12, pady=12)
        top.pack(fill="x")

        scope_bar = tk.Frame(top, bg=self._c("surface_alt"), padx=10, pady=6)
        scope_bar.pack(fill="x", pady=(0, 8))
        active_p = next((p for p in self.people if p["id"] == self.filter_person), None) if self.filter_person != "all" else None
        scope_ic = (
            self.logos.get_person_avatar_photo(active_p, size=24, fallback_ui_icon="user")
            if active_p is not None
            else self._icon("star" if self.filter_favorites else "users")
        )
        self._scope_icon_lbl = tk.Label(scope_bar, bg=self._c("surface_alt"))
        if scope_ic is not None:
            self._scope_icon_lbl.configure(image=scope_ic)
            self._scope_icon_lbl._img_ref = scope_ic
            self._scope_icon_lbl.pack(side="left", padx=(0, 6))
        self.active_person_lbl = tk.Label(
            scope_bar,
            text=self._active_scope_label(),
            font=(FONT_UI, 9, "bold"),
            bg=self._c("surface_alt"),
            fg=self._c("primary"),
            anchor="w",
        )
        self.active_person_lbl.pack(side="left", fill="x", expand=True)

        self._btn(
            top,
            icon_name="plus",
            text="  Add New Password",
            command=lambda: self.open_entry_dialog(None),
            font=(FONT_UI, 10, "bold"),
            bg=self._c("primary"),
            fg=self._c("primary_fg"),
            activebackground=self._c("primary"),
            activeforeground=self._c("primary_fg"),
            relief="flat",
            pady=8,
            cursor="hand2",
        ).pack(fill="x", pady=(0, 10))

        search_box = tk.Frame(
            top,
            bg=self._c("surface_alt"),
            highlightbackground=self._c("primary"),
            highlightthickness=1,
            padx=8,
            pady=4,
        )
        search_box.pack(fill="x", pady=(0, 8))
        search_icon = self._icon("search")
        if search_icon is not None:
            s_lbl = tk.Label(search_box, image=search_icon, bg=self._c("surface_alt"))
            s_lbl._img_ref = search_icon
            s_lbl.pack(side="left", padx=(2, 6))

        search_entry = tk.Entry(
            search_box,
            textvariable=self.search_var,
            font=(FONT_UI, 10),
            bg=self._c("surface_alt"),
            fg=self._c("text"),
            insertbackground=self._c("primary"),
            relief="flat",
        )
        search_entry.pack(side="left", fill="x", expand=True, ipady=4)

        self.search_placeholder_lbl = tk.Label(
            search_entry,
            text="Search title, username, tags...",
            font=(FONT_UI, 9),
            bg=self._c("surface_alt"),
            fg=self._c("muted"),
            cursor="xterm",
        )
        self.search_placeholder_lbl.bind("<Button-1>", lambda _e: search_entry.focus_set())
        if not self.search_var.get():
            self.search_placeholder_lbl.place(x=6, rely=0.5, anchor="w")

        self.clear_search_btn = tk.Button(
            search_box,
            text="✕",
            command=lambda: self.search_var.set(""),
            font=(FONT_UI, 9, "bold"),
            bg=self._c("surface_alt"),
            fg=self._c("text"),
            relief="flat",
            cursor="hand2",
        )
        if self.search_var.get():
            self.clear_search_btn.pack(side="right", padx=(4, 0))

        filter_row = tk.Frame(top, bg=self._c("surface"))
        filter_row.pack(fill="x", pady=(0, 6))

        self.cat_combo = ttk.Combobox(filter_row, values=["All Categories"] + self.categories, state="readonly", width=16)
        self.cat_combo.set(self.filter_category if self.filter_category in self.categories else "All Categories")
        self.cat_combo.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.cat_combo.bind("<<ComboboxSelected>>", lambda _e: self._on_combo_filter())

        all_tags = sorted({t for item in self.entries for t in item.get("tags", [])})
        self.tag_combo = ttk.Combobox(filter_row, values=["All Tags"] + all_tags, state="readonly", width=14)
        self.tag_combo.set(self.filter_tag if self.filter_tag in all_tags else "All Tags")
        self.tag_combo.pack(side="left", fill="x", expand=True)
        self.tag_combo.bind("<<ComboboxSelected>>", lambda _e: self._on_combo_filter())

        sort_row = tk.Frame(top, bg=self._c("surface"))
        sort_row.pack(fill="x")
        sort_icon = self._icon("sort")
        if sort_icon is not None:
            si_lbl = tk.Label(sort_row, image=sort_icon, bg=self._c("surface"))
            si_lbl._img_ref = sort_icon
            si_lbl.pack(side="left", padx=(0, 4))
        tk.Label(
            sort_row,
            text="Sort:",
            font=(FONT_UI, 9),
            bg=self._c("surface"),
            fg=self._c("text"),
        ).pack(side="left", padx=(0, 6))

        self._sort_map = [
            ("Newest Updated", "updated_desc"),
            ("Oldest Updated", "updated_asc"),
            ("Title (A–Z)", "title_asc"),
            ("Title (Z–A)", "title_desc"),
            ("Created Date", "created_desc"),
            ("Favorites First", "favorites"),
        ]
        self.sort_combo = ttk.Combobox(sort_row, values=[lbl for lbl, _k in self._sort_map], state="readonly")
        cur_sort_idx = next((i for i, (_lbl, k) in enumerate(self._sort_map) if k == self.sort_by), 0)
        self.sort_combo.current(cur_sort_idx)
        self.sort_combo.pack(side="left", fill="x", expand=True)
        self.sort_combo.bind("<<ComboboxSelected>>", lambda _e: self._on_sort_changed())

        self.count_lbl = tk.Label(top, text="", font=(FONT_UI, 8, "bold"), bg=self._c("surface"), fg=self._c("muted"), anchor="w")
        self.count_lbl.pack(fill="x", pady=(6, 0))

        list_outer = tk.Frame(self.list_pane, bg=self._c("bg"))
        list_outer.pack(fill="both", expand=True, padx=(8, 2), pady=(6, 8))

        self.list_canvas = tk.Canvas(list_outer, bg=self._c("bg"), highlightthickness=0, bd=0)
        list_scroll = ttk.Scrollbar(list_outer, orient="vertical", command=self.list_canvas.yview)
        self.listbox_frame = tk.Frame(self.list_canvas, bg=self._c("bg"))
        ScrollHelper.bind_bounded_scroll(
            self.list_canvas,
            self.listbox_frame,
            list_scroll,
            lambda c: self._enable_mousewheel(c, list_outer),
        )

    def _on_search_changed(self) -> None:
        has_q = bool(self.search_var.get())
        if hasattr(self, "search_placeholder_lbl"):
            if has_q:
                self.search_placeholder_lbl.place_forget()
            else:
                self.search_placeholder_lbl.place(x=6, rely=0.5, anchor="w")
        if hasattr(self, "clear_search_btn"):
            if has_q:
                self.clear_search_btn.pack(side="right", padx=(4, 0))
            else:
                self.clear_search_btn.pack_forget()
        if hasattr(self, "listbox_frame"):
            self.refresh_entry_list()

    def _on_combo_filter(self) -> None:
        cval = self.cat_combo.get()
        tval = self.tag_combo.get()
        self.filter_category = "all" if cval == "All Categories" else cval
        self.filter_tag = "all" if tval == "All Tags" else tval
        self.refresh_entry_list()

    def _on_sort_changed(self) -> None:
        idx = self.sort_combo.current()
        if 0 <= idx < len(self._sort_map):
            self.sort_by = self._sort_map[idx][1]
        self.refresh_entry_list()

    def filtered_entries(self) -> List[Dict[str, Any]]:
        q = self.search_var.get().strip().lower()
        res: List[Dict[str, Any]] = []
        for item in self.entries:
            if self.filter_favorites and not item.get("is_favorite"):
                continue
            if self.filter_person != "all" and item.get("person_id") != self.filter_person:
                continue
            if self.filter_category != "all" and item.get("category") != self.filter_category:
                continue
            if self.filter_tag != "all" and self.filter_tag not in item.get("tags", []):
                continue
            if q:
                blob = " ".join([
                    item.get("title", ""),
                    item.get("site_url", ""),
                    item.get("username", ""),
                    item.get("email", ""),
                    item.get("notes", ""),
                    item.get("category", ""),
                    " ".join(item.get("tags", [])),
                ]).lower()
                if q not in blob:
                    continue
            res.append(item)

        if self.sort_by == "updated_asc":
            res.sort(key=lambda e: e.get("updated_at", ""))
        elif self.sort_by == "title_asc":
            res.sort(key=lambda e: e.get("title", "").lower())
        elif self.sort_by == "title_desc":
            res.sort(key=lambda e: e.get("title", "").lower(), reverse=True)
        elif self.sort_by == "created_desc":
            res.sort(key=lambda e: (e.get("created_at", ""), e.get("updated_at", "")), reverse=True)
        elif self.sort_by == "favorites":
            res.sort(key=lambda e: (1 if e.get("is_favorite") else 0, e.get("updated_at", "")), reverse=True)
        else:
            res.sort(key=lambda e: e.get("updated_at", ""), reverse=True)
        return res

    def refresh_entry_list(self) -> None:
        for w in self.listbox_frame.winfo_children():
            w.destroy()

        items = self.filtered_entries()
        if hasattr(self, "_scope_icon_lbl"):
            active_p = next((p for p in self.people if p["id"] == self.filter_person), None) if self.filter_person != "all" else None
            sc_ic = (
                self.logos.get_person_avatar_photo(active_p, size=24, fallback_ui_icon="user")
                if active_p is not None
                else self._icon("star" if self.filter_favorites else "users")
            )
            if sc_ic is not None:
                self._scope_icon_lbl.configure(image=sc_ic)
                self._scope_icon_lbl._img_ref = sc_ic
        if hasattr(self, "active_person_lbl"):
            self.active_person_lbl.configure(text=self._active_scope_label())
        if hasattr(self, "count_lbl"):
            self.count_lbl.configure(text=f"{len(items)} credential(s)")

        if not items:
            tk.Label(self.listbox_frame, text="No matching passwords found.", font=(FONT_UI, 10), bg=self._c("bg"), fg=self._c("muted")).pack(pady=40)
            return

        for item in items:
            active = item["id"] == self.selected_entry_id
            row_bg = self._c("surface_alt") if active else self._c("surface")
            row = tk.Frame(
                self.listbox_frame,
                bg=row_bg,
                highlightbackground=self._c("primary") if active else self._c("border"),
                highlightthickness=1,
                padx=10,
                pady=8,
                cursor="hand2",
            )
            row.pack(fill="x", pady=3, padx=(0, 4))

            badge = self.logos.create_badge_label(
                row,
                item.get("logo_key", "globe"),
                item.get("custom_logo_b64", ""),
                self.custom_logos,
                size=38,
                custom_logo_file=item.get("custom_logo_file", ""),
            )
            badge.pack(side="left", padx=(0, 10))

            text_col = tk.Frame(row, bg=row_bg)
            text_col.pack(side="left", fill="x", expand=True)

            star = "★ " if item.get("is_favorite") else ""
            title_lbl = tk.Label(
                text_col,
                text=f"{star}{item['title']}",
                font=(FONT_UI, 10, "bold"),
                bg=row_bg,
                fg=self._c("text"),
                anchor="w",
            )
            title_lbl.pack(fill="x")

            sub_lbl = tk.Label(
                text_col,
                text=f"{item.get('username') or item.get('site_url') or 'No username'} · {item.get('category', '')}",
                font=(FONT_UI, 9),
                bg=row_bg,
                fg=self._c("muted"),
                anchor="w",
            )
            sub_lbl.pack(fill="x")

            for widget in (row, badge, text_col, title_lbl, sub_lbl):
                widget.bind("<Button-1>", lambda _e, eid=item["id"]: self.select_entry(eid))

    def select_entry(self, entry_id: str) -> None:
        self.selected_entry_id = entry_id
        self.reveal_password = False
        self.refresh_entry_list()
        self.render_detail_pane()

    def render_detail_pane(self) -> None:
        self._secret_val_lbl = None
        self._secret_toggle_btn = None
        self._secret_raw_val = ""

        for w in self.detail_pane.winfo_children():
            w.destroy()

        entry = next((e for e in self.entries if e["id"] == self.selected_entry_id), None)
        if not entry:
            tk.Label(self.detail_pane, text="Select an item or add a new password.", font=(FONT_UI, 11), bg=self._c("surface"), fg=self._c("muted")).place(relx=0.5, rely=0.5, anchor="center")
            return

        canvas = tk.Canvas(self.detail_pane, bg=self._c("surface"), highlightthickness=0, bd=0)
        scroll = ttk.Scrollbar(self.detail_pane, orient="vertical", command=canvas.yview)
        wrap = tk.Frame(canvas, bg=self._c("surface"), padx=28, pady=24)
        ScrollHelper.bind_bounded_scroll(
            canvas,
            wrap,
            scroll,
            lambda c: self._enable_mousewheel(c, self.detail_pane),
        )

        head = tk.Frame(wrap, bg=self._c("surface"))
        head.pack(fill="x", pady=(0, 18))

        badge = self.logos.create_badge_label(
            head,
            entry.get("logo_key", "globe"),
            entry.get("custom_logo_b64", ""),
            self.custom_logos,
            size=48,
            custom_logo_file=entry.get("custom_logo_file", ""),
        )
        badge.pack(side="left", padx=(0, 14))

        title_box = tk.Frame(head, bg=self._c("surface"))
        title_box.pack(side="left", fill="x", expand=True)
        tk.Label(title_box, text=entry["title"], font=(FONT_UI, 17, "bold"), bg=self._c("surface"), fg=self._c("text"), anchor="w").pack(fill="x")

        person_obj = next((p for p in self.people if p["id"] == entry.get("person_id")), None)
        person_name = person_obj["name"] if person_obj else "Me"
        meta_row = tk.Frame(title_box, bg=self._c("surface"))
        meta_row.pack(fill="x", pady=(4, 0))
        detail_av = self.logos.get_person_avatar_photo(person_obj, size=20, fallback_ui_icon="user")
        if detail_av is not None:
            av_w = tk.Label(meta_row, image=detail_av, bg=self._c("surface"))
            av_w._img_ref = detail_av
            av_w.pack(side="left", padx=(0, 6))
        meta_line = f"{person_name}  ·  {entry.get('category', 'General')}  ·  Created: {entry.get('created_at', '')}"
        tk.Label(meta_row, text=meta_line, font=(FONT_UI, 9), bg=self._c("surface"), fg=self._c("muted"), anchor="w").pack(side="left", fill="x")

        btns = tk.Frame(head, bg=self._c("surface"))
        btns.pack(side="right")
        self._btn(btns, icon_name="edit", text="  Edit", command=lambda: self.open_entry_dialog(entry), font=(FONT_UI, 9, "bold"), bg=self._c("surface_alt"), fg=self._c("text"), relief="flat", padx=12, pady=6, cursor="hand2").pack(side="left", padx=(0, 6))
        self._btn(btns, icon_name="trash", text="  Delete", command=lambda: self.confirm_delete_entry(entry), font=(FONT_UI, 9, "bold"), bg=self._c("danger"), fg="#FFFFFF", activebackground=self._c("danger"), activeforeground="#FFFFFF", relief="flat", padx=12, pady=6, cursor="hand2").pack(side="left")

        def field_row(label: str, value: str, secret: bool = False) -> None:
            box = tk.Frame(wrap, bg=self._c("surface_alt"), padx=16, pady=12)
            box.pack(fill="x", pady=5)
            tk.Label(box, text=label, font=(FONT_UI, 8, "bold"), bg=self._c("surface_alt"), fg=self._c("muted"), anchor="w").pack(fill="x")
            row_inner = tk.Frame(box, bg=self._c("surface_alt"))
            row_inner.pack(fill="x", pady=(4, 0))
            shown = ("•" * min(len(value), 16)) if (secret and not self.reveal_password) else (value or "—")
            val_lbl = tk.Label(row_inner, text=shown, font=(FONT_MONO if secret else FONT_UI, 11), bg=self._c("surface_alt"), fg=self._c("text"), anchor="w", wraplength=440, justify="left")
            val_lbl.pack(side="left", fill="x", expand=True)
            if secret:
                self._secret_val_lbl = val_lbl
                self._secret_raw_val = value
                t_btn = self._btn(row_inner, icon_name="eye", text="  " + ("Hide" if self.reveal_password else "Show"), command=self.toggle_reveal, font=(FONT_UI, 9), bg=self._c("surface"), fg=self._c("text"), relief="flat", padx=10, pady=4, cursor="hand2")
                t_btn.pack(side="right", padx=(6, 0))
                self._secret_toggle_btn = t_btn
            if value:
                self._btn(row_inner, icon_name="copy", text="  Copy", command=lambda v=value, is_sec=secret: self.copy_text(v, clear_after=30 if is_sec else 0), font=(FONT_UI, 9, "bold"), bg=self._c("surface"), fg=self._c("text"), relief="flat", padx=10, pady=4, cursor="hand2").pack(side="right")

        field_row("Website", entry.get("site_url", ""))
        field_row("Username" + (" (Same as Email)" if entry.get("username_is_email") else ""), entry.get("username", ""))
        if not entry.get("username_is_email"):
            field_row("Email", entry.get("email", ""))
        field_row("Password", entry.get("password", ""), secret=True)
        if entry.get("tags"):
            field_row("Tags", ", ".join(entry["tags"]))
        if entry.get("notes"):
            field_row("Notes", entry["notes"])

    def toggle_reveal(self) -> None:
        self.reveal_password = not self.reveal_password
        if self._secret_val_lbl is not None and self._secret_val_lbl.winfo_exists():
            val = self._secret_raw_val
            shown = ("•" * min(len(val), 16)) if not self.reveal_password else (val or "—")
            self._secret_val_lbl.configure(text=shown)
        if self._secret_toggle_btn is not None and self._secret_toggle_btn.winfo_exists():
            self._secret_toggle_btn.configure(text="  " + ("Hide" if self.reveal_password else "Show"))

    def copy_text(self, value: str, clear_after: int = 0, parent: Optional[Any] = None) -> None:
        if not value:
            return
        self.clipboard_clear()
        self.clipboard_append(value)
        if self._clipboard_clear_job is not None:
            try:
                self.after_cancel(self._clipboard_clear_job)
            except Exception:
                pass
            self._clipboard_clear_job = None
        if clear_after > 0:
            self._last_copied_secret = value

            def _wipe() -> None:
                self._clipboard_clear_job = None
                try:
                    if self.clipboard_get() == value:
                        self.clipboard_clear()
                except Exception:
                    pass
                self._last_copied_secret = ""

            self._clipboard_clear_job = self.after(clear_after * 1000, _wipe)
        else:
            self._last_copied_secret = ""
        msg = f"Copied to clipboard (auto-clears in {clear_after}s)." if clear_after > 0 else "Copied to clipboard."
        messagebox.showinfo("Copied", msg, parent=parent or self)

    def confirm_delete_entry(self, entry: Dict[str, Any]) -> None:
        if messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete '{entry['title']}'?", parent=self):
            self.db.delete_entry(entry["id"], dek=self.dek)
            if self.selected_entry_id == entry["id"]:
                self.selected_entry_id = None
            self._on_data_mutated()
            self.reload_data()
            self._build_list_pane()
            self.refresh_entry_list()
            self.render_detail_pane()

    def set_theme(self, name: str) -> None:
        if name == self.theme_name:
            return
        if self._theme_anim_job is not None:
            try:
                self.after_cancel(self._theme_anim_job)
            except Exception:
                pass
            self._theme_anim_job = None

        prev_theme = self.theme_name
        self.theme_name = name
        settings = self.db.get_settings()
        settings["theme"] = self.theme_name
        self.db.save_settings(settings)

        old_pal = ThemeManager.THEMES.get(prev_theme, ThemeManager.THEMES["light"])
        new_pal = ThemeManager.THEMES.get(name, ThemeManager.THEMES["light"])

        bg_token_by_hex: Dict[str, str] = {}
        for tok in ("bg", "surface", "surface_alt", "border", "primary", "accent_bg", "danger", "success", "accent", "muted", "text"):
            bg_token_by_hex.setdefault(old_pal[tok].upper(), tok)

        fg_token_by_hex: Dict[str, str] = {}
        for tok in ("text", "muted", "primary", "primary_fg", "accent", "danger", "success", "surface", "bg"):
            fg_token_by_hex.setdefault(old_pal[tok].upper(), tok)

        skip_widgets = set()
        if self._theme_switch_widget is not None:
            for attr in ("_canvas", "_badge_btn", "_ver_lbl"):
                w_ref = getattr(self._theme_switch_widget, attr, None)
                if w_ref is not None:
                    skip_widgets.add(w_ref)

        bg_opts = ("bg", "activebackground", "highlightbackground", "selectcolor")
        fg_opts = ("fg", "activeforeground", "insertbackground")
        targets: List[Tuple[Any, Dict[str, Tuple[str, str]]]] = []

        def _collect(widget: Any) -> None:
            if widget in skip_widgets:
                return
            token_map: Dict[str, str] = getattr(widget, "_theme_tokens", {})
            if not token_map:
                detected: Dict[str, str] = {}
                try:
                    w_keys = set(widget.keys())
                except Exception:
                    w_keys = set()
                for opt in bg_opts:
                    if opt in w_keys:
                        try:
                            cur = str(widget.cget(opt)).upper()
                            if cur in bg_token_by_hex:
                                detected[opt] = bg_token_by_hex[cur]
                        except Exception:
                            pass
                for opt in fg_opts:
                    if opt in w_keys:
                        try:
                            cur = str(widget.cget(opt)).upper()
                            if cur in fg_token_by_hex:
                                detected[opt] = fg_token_by_hex[cur]
                        except Exception:
                            pass
                if detected:
                    widget._theme_tokens = detected
                    token_map = detected

            if token_map:
                pairs: Dict[str, Tuple[str, str]] = {}
                for opt, tok in token_map.items():
                    try:
                        cur_hex = str(widget.cget(opt))
                    except Exception:
                        cur_hex = old_pal[tok]
                    if not cur_hex.startswith("#"):
                        cur_hex = old_pal[tok]
                    pairs[opt] = (cur_hex, new_pal[tok])
                if pairs:
                    targets.append((widget, pairs))

            for child in widget.winfo_children():
                _collect(child)

        _collect(self.main_container)

        if not targets:
            self._apply_ttk_theme()
            self._render_workspace_shell()
            return

        steps = 5
        graphic_swapped = {"done": False}
        switch_ref = self._theme_switch_widget
        brand_ref = self._brand_lockup_lbl

        def _apply_step(step_idx: int) -> None:
            t = step_idx / steps
            eased = 1.0 - (1.0 - t) ** 3
            for widget, pairs in targets:
                if not widget.winfo_exists():
                    continue
                cfg = {opt: ThemeManager.lerp_hex(c_from, c_to, eased) for opt, (c_from, c_to) in pairs.items()}
                try:
                    widget.configure(**cfg)
                except Exception:
                    pass

            swap_now = (not graphic_swapped["done"]) and (t >= 0.5)
            if swap_now:
                graphic_swapped["done"] = True
                self._apply_ttk_theme()
                if brand_ref is not None and brand_ref.winfo_exists():
                    is_large = bool(getattr(brand_ref, "_brand_large", False))
                    b_key = (
                        ("brandLogoLargeDark" if name == "dark" else "brandLogoLarge")
                        if is_large
                        else ("brandLogoSmallDark" if name == "dark" else "brandLogoSmall")
                    )
                    b_img = self.logos.get_named_photo(b_key)
                    if b_img is not None:
                        brand_ref.configure(image=b_img)
                        brand_ref._img_ref = b_img

            if switch_ref is not None:
                surf_cur = ThemeManager.lerp_hex(old_pal["surface"], new_pal["surface"], eased)
                muted_cur = ThemeManager.lerp_hex(old_pal["muted"], new_pal["muted"], eased)
                switch_ref.update_theme_visual(name, surf_cur, muted_cur, swap_graphic=swap_now)

            if step_idx < steps:
                self._theme_anim_job = self.after(10, lambda: _apply_step(step_idx + 1))
            else:
                self._theme_anim_job = None

        _apply_step(1)

    def toggle_theme(self) -> None:
        self.set_theme("dark" if self.theme_name == "light" else "light")


PassApp = PassVaultApp
