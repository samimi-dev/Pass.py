# -*- coding: utf-8 -*-
"""Security, Forgot Password (Email + Google Gmail SMTP), and Settings modal dialogs."""

import threading
import time
import webbrowser
from typing import Any, Dict, Optional, Tuple

from .paths import BACKUP_DIR
from .recovery import RecoveryEmailService
from .theme import APP_VERSION, FONT_MONO, FONT_UI
from .windows_auth import WindowsAuthService

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox
except ImportError:
    tk = None  # type: ignore
    filedialog = None  # type: ignore
    messagebox = None  # type: ignore


class VaultSecurityDialogsMixin:
    """Modal dialogs for Forgot Password recovery and application Settings."""

    def open_forgot_password_dialog(self) -> None:
        info = self.db.get_recovery_info()
        if not info.get("enabled"):
            messagebox.showinfo(
                "Password Recovery Not Configured",
                "No recovery Email has been configured for this vault.\n\n"
                "Once logged in, configure Email Recovery inside:\nSettings → Login & Security.",
                parent=self,
            )
            return

        dlg, frame, footer = self._create_scrollable_dialog("Recover Master Password", 480, 520, has_footer=True)
        tk.Label(frame, text="Email Password Recovery", font=(FONT_UI, 13, "bold"), bg=self._c("surface"), fg=self._c("text"), anchor="w").pack(fill="x", pady=(0, 6))
        tk.Label(
            frame,
            text=f"Registered Email: {info['email_masked']}\nVerify your Email and enter your 16-character Recovery Key to reset your master password safely.",
            font=(FONT_UI, 9),
            bg=self._c("surface"),
            fg=self._c("muted"),
            wraplength=420,
            justify="left",
            anchor="w",
        ).pack(fill="x", pady=(0, 10))

        v_email = tk.StringVar()
        v_otp = tk.StringVar()
        v_rec_key = tk.StringVar()
        v_new_pw = tk.StringVar()
        v_confirm_pw = tk.StringVar()
        otp_state: Dict[str, Any] = {"required": bool(info.get("has_smtp")), "hash": "", "salt": b"", "exp": 0}

        def add_input(label: str, var: tk.StringVar, show_char: str = "") -> Any:
            tk.Label(frame, text=label, font=(FONT_UI, 9, "bold"), bg=self._c("surface"), fg=self._c("text"), anchor="w").pack(fill="x", pady=(6, 2))
            ent = tk.Entry(frame, textvariable=var, show=show_char, font=(FONT_UI, 10), bg=self._c("surface_alt"), fg=self._c("text"), insertbackground=self._c("primary"), relief="flat")
            ent.pack(fill="x", ipady=6)
            return ent

        add_input("Registered Recovery Email *", v_email)

        otp_status_lbl = tk.Label(frame, text="", font=(FONT_UI, 8, "bold"), bg=self._c("surface"), fg=self._c("muted"), anchor="w", wraplength=420)
        if otp_state["required"]:
            otp_box = tk.Frame(frame, bg=self._c("surface_alt"), padx=10, pady=8)
            otp_box.pack(fill="x", pady=(8, 4))
            tk.Label(otp_box, text="Google Gmail SMTP Verification Code", font=(FONT_UI, 9, "bold"), bg=self._c("surface_alt"), fg=self._c("primary"), anchor="w").pack(fill="x")
            otp_row = tk.Frame(otp_box, bg=self._c("surface_alt"))
            otp_row.pack(fill="x", pady=(4, 0))
            tk.Entry(otp_row, textvariable=v_otp, font=(FONT_MONO, 10), bg=self._c("surface"), fg=self._c("text"), relief="flat", width=14).pack(side="left", ipady=5, padx=(0, 6))

            def send_otp_action() -> None:
                c_val = v_email.get().strip()
                if not c_val:
                    otp_status_lbl.configure(text="Enter your registered Email first.", fg=self._c("danger"))
                    return
                send_btn.configure(state="disabled", text="Sending...")

                def _worker() -> None:
                    err: Optional[str] = None
                    res = None
                    try:
                        res = self.db.send_recovery_otp(c_val)
                    except Exception as exc:
                        err = str(exc)

                    def _done() -> None:
                        if not dlg.winfo_exists():
                            return
                        send_btn.configure(state="normal", text="Send Gmail OTP")
                        if err:
                            otp_status_lbl.configure(text=err, fg=self._c("danger"))
                        elif res is not None:
                            otp_state["hash"], otp_state["salt"], otp_state["exp"] = res
                            otp_status_lbl.configure(text="6-digit OTP sent via Google SMTP! Enter it within 5 minutes.", fg=self._c("primary"))

                    self.after(0, _done)

                threading.Thread(target=_worker, daemon=True).start()

            send_btn = tk.Button(otp_row, text="Send Gmail OTP", command=send_otp_action, font=(FONT_UI, 9, "bold"), bg=self._c("primary"), fg=self._c("primary_fg"), relief="flat", padx=10, pady=4, cursor="hand2")
            send_btn.pack(side="left")
            otp_status_lbl.pack(fill="x", pady=(2, 4))

        add_input("Personal Recovery Key (XXXX-XXXX-XXXX-XXXX) *", v_rec_key)
        add_input("New Master Password (English, min 2 chars) *", v_new_pw, show_char="•")
        add_input("Confirm New Password *", v_confirm_pw, show_char="•")

        err_lbl = tk.Label(frame, text="", font=(FONT_UI, 9), bg=self._c("surface"), fg=self._c("danger"), wraplength=420, anchor="w")
        err_lbl.pack(fill="x", pady=(8, 0))

        def do_reset() -> None:
            if v_new_pw.get() != v_confirm_pw.get():
                err_lbl.configure(text="New password and confirmation do not match.")
                return
            if otp_state["required"]:
                if not otp_state["hash"] or time.time() > otp_state["exp"]:
                    err_lbl.configure(text="Please request and enter a valid 6-digit Gmail OTP first.")
                    return
                if not RecoveryEmailService.verify_otp(v_otp.get(), otp_state["salt"], otp_state["hash"]):
                    rem = self.db.record_recovery_otp_failure()
                    if rem > 0:
                        otp_state["hash"] = ""
                    msg = f"Invalid OTP code. Locked for {rem}s." if rem > 0 else "Invalid 6-digit OTP code."
                    err_lbl.configure(text=msg)
                    return
            try:
                dek = self.db.reset_password_via_recovery(v_email.get(), v_rec_key.get(), v_new_pw.get())
                self.dek = dek
                self._mark_activity()
                messagebox.showinfo("Password Reset", "Your master password has been reset and your vault is unlocked.", parent=dlg)
                dlg.destroy()
                self.show_vault_workspace()
            except Exception as exc:
                err_lbl.configure(text=str(exc))

        tk.Button(footer, text="Cancel", command=dlg.destroy, font=(FONT_UI, 10), bg=self._c("surface_alt"), fg=self._c("text"), relief="flat", padx=16, pady=8, cursor="hand2").pack(side="left")
        self._btn(footer, icon_name="key", text="  Reset Password & Unlock", command=do_reset, font=(FONT_UI, 10, "bold"), bg=self._c("primary"), fg=self._c("primary_fg"), activebackground=self._c("primary"), activeforeground=self._c("primary_fg"), relief="flat", padx=18, pady=8, cursor="hand2").pack(side="right", fill="x", expand=True, padx=(10, 0))

    def open_settings_dialog(self) -> None:
        dlg, frame, footer = self._create_scrollable_dialog("Settings", 560, 610, has_footer=True)

        settings = self.db.get_settings()
        meta = self.db.get_meta() or {}

        v_lock = tk.IntVar(value=int(settings.get("auto_lock_minutes", 5)))
        v_confirm_exit = tk.BooleanVar(value=bool(settings.get("confirm_on_close", True)))
        v_local_bkp = tk.BooleanVar(value=bool(settings.get("local_auto_backup", False)))
        v_backup_dir = tk.StringVar(value=str(settings.get("local_backup_dir") or BACKUP_DIR))
        v_online_bkp = tk.BooleanVar(value=bool(settings.get("online_auto_backup", False)))
        v_sync_url = tk.StringVar(value=settings.get("sync_url", "http://localhost:3000"))
        v_vault_id = tk.StringVar(value=settings.get("sync_vault_id", ""))

        menu_bar = tk.Frame(frame, bg=self._c("surface_alt"), padx=4, pady=4)
        menu_bar.pack(fill="x", pady=(0, 14))

        content_holder = tk.Frame(frame, bg=self._c("surface"))
        content_holder.pack(fill="both", expand=True)

        tab_general = tk.Frame(content_holder, bg=self._c("surface"))
        tab_backup = tk.Frame(content_holder, bg=self._c("surface"))
        tab_login = tk.Frame(content_holder, bg=self._c("surface"))

        tabs: Dict[str, Tuple[Any, Any]] = {}

        def switch_tab(name: str) -> None:
            for key, (panel, btn) in tabs.items():
                if key == name:
                    panel.pack(fill="both", expand=True)
                    btn.configure(bg=self._c("surface"), fg=self._c("text"), font=(FONT_UI, 9, "bold"))
                else:
                    panel.pack_forget()
                    btn.configure(bg=self._c("surface_alt"), fg=self._c("muted"), font=(FONT_UI, 9, "normal"))

        for key, label, icon_key, panel in [
            ("general", "General", "settings", tab_general),
            ("backup", "Backup & Sync", "cloud", tab_backup),
            ("login", "Login & Security", "lock", tab_login),
        ]:
            b = self._btn(
                menu_bar,
                icon_name=icon_key,
                text=f"  {label}",
                command=lambda k=key: switch_tab(k),
                font=(FONT_UI, 9),
                bg=self._c("surface_alt"),
                fg=self._c("muted"),
                relief="flat",
                padx=10,
                pady=7,
                cursor="hand2",
            )
            b.pack(side="left", fill="x", expand=True, padx=2)
            tabs[key] = (panel, b)

        # ---- General ----
        tk.Label(tab_general, text="General Settings", font=(FONT_UI, 12, "bold"), bg=self._c("surface"), fg=self._c("text"), anchor="w").pack(fill="x", pady=(0, 10))
        tk.Label(tab_general, text="Auto-Lock Timeout (minutes):", font=(FONT_UI, 9, "bold"), bg=self._c("surface"), fg=self._c("text"), anchor="w").pack(fill="x")
        tk.Spinbox(tab_general, from_=1, to=60, textvariable=v_lock).pack(fill="x", pady=(2, 12))
        tk.Checkbutton(
            tab_general,
            text="Ask for confirmation before closing application",
            variable=v_confirm_exit,
            font=(FONT_UI, 9),
            bg=self._c("surface"),
            fg=self._c("text"),
            activebackground=self._c("surface"),
            activeforeground=self._c("text"),
            selectcolor=self._c("surface_alt"),
            highlightthickness=0,
            anchor="w",
        ).pack(fill="x", pady=(0, 8))

        # ---- Backup & Sync ----
        tk.Label(tab_backup, text="Local Backup", font=(FONT_UI, 11, "bold"), bg=self._c("surface"), fg=self._c("primary"), anchor="w").pack(fill="x", pady=(0, 6))
        tk.Checkbutton(tab_backup, text="Local Auto-Backup on every change", variable=v_local_bkp, font=(FONT_UI, 9), bg=self._c("surface"), fg=self._c("text"), activebackground=self._c("surface"), activeforeground=self._c("text"), selectcolor=self._c("surface_alt"), highlightthickness=0, anchor="w").pack(fill="x")

        tk.Label(tab_backup, text="Local Backup Folder:", font=(FONT_UI, 9, "bold"), bg=self._c("surface"), fg=self._c("text"), anchor="w").pack(fill="x", pady=(6, 2))
        bkp_dir_row = tk.Frame(tab_backup, bg=self._c("surface"))
        bkp_dir_row.pack(fill="x", pady=(0, 8))
        bkp_dir_entry = tk.Entry(
            bkp_dir_row,
            textvariable=v_backup_dir,
            font=(FONT_UI, 9),
            bg=self._c("surface_alt"),
            fg=self._c("text"),
            insertbackground=self._c("primary"),
            relief="flat",
        )
        bkp_dir_entry.pack(side="left", fill="x", expand=True, ipady=6)

        def _selected_backup_dir() -> str:
            raw = (bkp_dir_entry.get() or v_backup_dir.get()).strip().strip('"').strip("'").strip()
            return raw or BACKUP_DIR

        def browse_backup_dir() -> None:
            chosen = filedialog.askdirectory(
                title="Select Local Backup Folder",
                initialdir=_selected_backup_dir(),
                parent=dlg,
            )
            if chosen:
                v_backup_dir.set(chosen)

        tk.Button(
            bkp_dir_row,
            text="Browse...",
            command=browse_backup_dir,
            font=(FONT_UI, 9),
            bg=self._c("surface_alt"),
            fg=self._c("text"),
            relief="flat",
            padx=10,
            pady=5,
            cursor="hand2",
        ).pack(side="left", padx=(6, 0))

        def create_backup_now() -> None:
            try:
                target_dir = _selected_backup_dir()
                saved_path = self.db.create_local_backup(target_dir)
                settings["local_backup_dir"] = target_dir
                self.db.save_settings(settings)
                v_backup_dir.set(target_dir)
                messagebox.showinfo("Backup Created", f"Saved to:\n{saved_path}", parent=dlg)
            except Exception as exc:
                messagebox.showerror("Backup Error", str(exc), parent=dlg)

        self._btn(
            tab_backup,
            icon_name="save_emerald",
            text="  Create Local Backup Now",
            command=create_backup_now,
            font=(FONT_UI, 9, "bold"),
            bg=self._c("surface_alt"),
            fg=self._c("text"),
            relief="flat",
            pady=8,
            cursor="hand2",
        ).pack(fill="x", pady=(0, 4))

        # Visual divider separating Local Backup from E2EE Cloud Sync
        tk.Frame(tab_backup, bg=self._c("border"), height=1).pack(fill="x", pady=(14, 12))

        tk.Label(tab_backup, text="E2EE Cloud Sync", font=(FONT_UI, 11, "bold"), bg=self._c("surface"), fg=self._c("primary"), anchor="w").pack(fill="x", pady=(0, 6))
        tk.Checkbutton(tab_backup, text="Online E2EE Auto-Backup on every change", variable=v_online_bkp, font=(FONT_UI, 9), bg=self._c("surface"), fg=self._c("text"), activebackground=self._c("surface"), activeforeground=self._c("text"), selectcolor=self._c("surface_alt"), highlightthickness=0, anchor="w").pack(fill="x", pady=(0, 10))

        tk.Label(tab_backup, text="E2EE Sync Server URL:", font=(FONT_UI, 9, "bold"), bg=self._c("surface"), fg=self._c("text"), anchor="w").pack(fill="x")
        tk.Entry(tab_backup, textvariable=v_sync_url, font=(FONT_UI, 10), bg=self._c("surface_alt"), fg=self._c("text"), relief="flat").pack(fill="x", ipady=6, pady=(2, 8))
        tk.Label(tab_backup, text="Cloud Vault ID:", font=(FONT_UI, 9, "bold"), bg=self._c("surface"), fg=self._c("text"), anchor="w").pack(fill="x")
        tk.Entry(tab_backup, textvariable=v_vault_id, font=(FONT_UI, 10), bg=self._c("surface_alt"), fg=self._c("text"), relief="flat").pack(fill="x", ipady=6, pady=(2, 4))
        tk.Label(
            tab_backup,
            text="Optional remote server for encrypted multi-device sync (server sees ciphertext only). Cloud Vault ID identifies your encrypted vault on that server.",
            font=(FONT_UI, 8),
            bg=self._c("surface"),
            fg=self._c("muted"),
            wraplength=470,
            justify="left",
            anchor="w",
        ).pack(fill="x", pady=(0, 10))

        def _persist_sync_fields() -> None:
            settings["sync_url"] = v_sync_url.get().strip()
            settings["sync_vault_id"] = v_vault_id.get().strip()
            self.db.save_settings(settings)

        def sync_now() -> None:
            if self.dek is None:
                return
            _persist_sync_fields()
            dek = self.dek
            sync_btn.configure(state="disabled", text="  Syncing...")

            def _worker() -> None:
                err: Optional[str] = None
                try:
                    self.db.push_cloud_sync(dek, is_auto_backup=False)
                except Exception as exc:
                    err = str(exc)

                def _done() -> None:
                    if not dlg.winfo_exists():
                        return
                    sync_btn.configure(state="normal", text="  Push Encrypted Sync Now")
                    if err:
                        messagebox.showerror("Sync Failed", err, parent=dlg)
                    else:
                        messagebox.showinfo("Sync Complete", "Encrypted snapshot uploaded successfully.", parent=dlg)

                self.after(0, _done)

            threading.Thread(target=_worker, daemon=True).start()

        def pull_now() -> None:
            if self.dek is None:
                return
            _persist_sync_fields()
            dek = self.dek
            pull_btn.configure(state="disabled", text="  Pulling...")

            def _worker() -> None:
                err: Optional[str] = None
                count = 0
                try:
                    count = self.db.pull_cloud_sync(dek)
                except Exception as exc:
                    err = str(exc)

                def _done() -> None:
                    if not dlg.winfo_exists():
                        return
                    pull_btn.configure(state="normal", text="  Pull & Decrypt from Cloud")
                    if err:
                        messagebox.showerror("Pull Failed", err, parent=dlg)
                    else:
                        self.reload_data()
                        self._build_sidebar()
                        self._build_list_pane()
                        self.refresh_entry_list()
                        self.render_detail_pane()
                        messagebox.showinfo("Pull Complete", f"Decrypted and synced {count} entries.", parent=dlg)

                self.after(0, _done)

            threading.Thread(target=_worker, daemon=True).start()

        sync_btn = self._btn(tab_backup, icon_name="cloud_upload", text="  Push Encrypted Sync Now", command=sync_now, font=(FONT_UI, 9, "bold"), bg=self._c("surface_alt"), fg=self._c("text"), relief="flat", pady=8, cursor="hand2")
        sync_btn.pack(fill="x", pady=3)
        pull_btn = self._btn(tab_backup, icon_name="cloud_download", text="  Pull & Decrypt from Cloud", command=pull_now, font=(FONT_UI, 9), bg=self._c("surface_alt"), fg=self._c("text"), relief="flat", pady=8, cursor="hand2")
        pull_btn.pack(fill="x", pady=3)

        # ---- Login & Security ----
        tk.Label(tab_login, text="Login & Master Password", font=(FONT_UI, 12, "bold"), bg=self._c("surface"), fg=self._c("text"), anchor="w").pack(fill="x", pady=(0, 10))

        initial_auth_mode = meta.get("auth_mode", "custom")
        auth_updated = {"done": False}
        v_auth_mode = tk.StringVar(value=initial_auth_mode)
        win_info_row = tk.Frame(tab_login, bg=self._c("surface_alt"), padx=10, pady=6)
        wu_icon = self._icon("user")
        if wu_icon is not None:
            wu_lbl = tk.Label(win_info_row, image=wu_icon, bg=self._c("surface_alt"))
            wu_lbl._img_ref = wu_icon
            wu_lbl.pack(side="left", padx=(0, 6))
        tk.Label(win_info_row, text=f"User: {WindowsAuthService.current_username()}", font=(FONT_UI, 9, "bold"), bg=self._c("surface_alt"), fg=self._c("text"), anchor="w").pack(side="left", fill="x", expand=True)

        mode_row = tk.Frame(tab_login, bg=self._c("surface"))
        mode_row.pack(fill="x", pady=(0, 6))

        v_cur_pw = tk.StringVar()
        v_new_pw = tk.StringVar()
        v_confirm_pw = tk.StringVar()

        tk.Label(tab_login, text="Current (Previous) Password *", font=(FONT_UI, 9, "bold"), bg=self._c("surface"), fg=self._c("text"), anchor="w").pack(fill="x")
        tk.Entry(tab_login, textvariable=v_cur_pw, show="•", font=(FONT_UI, 10), bg=self._c("surface_alt"), fg=self._c("text"), relief="flat").pack(fill="x", ipady=6, pady=(2, 6))

        new_pw_lbl = tk.Label(tab_login, text="New Password (English chars/numbers, min 2)", font=(FONT_UI, 9, "bold"), bg=self._c("surface"), fg=self._c("text"), anchor="w")
        new_pw_lbl.pack(fill="x")
        tk.Entry(tab_login, textvariable=v_new_pw, show="•", font=(FONT_UI, 10), bg=self._c("surface_alt"), fg=self._c("text"), relief="flat").pack(fill="x", ipady=6, pady=(2, 6))

        confirm_pw_box = tk.Frame(tab_login, bg=self._c("surface"))
        tk.Label(confirm_pw_box, text="Confirm New Password", font=(FONT_UI, 9, "bold"), bg=self._c("surface"), fg=self._c("text"), anchor="w").pack(fill="x")
        tk.Entry(confirm_pw_box, textvariable=v_confirm_pw, show="•", font=(FONT_UI, 10), bg=self._c("surface_alt"), fg=self._c("text"), relief="flat").pack(fill="x", ipady=6, pady=(2, 10))
        confirm_pw_box.pack(fill="x")

        def apply_auth_change() -> None:
            if self.dek is None:
                return
            if not v_cur_pw.get():
                messagebox.showwarning("Verification Required", "Please enter your current password first.", parent=dlg)
                return
            if v_auth_mode.get() == "custom" and v_new_pw.get() != v_confirm_pw.get():
                messagebox.showwarning("Mismatch", "New password and confirmation do not match.", parent=dlg)
                return
            try:
                self.db.update_auth_mode(self.dek, v_cur_pw.get(), v_auth_mode.get(), v_new_pw.get())
                auth_updated["done"] = True
                messagebox.showinfo("Updated", "Login settings and master key updated successfully.", parent=dlg)
                dlg.destroy()
            except Exception as exc:
                messagebox.showerror("Error", str(exc), parent=dlg)

        auth_update_btn = self._btn(tab_login, icon_name="lock", text="  Update Login Mode / Password", command=apply_auth_change, font=(FONT_UI, 9, "bold"), bg=self._c("surface_alt"), fg=self._c("text"), relief="flat", pady=8, cursor="hand2")
        auth_update_btn.pack(fill="x", pady=(2, 12))

        def sync_settings_win_banner(*_args: Any) -> None:
            if v_auth_mode.get() == "windows":
                win_info_row.pack(fill="x", pady=(0, 8), after=mode_row)
                new_pw_lbl.configure(text="Windows Password *")
                confirm_pw_box.pack_forget()
            else:
                win_info_row.pack_forget()
                new_pw_lbl.configure(text="New Password (English chars/numbers, min 2)")
                confirm_pw_box.pack(fill="x", before=auth_update_btn)

        tk.Radiobutton(
            mode_row,
            text="Custom Password",
            variable=v_auth_mode,
            value="custom",
            command=sync_settings_win_banner,
            font=(FONT_UI, 10),
            bg=self._c("surface"),
            fg=self._c("text"),
            activebackground=self._c("surface"),
            activeforeground=self._c("text"),
            selectcolor=self._c("surface_alt"),
            highlightthickness=0,
            bd=0,
            anchor="w",
            cursor="hand2",
        ).pack(side="left", padx=(0, 18))
        if WindowsAuthService.IS_WINDOWS:
            tk.Radiobutton(
                mode_row,
                text="Windows Password",
                variable=v_auth_mode,
                value="windows",
                command=sync_settings_win_banner,
                font=(FONT_UI, 10),
                bg=self._c("surface"),
                fg=self._c("text"),
                activebackground=self._c("surface"),
                activeforeground=self._c("text"),
                selectcolor=self._c("surface_alt"),
                highlightthickness=0,
                bd=0,
                anchor="w",
                cursor="hand2",
            ).pack(side="left")

        sync_settings_win_banner()

        # ---- Email Recovery + Google Gmail SMTP ----
        tk.Frame(tab_login, bg=self._c("border"), height=1).pack(fill="x", pady=(4, 12))
        tk.Label(tab_login, text="Email Recovery (Custom Mode)", font=(FONT_UI, 11, "bold"), bg=self._c("surface"), fg=self._c("text"), anchor="w").pack(fill="x")

        rec_info = self.db.get_recovery_info()
        rec_status_var = tk.StringVar(
            value=(f"Status: Enabled ({rec_info['email_masked']})" if rec_info.get("enabled") else "Status: Not configured")
        )
        tk.Label(tab_login, textvariable=rec_status_var, font=(FONT_UI, 9), bg=self._c("surface"), fg=self._c("primary") if rec_info.get("enabled") else self._c("muted"), anchor="w").pack(fill="x", pady=(2, 8))

        v_rec_email = tk.StringVar()
        tk.Label(tab_login, text="Recovery Email Address", font=(FONT_UI, 9, "bold"), bg=self._c("surface"), fg=self._c("text"), anchor="w").pack(fill="x")
        tk.Entry(tab_login, textvariable=v_rec_email, font=(FONT_UI, 10), bg=self._c("surface_alt"), fg=self._c("text"), relief="flat").pack(fill="x", ipady=6, pady=(2, 6))

        v_google_smtp = tk.BooleanVar(value=bool(rec_info.get("has_smtp", False)))
        smtp_frame = tk.Frame(tab_login, bg=self._c("surface_alt"), padx=10, pady=8)

        v_gmail_sender = tk.StringVar(value=str(rec_info.get("smtp_sender") or ""))
        v_gmail_app_pw = tk.StringVar()

        tk.Label(smtp_frame, text="Google SMTP: smtp.gmail.com (Port 587 TLS)", font=(FONT_UI, 8, "bold"), bg=self._c("surface_alt"), fg=self._c("primary"), anchor="w").pack(fill="x", pady=(0, 4))
        tk.Label(smtp_frame, text="Sender Gmail Address", font=(FONT_UI, 8, "bold"), bg=self._c("surface_alt"), fg=self._c("text"), anchor="w").pack(fill="x")
        tk.Entry(smtp_frame, textvariable=v_gmail_sender, font=(FONT_UI, 9), bg=self._c("surface"), fg=self._c("text"), relief="flat").pack(fill="x", ipady=4, pady=(1, 4))
        tk.Label(smtp_frame, text="Google App Password (16-char)", font=(FONT_UI, 8, "bold"), bg=self._c("surface_alt"), fg=self._c("text"), anchor="w").pack(fill="x")
        tk.Entry(smtp_frame, textvariable=v_gmail_app_pw, show="•", font=(FONT_UI, 9), bg=self._c("surface"), fg=self._c("text"), relief="flat").pack(fill="x", ipady=4, pady=(1, 2))

        def toggle_smtp_box() -> None:
            if v_google_smtp.get():
                smtp_frame.pack(fill="x", pady=(4, 8), after=chk_smtp)
            else:
                smtp_frame.pack_forget()

        chk_smtp = tk.Checkbutton(
            tab_login,
            text="Verify with 6-digit OTP via Google Gmail SMTP (optional)",
            variable=v_google_smtp,
            command=toggle_smtp_box,
            font=(FONT_UI, 9),
            bg=self._c("surface"),
            fg=self._c("text"),
            activebackground=self._c("surface"),
            activeforeground=self._c("text"),
            selectcolor=self._c("surface_alt"),
            highlightthickness=0,
            anchor="w",
        )
        chk_smtp.pack(fill="x", pady=(0, 6))
        if v_google_smtp.get():
            smtp_frame.pack(fill="x", pady=(4, 8))

        def save_recovery_cfg() -> None:
            if self.dek is None:
                return
            email_val = v_rec_email.get().strip()
            if not email_val:
                messagebox.showwarning("Missing Email", "Please enter a valid Recovery Email address.", parent=dlg)
                return
            smtp_cfg: Optional[Dict[str, Any]] = None
            if v_google_smtp.get():
                smtp_cfg = {
                    "enabled": True,
                    "sender_email": v_gmail_sender.get().strip() or email_val,
                    "app_password": v_gmail_app_pw.get().strip(),
                }
            try:
                rec_key = self.db.configure_recovery(self.dek, email_val, google_smtp=smtp_cfg)
                masked = self.db.get_recovery_info().get("email_masked", email_val)
                rec_status_var.set(f"Status: Enabled ({masked})")
                self._show_recovery_key_modal(rec_key, masked, parent_win=dlg)
            except Exception as exc:
                messagebox.showerror("Recovery Error", str(exc), parent=dlg)

        def disable_recovery_cfg() -> None:
            if not v_cur_pw.get():
                messagebox.showwarning("Verification Required", "Please enter your Current Password above first to disable recovery.", parent=dlg)
                return
            if not messagebox.askyesno("Disable Recovery", "Disable Email password recovery for this vault?", parent=dlg):
                return
            try:
                self.db.disable_recovery(v_cur_pw.get())
                rec_status_var.set("Status: Not configured")
                messagebox.showinfo("Disabled", "Password recovery has been disabled.", parent=dlg)
            except Exception as exc:
                messagebox.showerror("Error", str(exc), parent=dlg)

        rec_btn_row = tk.Frame(tab_login, bg=self._c("surface"))
        rec_btn_row.pack(fill="x", pady=(2, 8))
        self._btn(
            rec_btn_row,
            icon_name="key",
            text="  Save Email & Generate Key",
            command=save_recovery_cfg,
            font=(FONT_UI, 9, "bold"),
            bg=self._c("primary"),
            fg=self._c("primary_fg"),
            activebackground=self._c("primary"),
            activeforeground=self._c("primary_fg"),
            relief="flat",
            padx=12,
            pady=7,
            cursor="hand2",
        ).pack(side="left", fill="x", expand=True)
        tk.Button(
            rec_btn_row,
            text="Disable",
            command=disable_recovery_cfg,
            font=(FONT_UI, 9),
            bg=self._c("surface_alt"),
            fg=self._c("text"),
            relief="flat",
            padx=12,
            pady=7,
            cursor="hand2",
        ).pack(side="left", padx=(6, 0))

        switch_tab("general")

        def save_set() -> None:
            if not auth_updated["done"] and v_auth_mode.get() != initial_auth_mode:
                switch_tab("login")
                messagebox.showwarning(
                    "Unsaved Login Mode",
                    "Please click 'Update Login Mode / Password' first before saving.",
                    parent=dlg,
                )
                return
            settings["auto_lock_minutes"] = int(v_lock.get())
            settings["confirm_on_close"] = v_confirm_exit.get()
            settings["local_auto_backup"] = v_local_bkp.get()
            settings["local_backup_dir"] = _selected_backup_dir()
            settings["online_auto_backup"] = v_online_bkp.get()
            settings["sync_url"] = v_sync_url.get().strip()
            settings["sync_vault_id"] = v_vault_id.get().strip()
            self.db.save_settings(settings)
            messagebox.showinfo("Saved", "Settings updated successfully.", parent=dlg)
            dlg.destroy()

        self._btn(footer, icon_name="save", text="  Save Settings", command=save_set, font=(FONT_UI, 10, "bold"), bg=self._c("primary"), fg=self._c("primary_fg"), activebackground=self._c("primary"), activeforeground=self._c("primary_fg"), relief="flat", pady=9, cursor="hand2").pack(fill="x")

    def open_about_dialog(self) -> None:
        dlg, frame, footer = self._create_scrollable_dialog("About Pass.py", 470, 495, has_footer=True)

        brand_key = "brandLogoLargeDark" if self.theme_name == "dark" else "brandLogoLarge"
        brand_img = self.logos.get_named_photo(brand_key)
        if brand_img is not None:
            b_lbl = tk.Label(frame, image=brand_img, bg=self._c("surface"))
            b_lbl._img_ref = brand_img
            b_lbl.pack(anchor="center", pady=(8, 4))
        else:
            tk.Label(frame, text="Pass.py", font=(FONT_UI, 18, "bold"), bg=self._c("surface"), fg=self._c("primary")).pack(anchor="center", pady=(8, 4))

        tk.Label(
            frame,
            text=f"Version {APP_VERSION.lstrip('vV')}",
            font=(FONT_UI, 9, "bold"),
            bg=self._c("surface"),
            fg=self._c("muted"),
        ).pack(anchor="center", pady=(0, 12))

        card = tk.Frame(
            frame,
            bg=self._c("surface_alt"),
            highlightbackground=self._c("border"),
            highlightthickness=1,
            padx=16,
            pady=14,
        )
        card.pack(fill="x", pady=(0, 10))

        tk.Label(
            card,
            text=(
                "Pass.py is a zero-knowledge desktop password manager designed for private, "
                "offline credential storage and multi-profile organization on Windows."
            ),
            font=(FONT_UI, 9),
            bg=self._c("surface_alt"),
            fg=self._c("text"),
            justify="left",
            wraplength=390,
            anchor="w",
        ).pack(fill="x", pady=(0, 10))

        tk.Label(
            card,
            text="Security Architecture",
            font=(FONT_UI, 9, "bold"),
            bg=self._c("surface_alt"),
            fg=self._c("primary"),
            anchor="w",
        ).pack(fill="x", pady=(0, 3))
        tk.Label(
            card,
            text=(
                "• Encryption: AES-256-GCM & PBKDF2-HMAC-SHA256 (600,000 iterations)\n"
                "• Authentication: Custom master password or Windows account (DPAPI)\n"
                "• Backups & Recovery: Local vault snapshots, optional E2EE sync & Gmail OTP"
            ),
            font=(FONT_UI, 8),
            bg=self._c("surface_alt"),
            fg=self._c("text"),
            justify="left",
            wraplength=390,
            anchor="w",
        ).pack(fill="x", pady=(0, 10))

        tk.Label(
            card,
            text="Technology Stack",
            font=(FONT_UI, 9, "bold"),
            bg=self._c("surface_alt"),
            fg=self._c("primary"),
            anchor="w",
        ).pack(fill="x", pady=(0, 3))
        tk.Label(
            card,
            text=(
                "• Python 3 (Modular OOP) · Tkinter / ttk · SQLite3\n"
                "• cryptography · Windows Win32 API (advapi32, crypt32, gdiplus)\n"
                "• smtplib (TLS Email OTP) · Pillow (optional fast thumbnails)"
            ),
            font=(FONT_UI, 8),
            bg=self._c("surface_alt"),
            fg=self._c("muted"),
            justify="left",
            wraplength=390,
            anchor="w",
        ).pack(fill="x")

        gh_url = "https://github.com/samimi-dev/"
        gh_icon_name = "github_light" if self.theme_name == "dark" else "github_dark"
        gh_img = self.logos.get_ui_icon(gh_icon_name) or self.logos.get_logo_photo("github", "", [], size=32)

        gh_wrap = tk.Frame(footer, bg=self._c("surface"))
        gh_wrap.pack(anchor="center")

        gh_btn = tk.Button(
            gh_wrap,
            image=gh_img if gh_img is not None else "",
            text="" if gh_img is not None else "GitHub",
            command=lambda: webbrowser.open(gh_url, new=2),
            font=(FONT_UI, 9, "bold"),
            bg=self._c("surface"),
            activebackground=self._c("surface_alt"),
            fg=self._c("text"),
            bd=0,
            highlightthickness=0,
            relief="flat",
            padx=8,
            pady=4,
            cursor="hand2",
        )
        if gh_img is not None:
            gh_btn._img_ref = gh_img
        gh_btn.pack(anchor="center")

        gh_lbl = tk.Label(
            gh_wrap,
            text="github.com/samimi-dev",
            font=(FONT_UI, 8),
            bg=self._c("surface"),
            fg=self._c("muted"),
            cursor="hand2",
        )
        gh_lbl.pack(anchor="center")
        gh_lbl.bind("<Button-1>", lambda _e: webbrowser.open(gh_url, new=2))
