# -*- coding: utf-8 -*-
"""Entry, Category, Custom Logo, People, and Password Generator modal dialogs."""

import datetime
import os
from typing import Any, Dict, List, Optional, Tuple

from .assets import POPULAR_SITE_LOGOS
from .calendar_picker import CalendarDatePicker
from .image_validator import ImageValidator
from .password_generator import PasswordGeneratorService
from .theme import FONT_MONO, FONT_UI

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
except ImportError:
    tk = None  # type: ignore
    filedialog = None  # type: ignore
    messagebox = None  # type: ignore
    ttk = None  # type: ignore


class VaultEntryDialogsMixin:
    """Modal dialogs for entries, categories, logos, people, and password generation."""

    def open_entry_dialog(self, existing: Optional[Dict[str, Any]]) -> None:
        dlg, frame, footer = self._create_scrollable_dialog(
            "Edit Entry" if existing else "Add New Password", 560, 620, has_footer=True
        )

        def add_field(lbl: str, initial: str = "") -> tk.StringVar:
            tk.Label(frame, text=lbl, font=(FONT_UI, 9, "bold"), bg=self._c("surface"), fg=self._c("text"), anchor="w").pack(fill="x", pady=(8, 2))
            var = tk.StringVar(value=initial)
            tk.Entry(
                frame,
                textvariable=var,
                font=(FONT_UI, 10),
                bg=self._c("surface_alt"),
                fg=self._c("text"),
                insertbackground=self._c("primary"),
                relief="flat",
            ).pack(fill="x", ipady=6)
            return var

        v_title = add_field("Title *", existing["title"] if existing else "")
        v_site = add_field("Website", existing.get("site_url", "") if existing else "")

        tk.Label(frame, text="Site Logo (PNG, JPG, JPEG, GIF)", font=(FONT_UI, 9, "bold"), bg=self._c("surface"), fg=self._c("text"), anchor="w").pack(fill="x", pady=(8, 2))
        logo_row = tk.Frame(frame, bg=self._c("surface"))
        logo_row.pack(fill="x")

        def _build_logo_options() -> List[Tuple[str, str]]:
            return [
                (f"Custom: {cl['label']}", f"custom:{cl['id']}") for cl in self.custom_logos
            ] + [(info["label"], key) for key, info in POPULAR_SITE_LOGOS.items()]

        logo_options: List[Tuple[str, str]] = _build_logo_options()
        logo_labels: List[str] = [opt[0] for opt in logo_options]
        logo_keys: List[str] = [opt[1] for opt in logo_options]

        preview_holder = tk.Frame(logo_row, bg=self._c("surface"))
        preview_holder.pack(side="left", padx=(0, 8))

        logo_combo = ttk.Combobox(logo_row, values=logo_labels, state="readonly")
        cur_logo = existing.get("logo_key", "globe") if existing else "globe"
        logo_combo.current(logo_keys.index(cur_logo) if cur_logo in logo_keys else len(logo_keys) - 1)
        logo_combo.pack(side="left", fill="x", expand=True)

        custom_logo_state = {
            "b64": existing.get("custom_logo_b64", "") if existing else "",
            "mime": existing.get("custom_logo_mime", "image/png") if existing else "image/png",
            "file": existing.get("custom_logo_file", "") if existing else "",
        }

        def refresh_logo_preview(*_args: Any) -> None:
            for w in preview_holder.winfo_children():
                w.destroy()
            idx = logo_combo.current()
            selected_key = logo_keys[idx] if idx >= 0 else "globe"
            badge = self.logos.create_badge_label(
                preview_holder,
                selected_key,
                custom_logo_state["b64"],
                self.custom_logos,
                size=36,
                custom_logo_file=custom_logo_state["file"],
            )
            badge.pack()

        def on_logo_combo_selected(*_args: Any) -> None:
            custom_logo_state["b64"] = ""
            custom_logo_state["file"] = ""
            refresh_logo_preview()

        logo_combo.bind("<<ComboboxSelected>>", on_logo_combo_selected)
        refresh_logo_preview()

        def pick_custom_logo() -> None:
            path = filedialog.askopenfilename(
                title="Select Logo (PNG, JPG, JPEG, GIF)",
                filetypes=[("Allowed Images", "*.png *.jpg *.jpeg *.gif")],
                parent=dlg,
            )
            if not path:
                return
            try:
                mime, b64 = ImageValidator.validate_and_encode(path)
                matched = next((cl for cl in self.custom_logos if cl.get("data_b64") == b64), None)
                if matched:
                    cid = matched["id"]
                else:
                    file_stem = os.path.splitext(os.path.basename(path))[0].replace("_", " ").replace("-", " ").strip()
                    logo_label = (v_title.get().strip() or file_stem or "Custom Logo")[:40]
                    domain_kw = v_site.get().strip().lower()
                    cid = self.db.add_custom_logo(logo_label, domain_kw, mime, b64)
                    self.custom_logos = self.db.list_custom_logos()
                    logo_options[:] = _build_logo_options()
                    logo_labels[:] = [opt[0] for opt in logo_options]
                    logo_keys[:] = [opt[1] for opt in logo_options]
                    logo_combo.configure(values=logo_labels)

                target_key = f"custom:{cid}"
                if target_key in logo_keys:
                    logo_combo.current(logo_keys.index(target_key))
                custom_logo_state["b64"] = ""
                custom_logo_state["mime"] = mime
                custom_logo_state["file"] = ""
                refresh_logo_preview()
                messagebox.showinfo("Logo Saved", "Image saved to Default Logos and selected for this entry.", parent=dlg)
            except Exception as exc:
                messagebox.showerror("Invalid Image", str(exc), parent=dlg)

        def clear_custom_logo() -> None:
            custom_logo_state["b64"] = ""
            custom_logo_state["file"] = ""
            refresh_logo_preview()

        self._btn(logo_row, icon_name="image", text="  Upload", command=pick_custom_logo, font=(FONT_UI, 9), bg=self._c("surface_alt"), fg=self._c("text"), relief="flat", padx=8, pady=4, cursor="hand2").pack(side="left", padx=(6, 0))
        tk.Button(logo_row, text="Clear", command=clear_custom_logo, font=(FONT_UI, 9), bg=self._c("surface_alt"), fg=self._c("text"), relief="flat", padx=8, pady=4, cursor="hand2").pack(side="left", padx=(4, 0))

        v_user = add_field("Username", existing.get("username", "") if existing else "")
        v_is_email = tk.BooleanVar(value=existing.get("username_is_email", False) if existing else False)

        email_container = tk.Frame(frame, bg=self._c("surface"))
        tk.Label(email_container, text="Email", font=(FONT_UI, 9, "bold"), bg=self._c("surface"), fg=self._c("text"), anchor="w").pack(fill="x", pady=(6, 2))
        v_email = tk.StringVar(value=existing.get("email", "") if existing else "")
        tk.Entry(email_container, textvariable=v_email, font=(FONT_UI, 10), bg=self._c("surface_alt"), fg=self._c("text"), relief="flat").pack(fill="x", ipady=6)

        def sync_email_visibility() -> None:
            if v_is_email.get():
                email_container.pack_forget()
            else:
                email_container.pack(fill="x", after=chk_email)

        chk_email = tk.Checkbutton(
            frame,
            text="Username is the same as Email",
            variable=v_is_email,
            command=sync_email_visibility,
            font=(FONT_UI, 9),
            bg=self._c("surface"),
            fg=self._c("text"),
            activebackground=self._c("surface"),
            activeforeground=self._c("text"),
            selectcolor=self._c("surface_alt"),
            highlightthickness=0,
            anchor="w",
        )
        chk_email.pack(fill="x", pady=(6, 2))
        if not v_is_email.get():
            email_container.pack(fill="x")

        tk.Label(frame, text="Password *", font=(FONT_UI, 9, "bold"), bg=self._c("surface"), fg=self._c("text"), anchor="w").pack(fill="x", pady=(8, 2))
        pw_row = tk.Frame(frame, bg=self._c("surface"))
        pw_row.pack(fill="x")
        v_pw = tk.StringVar(value=existing.get("password", "") if existing else "")
        tk.Entry(pw_row, textvariable=v_pw, font=(FONT_MONO, 10), bg=self._c("surface_alt"), fg=self._c("text"), relief="flat").pack(side="left", fill="x", expand=True, ipady=6)
        self._btn(
            pw_row,
            icon_name="wand",
            text="  Generate (8)",
            command=lambda: v_pw.set(PasswordGeneratorService.generate(8, True, True, True, True)),
            font=(FONT_UI, 9, "bold"),
            bg=self._c("surface_alt"),
            fg=self._c("text"),
            relief="flat",
            padx=10,
            pady=5,
            cursor="hand2",
        ).pack(side="left", padx=(6, 0))

        update_entry_strength, entry_strength_box = self._create_strength_meter(frame)
        entry_strength_box.pack(fill="x", pady=(6, 2))
        v_pw.trace_add("write", lambda *_: update_entry_strength(v_pw.get()))
        update_entry_strength(v_pw.get())

        tk.Label(frame, text="Category & Person", font=(FONT_UI, 9, "bold"), bg=self._c("surface"), fg=self._c("text"), anchor="w").pack(fill="x", pady=(10, 2))
        meta_row = tk.Frame(frame, bg=self._c("surface"))
        meta_row.pack(fill="x")

        cat_combo = ttk.Combobox(meta_row, values=self.categories, state="readonly")
        initial_cat = existing.get("category", self.categories[0] if self.categories else "General") if existing else (self.categories[0] if self.categories else "General")
        cat_combo.set(initial_cat if initial_cat in self.categories else self.categories[0])
        cat_combo.pack(side="left", fill="x", expand=True)

        def quick_add_category() -> None:
            pop = tk.Toplevel(dlg)
            pop.title("New Category")
            pop.configure(bg=self._c("surface"))
            pop.transient(dlg)
            self._center_dialog(pop, 320, 145, parent=dlg)
            pop.grab_set()

            def _restore_dlg_grab(e: Any) -> None:
                if e.widget is pop and dlg.winfo_exists():
                    try:
                        dlg.grab_set()
                    except Exception:
                        pass

            pop.bind("<Destroy>", _restore_dlg_grab)
            tk.Label(pop, text="Category Name:", font=(FONT_UI, 9, "bold"), bg=self._c("surface"), fg=self._c("text"), anchor="w").pack(fill="x", padx=16, pady=(14, 4))
            v_new_cat = tk.StringVar()
            ent = tk.Entry(pop, textvariable=v_new_cat, font=(FONT_UI, 10), bg=self._c("surface_alt"), fg=self._c("text"), relief="flat")
            ent.pack(fill="x", padx=16, ipady=6)
            ent.focus_set()

            def do_create(_e: Any = None) -> None:
                try:
                    created = self.db.add_category(v_new_cat.get())
                    self.categories = self.db.list_categories()
                    cat_combo.configure(values=self.categories)
                    cat_combo.set(created)
                    self._build_list_pane()
                    pop.destroy()
                except Exception as exc:
                    messagebox.showerror("Error", str(exc), parent=pop)

            ent.bind("<Return>", do_create)
            self._btn(pop, icon_name="plus", text="  Add Category", command=do_create, font=(FONT_UI, 9, "bold"), bg=self._c("primary"), fg=self._c("primary_fg"), activebackground=self._c("primary"), activeforeground=self._c("primary_fg"), relief="flat", pady=6).pack(fill="x", padx=16, pady=12)

        self._btn(meta_row, icon_name="plus_green", text="  New", command=quick_add_category, font=(FONT_UI, 9, "bold"), bg=self._c("surface_alt"), fg=self._c("text"), relief="flat", padx=8, pady=4, cursor="hand2").pack(side="left", padx=(4, 8))

        person_names = [p["name"] for p in self.people]
        person_combo = ttk.Combobox(meta_row, values=person_names, state="readonly")
        default_pid = (
            self.filter_person
            if (self.filter_person != "all" and any(p["id"] == self.filter_person for p in self.people))
            else self.people[0]["id"]
        )
        cur_pid = existing.get("person_id", default_pid) if existing else default_pid
        person_combo.current(next((i for i, p in enumerate(self.people) if p["id"] == cur_pid), 0))
        person_avatar_lbl = tk.Label(meta_row, bg=self._c("surface"))
        person_avatar_lbl.pack(side="left", padx=(0, 6))
        person_combo.pack(side="left", fill="x", expand=True)

        def refresh_entry_person_avatar(*_args: Any) -> None:
            idx = person_combo.current()
            sel_person = self.people[idx] if 0 <= idx < len(self.people) else (self.people[0] if self.people else None)
            av_img = self.logos.get_person_avatar_photo(sel_person, size=26, fallback_ui_icon="user")
            if av_img is not None:
                person_avatar_lbl.configure(image=av_img)
                person_avatar_lbl._img_ref = av_img

        person_combo.bind("<<ComboboxSelected>>", refresh_entry_person_avatar)
        refresh_entry_person_avatar()

        v_tags = add_field("Tags (comma separated)", ", ".join(existing.get("tags", [])) if existing else "")

        tk.Label(frame, text="Notes", font=(FONT_UI, 9, "bold"), bg=self._c("surface"), fg=self._c("text"), anchor="w").pack(fill="x", pady=(8, 2))
        notes_wrap = tk.Frame(
            frame,
            bg=self._c("surface_alt"),
            highlightbackground=self._c("border"),
            highlightthickness=1,
            padx=6,
            pady=4,
        )
        notes_wrap.pack(fill="x")
        notes_text = tk.Text(
            notes_wrap,
            height=5,
            wrap="word",
            undo=True,
            font=(FONT_UI, 10),
            bg=self._c("surface_alt"),
            fg=self._c("text"),
            insertbackground=self._c("primary"),
            relief="flat",
            bd=0,
            highlightthickness=0,
        )
        notes_text.pack(fill="both", expand=True)
        if existing and existing.get("notes"):
            notes_text.insert("1.0", existing["notes"])

        tk.Label(frame, text="Created Date (YYYY-MM-DD)", font=(FONT_UI, 9, "bold"), bg=self._c("surface"), fg=self._c("text"), anchor="w").pack(fill="x", pady=(8, 2))
        date_row = tk.Frame(frame, bg=self._c("surface"))
        date_row.pack(fill="x")
        v_date = tk.StringVar(value=(existing.get("created_at", "") if existing else datetime.date.today().isoformat()))
        tk.Entry(date_row, textvariable=v_date, font=(FONT_UI, 10), bg=self._c("surface_alt"), fg=self._c("text"), insertbackground=self._c("primary"), relief="flat").pack(side="left", fill="x", expand=True, ipady=6)
        self._btn(
            date_row,
            icon_name="calendar",
            text="  Pick Date",
            command=lambda: CalendarDatePicker.open(dlg, self.theme_name, v_date.get(), v_date.set, self._center_dialog),
            font=(FONT_UI, 9, "bold"),
            bg=self._c("surface_alt"),
            fg=self._c("text"),
            relief="flat",
            padx=10,
            pady=4,
            cursor="hand2",
        ).pack(side="left", padx=(6, 0))

        v_fav = tk.BooleanVar(value=existing.get("is_favorite", False) if existing else False)
        tk.Checkbutton(frame, text="Add to Favorites", variable=v_fav, font=(FONT_UI, 9), bg=self._c("surface"), fg=self._c("text"), activebackground=self._c("surface"), activeforeground=self._c("text"), selectcolor=self._c("surface_alt"), highlightthickness=0, anchor="w").pack(fill="x", pady=(8, 6))

        def save_action() -> None:
            if not v_title.get().strip() or not v_pw.get():
                messagebox.showwarning("Missing Information", "Please enter both Title and Password.", parent=dlg)
                return
            if self.dek is None:
                return
            chosen_logo = logo_keys[logo_combo.current()] if logo_combo.current() >= 0 else ImageValidator.match_logo_key(v_site.get(), v_title.get(), self.custom_logos)
            raw_date = v_date.get().strip()
            if raw_date:
                try:
                    datetime.date.fromisoformat(raw_date)
                except ValueError:
                    messagebox.showwarning("Invalid Date", "Please use YYYY-MM-DD format or pick a date from the calendar.", parent=dlg)
                    return
            payload = {
                "id": existing["id"] if existing else None,
                "title": v_title.get(),
                "site_url": v_site.get(),
                "logo_key": chosen_logo,
                "custom_logo_b64": custom_logo_state["b64"],
                "custom_logo_mime": custom_logo_state["mime"],
                "username": v_user.get(),
                "username_is_email": v_is_email.get(),
                "email": v_email.get(),
                "password": v_pw.get(),
                "category": cat_combo.get(),
                "person_id": self.people[person_combo.current()]["id"],
                "tags": [t.strip() for t in v_tags.get().replace("،", ",").split(",") if t.strip()],
                "notes": notes_text.get("1.0", "end-1c").strip(),
                "created_at": raw_date or datetime.date.today().isoformat(),
                "is_favorite": v_fav.get(),
            }
            eid = self.db.save_entry(payload, self.dek)
            self.selected_entry_id = eid
            self._on_data_mutated()
            self.reload_data()
            self._build_list_pane()
            self.refresh_entry_list()
            self.render_detail_pane()
            dlg.destroy()

        tk.Button(footer, text="Cancel", command=dlg.destroy, font=(FONT_UI, 10), bg=self._c("surface_alt"), fg=self._c("text"), relief="flat", padx=18, pady=9, cursor="hand2").pack(side="left")
        self._btn(footer, icon_name="save", text="  Save to Vault", command=save_action, font=(FONT_UI, 10, "bold"), bg=self._c("primary"), fg=self._c("primary_fg"), activebackground=self._c("primary"), activeforeground=self._c("primary_fg"), relief="flat", padx=20, pady=9, cursor="hand2").pack(side="right", fill="x", expand=True, padx=(10, 0))

    def open_categories_manager(self) -> None:
        dlg, frame, footer = self._create_scrollable_dialog("Manage Categories", 460, 480, has_footer=True)
        tk.Label(frame, text="Categories", font=(FONT_UI, 13, "bold"), bg=self._c("surface"), fg=self._c("text"), anchor="w").pack(fill="x", pady=(0, 8))

        list_box = tk.Frame(frame, bg=self._c("surface"))
        list_box.pack(fill="x")
        editing_old: Dict[str, Optional[str]] = {"val": None}
        v_cat = tk.StringVar()

        def render_cats() -> None:
            for w in list_box.winfo_children():
                w.destroy()
            cats = self.db.list_categories()
            for c in cats:
                r = tk.Frame(list_box, bg=self._c("surface_alt"), padx=10, pady=8)
                r.pack(fill="x", pady=3)
                tk.Label(r, text=c, font=(FONT_UI, 10), bg=self._c("surface_alt"), fg=self._c("text"), anchor="w").pack(side="left", fill="x", expand=True)
                if len(cats) > 1:
                    self._btn(r, icon_name="trash", text="  Delete", command=lambda name=c: delete_cat(name), font=(FONT_UI, 9), bg=self._c("danger"), fg="#FFFFFF", activebackground=self._c("danger"), activeforeground="#FFFFFF", relief="flat", padx=8, cursor="hand2").pack(side="right", padx=(6, 0))
                self._btn(r, icon_name="edit", text="  Edit", command=lambda name=c: start_edit(name), font=(FONT_UI, 9), bg=self._c("surface"), fg=self._c("text"), relief="flat", padx=8, cursor="hand2").pack(side="right")

        def start_edit(name: str) -> None:
            editing_old["val"] = name
            v_cat.set(name)
            save_btn.configure(text="  Save Rename")

        def delete_cat(name: str) -> None:
            if self.dek is not None and messagebox.askyesno("Confirm Deletion", f"Delete category '{name}'? Entries will be reassigned.", parent=dlg):
                try:
                    self.db.delete_category(name, self.dek)
                    if self.filter_category == name:
                        self.filter_category = "all"
                    self.reload_data()
                    self._build_list_pane()
                    self.refresh_entry_list()
                    self.render_detail_pane()
                    render_cats()
                except Exception as exc:
                    messagebox.showerror("Error", str(exc), parent=dlg)

        render_cats()
        tk.Entry(footer, textvariable=v_cat, font=(FONT_UI, 10), bg=self._c("surface_alt"), fg=self._c("text"), relief="flat").pack(fill="x", ipady=7, pady=(0, 8))

        def save_cat() -> None:
            if self.dek is None:
                return
            try:
                if editing_old["val"]:
                    old_cat = editing_old["val"]
                    renamed = self.db.rename_category(old_cat, v_cat.get(), self.dek)
                    if self.filter_category == old_cat:
                        self.filter_category = renamed
                    editing_old["val"] = None
                    save_btn.configure(text="  Add Category")
                else:
                    self.db.add_category(v_cat.get())
                v_cat.set("")
                self.reload_data()
                self._build_list_pane()
                self.refresh_entry_list()
                self.render_detail_pane()
                render_cats()
            except Exception as exc:
                messagebox.showerror("Error", str(exc), parent=dlg)

        save_btn = self._btn(footer, icon_name="plus", text="  Add Category", command=save_cat, font=(FONT_UI, 10, "bold"), bg=self._c("primary"), fg=self._c("primary_fg"), activebackground=self._c("primary"), activeforeground=self._c("primary_fg"), relief="flat", pady=8, cursor="hand2")
        save_btn.pack(fill="x")

    def open_custom_logos_manager(self) -> None:
        dlg, frame, footer = self._create_scrollable_dialog("Custom Default Logos", 500, 540, has_footer=True)
        tk.Label(frame, text="Custom Default Logos (PNG, JPG, JPEG, GIF)", font=(FONT_UI, 12, "bold"), bg=self._c("surface"), fg=self._c("text"), anchor="w").pack(fill="x", pady=(0, 2))
        tk.Label(frame, text=f"Saved in: {self.db.logos_dir}", font=(FONT_UI, 8), bg=self._c("surface"), fg=self._c("muted"), anchor="w", wraplength=440).pack(fill="x", pady=(0, 8))

        list_box = tk.Frame(frame, bg=self._c("surface"))
        list_box.pack(fill="x")

        def render_logos() -> None:
            for w in list_box.winfo_children():
                w.destroy()
            logos = self.db.list_custom_logos()
            if not logos:
                tk.Label(list_box, text="No custom default logos saved yet.", font=(FONT_UI, 9), bg=self._c("surface"), fg=self._c("muted")).pack(pady=16)
                return
            for cl in logos:
                r = tk.Frame(list_box, bg=self._c("surface_alt"), padx=10, pady=8)
                r.pack(fill="x", pady=4)
                badge = self.logos.create_badge_label(
                    r,
                    f"custom:{cl['id']}",
                    cl["data_b64"],
                    logos,
                    size=36,
                    custom_logo_file=cl.get("file_name", ""),
                )
                badge.pack(side="left", padx=(0, 10))
                tk.Label(r, text=f"{cl['label']} ({cl.get('domain') or 'manual'})", font=(FONT_UI, 10), bg=self._c("surface_alt"), fg=self._c("text"), anchor="w").pack(side="left", fill="x", expand=True)
                self._btn(r, icon_name="trash", text="  Delete", command=lambda lid=cl["id"]: delete_logo(lid), font=(FONT_UI, 9), bg=self._c("danger"), fg="#FFFFFF", activebackground=self._c("danger"), activeforeground="#FFFFFF", relief="flat", padx=8, cursor="hand2").pack(side="right")

        def delete_logo(lid: str) -> None:
            if self.dek is None:
                return
            self.db.delete_custom_logo(lid, self.dek)
            self.reload_data()
            self.refresh_entry_list()
            self.render_detail_pane()
            render_logos()

        render_logos()

        tk.Frame(frame, bg=self._c("border"), height=1).pack(fill="x", pady=12)
        v_label = tk.StringVar()
        v_domain = tk.StringVar()
        uploaded = {"mime": "", "b64": ""}

        tk.Label(frame, text="Logo Name *", font=(FONT_UI, 9, "bold"), bg=self._c("surface"), fg=self._c("text"), anchor="w").pack(fill="x")
        tk.Entry(frame, textvariable=v_label, font=(FONT_UI, 10), bg=self._c("surface_alt"), fg=self._c("text"), relief="flat").pack(fill="x", ipady=6, pady=(2, 6))
        tk.Label(frame, text="Domain Keyword (e.g. mybank.ir)", font=(FONT_UI, 9, "bold"), bg=self._c("surface"), fg=self._c("text"), anchor="w").pack(fill="x")
        tk.Entry(frame, textvariable=v_domain, font=(FONT_UI, 10), bg=self._c("surface_alt"), fg=self._c("text"), relief="flat").pack(fill="x", ipady=6, pady=(2, 8))

        def pick_file() -> None:
            path = filedialog.askopenfilename(title="Select Default Logo (PNG, JPG, JPEG, GIF)", filetypes=[("Allowed Images", "*.png *.jpg *.jpeg *.gif")], parent=dlg)
            if not path:
                return
            try:
                mime, b64 = ImageValidator.validate_and_encode(path, max_dim=256)
                uploaded["mime"] = mime
                uploaded["b64"] = b64
                status_lbl.configure(text=f"Ready: {os.path.basename(path)}", fg=self._c("text"))
            except Exception as exc:
                messagebox.showerror("Invalid Image", str(exc), parent=dlg)

        def save_logo() -> None:
            if not uploaded["b64"]:
                messagebox.showwarning("Missing Image", "Please select a PNG, JPG, JPEG, or GIF image first.", parent=dlg)
                return
            try:
                self.db.add_custom_logo(v_label.get(), v_domain.get(), uploaded["mime"], uploaded["b64"])
                v_label.set("")
                v_domain.set("")
                uploaded["b64"] = ""
                status_lbl.configure(text="Saved!", fg=self._c("primary"))
                self.reload_data()
                render_logos()
            except Exception as exc:
                messagebox.showerror("Error", str(exc), parent=dlg)

        pick_row = tk.Frame(frame, bg=self._c("surface"))
        pick_row.pack(fill="x", pady=(2, 4))
        self._btn(pick_row, icon_name="image", text="  Choose Image", command=pick_file, font=(FONT_UI, 9), bg=self._c("surface_alt"), fg=self._c("text"), relief="flat", padx=12, pady=7, cursor="hand2").pack(side="left")
        status_lbl = tk.Label(pick_row, text="No image selected", font=(FONT_UI, 9), bg=self._c("surface"), fg=self._c("muted"), anchor="w")
        status_lbl.pack(side="left", fill="x", expand=True, padx=(10, 0))

        self._btn(footer, icon_name="save", text="  Save Default Logo", command=save_logo, font=(FONT_UI, 10, "bold"), bg=self._c("primary"), fg=self._c("primary_fg"), activebackground=self._c("primary"), activeforeground=self._c("primary_fg"), relief="flat", pady=9, cursor="hand2").pack(fill="x")

    def open_people_manager(self) -> None:
        dlg, frame, footer = self._create_scrollable_dialog("Manage People", 490, 540, has_footer=True)

        header_row = tk.Frame(frame, bg=self._c("surface"))
        header_row.pack(fill="x", pady=(0, 10))
        title_col = tk.Frame(header_row, bg=self._c("surface"))
        title_col.pack(side="left", fill="x", expand=True)
        tk.Label(title_col, text="Manage People", font=(FONT_UI, 14, "bold"), bg=self._c("surface"), fg=self._c("text"), anchor="w").pack(fill="x")
        tk.Label(title_col, text="Organize vaults & circular profile photos", font=(FONT_UI, 9), bg=self._c("surface"), fg=self._c("muted"), anchor="w").pack(fill="x")
        count_badge = tk.Label(
            header_row,
            text="",
            font=(FONT_UI, 8, "bold"),
            bg=self._c("surface_alt"),
            fg=self._c("primary"),
            padx=10,
            pady=4,
        )
        count_badge.pack(side="right", anchor="n")

        list_box = tk.Frame(frame, bg=self._c("surface"))
        list_box.pack(fill="x")
        editing_id: Dict[str, Optional[str]] = {"val": None}
        avatar_state: Dict[str, Any] = {"mime": "", "b64": "", "clear": False, "existing_person": None}
        v_name = tk.StringVar()

        def entry_count_for(pid: str) -> int:
            return sum(1 for e in self.entries if e.get("person_id") == pid)

        def render_people() -> None:
            for w in list_box.winfo_children():
                w.destroy()
            people = self.db.list_people()
            count_badge.configure(text=f"{len(people)} profile{'s' if len(people) != 1 else ''}")
            for p in people:
                is_editing = editing_id["val"] == p["id"]
                card = tk.Frame(
                    list_box,
                    bg=self._c("surface_alt"),
                    highlightbackground=self._c("primary") if is_editing else self._c("border"),
                    highlightthickness=1,
                    padx=12,
                    pady=10,
                )
                card.pack(fill="x", pady=4)

                p_av = self.logos.get_person_avatar_photo(p, size=36, fallback_ui_icon="user")
                if p_av is not None:
                    av_lbl = tk.Label(card, image=p_av, bg=self._c("surface_alt"))
                    av_lbl._img_ref = p_av
                    av_lbl.pack(side="left", padx=(0, 12))

                info_col = tk.Frame(card, bg=self._c("surface_alt"))
                info_col.pack(side="left", fill="x", expand=True)
                tk.Label(info_col, text=p["name"], font=(FONT_UI, 10, "bold"), bg=self._c("surface_alt"), fg=self._c("text"), anchor="w").pack(fill="x")
                n_creds = entry_count_for(p["id"])
                tk.Label(
                    info_col,
                    text=f"{n_creds} saved password{'s' if n_creds != 1 else ''}",
                    font=(FONT_UI, 8),
                    bg=self._c("surface_alt"),
                    fg=self._c("muted"),
                    anchor="w",
                ).pack(fill="x")

                btns_col = tk.Frame(card, bg=self._c("surface_alt"))
                btns_col.pack(side="right")
                self._btn(
                    btns_col,
                    icon_name="edit",
                    text="  Edit",
                    command=lambda person=p: start_edit(person),
                    font=(FONT_UI, 9, "bold"),
                    bg=self._c("surface"),
                    fg=self._c("text"),
                    relief="flat",
                    padx=10,
                    pady=5,
                    cursor="hand2",
                ).pack(side="left", padx=(0, 6))
                if len(people) > 1:
                    self._btn(
                        btns_col,
                        icon_name="trash",
                        text="  Delete",
                        command=lambda person=p: delete_p(person),
                        font=(FONT_UI, 9, "bold"),
                        bg=self._c("danger"),
                        fg="#FFFFFF",
                        activebackground=self._c("danger"),
                        activeforeground="#FFFFFF",
                        relief="flat",
                        padx=10,
                        pady=5,
                        cursor="hand2",
                    ).pack(side="left")

        def refresh_avatar_preview() -> None:
            if avatar_state["clear"]:
                img = self.logos.get_ui_icon("user")
            elif avatar_state["b64"]:
                img = self.logos.get_person_avatar_photo(None, size=44, fallback_ui_icon="user", raw_b64=avatar_state["b64"])
            else:
                img = self.logos.get_person_avatar_photo(avatar_state["existing_person"], size=44, fallback_ui_icon="user")
            if img is not None:
                preview_lbl.configure(image=img)
                preview_lbl._img_ref = img

        def start_edit(person: Dict[str, str]) -> None:
            editing_id["val"] = person["id"]
            v_name.set(person["name"])
            avatar_state["mime"] = ""
            avatar_state["b64"] = ""
            avatar_state["clear"] = False
            avatar_state["existing_person"] = person
            mode_lbl.configure(text=f"Edit Profile: {person['name']}")
            cancel_edit_btn.pack(side="right")
            save_person_btn.configure(text="  Save Changes")
            refresh_avatar_preview()
            render_people()

        def delete_p(person: Dict[str, str]) -> None:
            if self.dek is None:
                return
            pid = person["id"]
            p_entries = [e for e in self.entries if e.get("person_id") == pid]
            if p_entries:
                titles = [e.get("title") or "(Untitled)" for e in p_entries]
                listed = "\n".join(f"• {t}" for t in titles[:12])
                more = f"\n... and {len(titles) - 12} more" if len(titles) > 12 else ""
                confirm_msg = (
                    f"Delete '{person['name']}'?\n\n"
                    f"All {len(p_entries)} saved password(s) below will ALSO be deleted:\n"
                    f"{listed}{more}"
                )
            else:
                confirm_msg = f"Delete '{person['name']}'?\n\nThis person has no saved passwords."

            if not messagebox.askyesno("Confirm Deletion", confirm_msg, parent=dlg):
                return
            try:
                deleted_ids = {e["id"] for e in p_entries}
                self.db.delete_person(pid, self.dek)
                if self.selected_entry_id in deleted_ids:
                    self.selected_entry_id = None
                if editing_id["val"] == pid:
                    reset_form(refresh_list=False)
                if self.filter_person == pid:
                    self.filter_person = "all"
                    self.active_sidebar_item = "all"
                self.reload_data()
                self._build_sidebar()
                self.refresh_entry_list()
                self.render_detail_pane()
                render_people()
            except Exception as exc:
                messagebox.showerror("Error", str(exc), parent=dlg)

        # Footer editor card
        editor_card = tk.Frame(
            footer,
            bg=self._c("surface_alt"),
            highlightbackground=self._c("border"),
            highlightthickness=1,
            padx=12,
            pady=10,
        )
        editor_card.pack(fill="x")

        editor_head = tk.Frame(editor_card, bg=self._c("surface_alt"))
        editor_head.pack(fill="x", pady=(0, 8))
        mode_lbl = tk.Label(editor_head, text="Add New Person", font=(FONT_UI, 9, "bold"), bg=self._c("surface_alt"), fg=self._c("primary"), anchor="w")
        mode_lbl.pack(side="left")

        def reset_form(refresh_list: bool = True) -> None:
            editing_id["val"] = None
            v_name.set("")
            avatar_state["mime"] = ""
            avatar_state["b64"] = ""
            avatar_state["clear"] = False
            avatar_state["existing_person"] = None
            mode_lbl.configure(text="Add New Person")
            cancel_edit_btn.pack_forget()
            save_person_btn.configure(text="  Add Person")
            refresh_avatar_preview()
            if refresh_list:
                render_people()

        cancel_edit_btn = tk.Button(
            editor_head,
            text="Cancel",
            command=reset_form,
            font=(FONT_UI, 8, "bold"),
            bg=self._c("surface"),
            fg=self._c("muted"),
            relief="flat",
            padx=8,
            pady=2,
            cursor="hand2",
        )

        body_row = tk.Frame(editor_card, bg=self._c("surface_alt"))
        body_row.pack(fill="x", pady=(0, 8))

        preview_lbl = tk.Label(body_row, bg=self._c("surface_alt"), width=46, height=46)
        preview_lbl.pack(side="left", padx=(0, 12))

        fields_col = tk.Frame(body_row, bg=self._c("surface_alt"))
        fields_col.pack(side="left", fill="x", expand=True)

        tk.Entry(
            fields_col,
            textvariable=v_name,
            font=(FONT_UI, 10),
            bg=self._c("surface"),
            fg=self._c("text"),
            insertbackground=self._c("primary"),
            relief="flat",
        ).pack(fill="x", ipady=6, pady=(0, 6))

        def pick_person_photo() -> None:
            path = filedialog.askopenfilename(
                title="Select Profile Photo (PNG, JPG, JPEG, GIF)",
                filetypes=[("Allowed Images", "*.png *.jpg *.jpeg *.gif")],
                parent=dlg,
            )
            if not path:
                return
            try:
                mime, b64 = ImageValidator.validate_and_encode(path, max_dim=160)
                avatar_state["mime"] = mime
                avatar_state["b64"] = b64
                avatar_state["clear"] = False
                refresh_avatar_preview()
            except Exception as exc:
                messagebox.showerror("Invalid Image", str(exc), parent=dlg)

        def clear_person_photo() -> None:
            avatar_state["mime"] = ""
            avatar_state["b64"] = ""
            avatar_state["clear"] = True
            refresh_avatar_preview()

        photo_btns = tk.Frame(fields_col, bg=self._c("surface_alt"))
        photo_btns.pack(fill="x")
        self._btn(photo_btns, icon_name="image", text="  Upload Photo", command=pick_person_photo, font=(FONT_UI, 9), bg=self._c("surface"), fg=self._c("text"), relief="flat", padx=8, pady=4, cursor="hand2").pack(side="left", padx=(0, 6))
        tk.Button(photo_btns, text="Remove", command=clear_person_photo, font=(FONT_UI, 9), bg=self._c("surface"), fg=self._c("muted"), relief="flat", padx=8, pady=4, cursor="hand2").pack(side="left")

        def add_or_update_p() -> None:
            if not v_name.get().strip():
                messagebox.showwarning("Missing Name", "Please enter a person name.", parent=dlg)
                return
            try:
                self.db.upsert_person(
                    editing_id["val"],
                    v_name.get(),
                    avatar_mime=avatar_state["mime"],
                    avatar_b64=avatar_state["b64"],
                    clear_avatar=bool(avatar_state["clear"]),
                )
                reset_form(refresh_list=False)
                self.reload_data()
                self._build_sidebar()
                self.refresh_entry_list()
                self.render_detail_pane()
                render_people()
            except Exception as exc:
                messagebox.showerror("Duplicate or Invalid Name", str(exc), parent=dlg)

        save_person_btn = self._btn(
            editor_card,
            icon_name="plus",
            text="  Add Person",
            command=add_or_update_p,
            font=(FONT_UI, 10, "bold"),
            bg=self._c("primary"),
            fg=self._c("primary_fg"),
            activebackground=self._c("primary"),
            activeforeground=self._c("primary_fg"),
            relief="flat",
            pady=8,
            cursor="hand2",
        )
        save_person_btn.pack(fill="x")
        render_people()
        refresh_avatar_preview()

    def open_generator_dialog(self) -> None:
        dlg, frame, _ = self._create_scrollable_dialog("Password Generator", 460, 440)

        v_len = tk.IntVar(value=8)
        v_lower = tk.BooleanVar(value=True)
        v_upper = tk.BooleanVar(value=True)
        v_nums = tk.BooleanVar(value=True)
        v_syms = tk.BooleanVar(value=True)
        v_out = tk.StringVar()

        tk.Entry(frame, textvariable=v_out, font=(FONT_MONO, 14, "bold"), bg=self._c("surface_alt"), fg=self._c("text"), relief="flat", justify="center").pack(fill="x", ipady=12, pady=(0, 8))
        update_strength, strength_box = self._create_strength_meter(frame)
        strength_box.pack(fill="x", pady=(0, 12))

        def regenerate(*_args: Any) -> None:
            if not (v_lower.get() or v_upper.get() or v_nums.get() or v_syms.get()):
                v_lower.set(True)
            pw = PasswordGeneratorService.generate(v_len.get(), v_lower.get(), v_upper.get(), v_nums.get(), v_syms.get())
            v_out.set(pw)
            update_strength(pw)

        row = tk.Frame(frame, bg=self._c("surface"))
        row.pack(fill="x", pady=6)
        tk.Label(row, text="Character Length (4–64):", font=(FONT_UI, 10, "bold"), bg=self._c("surface"), fg=self._c("text")).pack(side="left")
        tk.Spinbox(row, from_=4, to=64, textvariable=v_len, width=6, command=regenerate).pack(side="right")

        tk.Scale(frame, from_=4, to=64, orient="horizontal", variable=v_len, showvalue=False, bg=self._c("surface"), fg=self._c("primary"), highlightthickness=0, command=lambda _v: regenerate()).pack(fill="x", pady=(0, 12))

        grid = tk.Frame(frame, bg=self._c("surface"))
        grid.pack(fill="x", pady=(0, 14))
        for idx, (text, var) in enumerate([("Lowercase (a–z)", v_lower), ("Uppercase (A–Z)", v_upper), ("Numbers (0–9)", v_nums), ("Symbols (!@#$)", v_syms)]):
            tk.Checkbutton(grid, text=text, variable=var, command=regenerate, font=(FONT_UI, 9), bg=self._c("surface"), fg=self._c("text"), activebackground=self._c("surface"), activeforeground=self._c("text"), selectcolor=self._c("surface_alt"), highlightthickness=0, anchor="w").grid(row=idx // 2, column=idx % 2, sticky="w", padx=(0, 20), pady=4)

        regenerate()

        self._btn(frame, icon_name="wand_white", text="  Generate Password", command=regenerate, font=(FONT_UI, 10, "bold"), bg=self._c("primary"), fg=self._c("primary_fg"), activebackground=self._c("primary"), activeforeground=self._c("primary_fg"), relief="flat", pady=9, cursor="hand2").pack(fill="x", pady=(0, 8))
        self._btn(frame, icon_name="copy", text="  Copy Password", command=lambda: self.copy_text(v_out.get(), clear_after=30, parent=dlg), font=(FONT_UI, 10), bg=self._c("surface_alt"), fg=self._c("text"), relief="flat", pady=9, cursor="hand2").pack(fill="x")
