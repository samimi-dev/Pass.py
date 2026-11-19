# -*- coding: utf-8 -*-
"""Encrypted SQLite vault repository with safe schema migration & Email recovery."""

import base64
import datetime
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from .assets import ALLOWED_IMAGE_MIMES, DEFAULT_CATEGORIES
from .image_validator import ImageValidator
from .paths import AVATARS_DIR, BACKUP_DIR, DB_PATH, LOGOS_DIR
from .recovery import RecoveryEmailService
from .security import SecurityService
from .windows_auth import WindowsAuthService


class VaultRepository:
    """SQLite Encrypted Vault Repository with safe migrations & zero-knowledge Email recovery."""

    _INTERNAL_META_KEY = "_legacy_id_maps"

    def __init__(
        self,
        db_path: str = DB_PATH,
        logos_dir: Optional[str] = None,
        avatars_dir: Optional[str] = None,
    ) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._failed_unlock_attempts = 0
        self._unlock_locked_until = 0.0
        parent = os.path.dirname(os.path.abspath(self.db_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.logos_dir = logos_dir or (os.path.join(parent, "logos") if db_path != DB_PATH else LOGOS_DIR)
        self.avatars_dir = avatars_dir or (os.path.join(parent, "avatars") if db_path != DB_PATH else AVATARS_DIR)
        os.makedirs(self.logos_dir, exist_ok=True)
        os.makedirs(self.avatars_dir, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=15.0)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    @staticmethod
    def _db_id(raw_id: Any) -> Any:
        s = str(raw_id).strip()
        return int(s) if s.isdigit() else s

    def _table_columns(self, table_name: str) -> List[Dict[str, Any]]:
        rows = self.conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        return [dict(r) for r in rows]

    def _init_schema(self) -> None:
        cur = self.conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS vault_meta (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                auth_mode TEXT NOT NULL,
                salt_b64 TEXT NOT NULL,
                wrapped_dek TEXT,
                dpapi_dek TEXT,
                settings_json TEXT NOT NULL,
                recovery_json TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL
            )
            """
        )
        meta_cols = [c["name"] for c in self._table_columns("vault_meta")]
        if "recovery_json" not in meta_cols:
            cur.execute("ALTER TABLE vault_meta ADD COLUMN recovery_json TEXT NOT NULL DEFAULT ''")

        people_id_map: Dict[str, str] = {}
        logo_id_map: Dict[str, str] = {}
        needs_entry_slim = False
        schema_migrated = False

        # --- categories: (id INTEGER PK, name UNIQUE, sort_order) ---
        cat_info = self._table_columns("categories")
        if not cat_info:
            cur.execute(
                """
                CREATE TABLE categories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    sort_order INTEGER NOT NULL
                )
                """
            )
        else:
            cat_cols = {c["name"] for c in cat_info}
            if "id" not in cat_cols or "created_at" in cat_cols:
                schema_migrated = True
                old_cats = cur.execute("SELECT name, sort_order FROM categories ORDER BY sort_order ASC, name ASC").fetchall()
                cur.execute("DROP TABLE IF EXISTS categories_new")
                cur.execute(
                    """
                    CREATE TABLE categories_new (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL UNIQUE,
                        sort_order INTEGER NOT NULL
                    )
                    """
                )
                seen_cats = set()
                idx = 0
                for row in old_cats:
                    cname = str(row["name"]).strip()
                    if not cname or cname.lower() in seen_cats:
                        continue
                    seen_cats.add(cname.lower())
                    cur.execute("INSERT INTO categories_new (name, sort_order) VALUES (?, ?)", (cname, idx))
                    idx += 1
                cur.execute("DROP TABLE categories")
                cur.execute("ALTER TABLE categories_new RENAME TO categories")

        # --- people: (id INTEGER PK, name UNIQUE, avatar_file, created_at) ---
        people_info = self._table_columns("people")
        if not people_info:
            cur.execute(
                """
                CREATE TABLE people (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    avatar_file TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                )
                """
            )
        else:
            p_map = {c["name"]: c for c in people_info}
            p_needs_mig = (
                "avatar_b64" in p_map
                or "avatar_mime" in p_map
                or "relation" in p_map
                or str(p_map.get("id", {}).get("type", "")).upper() != "INTEGER"
            )
            if p_needs_mig:
                schema_migrated = True
                old_people = cur.execute("SELECT * FROM people ORDER BY rowid ASC").fetchall()
                cur.execute("DROP TABLE IF EXISTS people_new")
                cur.execute(
                    """
                    CREATE TABLE people_new (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL UNIQUE,
                        avatar_file TEXT NOT NULL DEFAULT '',
                        created_at TEXT NOT NULL
                    )
                    """
                )
                seen_names = set()
                for row in old_people:
                    keys = set(row.keys())
                    old_id = str(row["id"])
                    name = str(row["name"] or "").strip() or f"User {len(seen_names) + 1}"
                    if name.lower() in seen_names:
                        suffix = 2
                        while f"{name} {suffix}".lower() in seen_names:
                            suffix += 1
                        name = f"{name} {suffix}"
                    seen_names.add(name.lower())

                    avatar_file = str(row["avatar_file"] or "") if "avatar_file" in keys else ""
                    avatar_b64 = str(row["avatar_b64"] or "") if "avatar_b64" in keys else ""
                    avatar_mime = (str(row["avatar_mime"] or "") if "avatar_mime" in keys else "") or "image/png"
                    if avatar_mime not in ALLOWED_IMAGE_MIMES:
                        avatar_mime = "image/png"
                    if avatar_b64:
                        disk_path = os.path.join(self.avatars_dir, os.path.basename(avatar_file)) if avatar_file else ""
                        if not avatar_file or not os.path.isfile(disk_path):
                            avatar_file = ImageValidator.save_logo_file(
                                avatar_b64,
                                avatar_mime,
                                f"avatar_{secrets.token_hex(4)}",
                                logos_dir=self.avatars_dir,
                            )

                    created_at = str(row["created_at"] or "") if "created_at" in keys else ""
                    if not created_at:
                        created_at = datetime.date.today().isoformat()

                    cur.execute(
                        "INSERT INTO people_new (name, avatar_file, created_at) VALUES (?, ?, ?)",
                        (name, avatar_file, created_at),
                    )
                    people_id_map[old_id] = str(cur.lastrowid)
                cur.execute("DROP TABLE people")
                cur.execute("ALTER TABLE people_new RENAME TO people")

        # --- custom_logos: (id INTEGER PK, label, domain, file_name) ---
        cl_info = self._table_columns("custom_logos")
        if not cl_info:
            cur.execute(
                """
                CREATE TABLE custom_logos (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    label TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    file_name TEXT NOT NULL
                )
                """
            )
        else:
            cl_map = {c["name"]: c for c in cl_info}
            cl_needs_mig = (
                "data_b64" in cl_map
                or "mime_type" in cl_map
                or "created_at" in cl_map
                or str(cl_map.get("id", {}).get("type", "")).upper() != "INTEGER"
            )
            if cl_needs_mig:
                schema_migrated = True
                old_logos = cur.execute("SELECT * FROM custom_logos ORDER BY rowid ASC").fetchall()
                cur.execute("DROP TABLE IF EXISTS custom_logos_new")
                cur.execute(
                    """
                    CREATE TABLE custom_logos_new (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        label TEXT NOT NULL,
                        domain TEXT NOT NULL,
                        file_name TEXT NOT NULL
                    )
                    """
                )
                for row in old_logos:
                    keys = set(row.keys())
                    old_id = str(row["id"])
                    label = str(row["label"] or "").strip() or "Custom Logo"
                    domain = str(row["domain"] or "").strip().lower()
                    file_name = str(row["file_name"] or "") if "file_name" in keys else ""
                    data_b64 = str(row["data_b64"] or "") if "data_b64" in keys else ""
                    mime_type = (str(row["mime_type"] or "") if "mime_type" in keys else "") or "image/png"
                    if mime_type not in ALLOWED_IMAGE_MIMES:
                        mime_type = "image/png"
                    if data_b64:
                        disk_path = os.path.join(self.logos_dir, os.path.basename(file_name)) if file_name else ""
                        if not file_name or not os.path.isfile(disk_path):
                            file_name = ImageValidator.save_logo_file(
                                data_b64,
                                mime_type,
                                f"default_{secrets.token_hex(4)}",
                                logos_dir=self.logos_dir,
                            )
                    cur.execute(
                        "INSERT INTO custom_logos_new (label, domain, file_name) VALUES (?, ?, ?)",
                        (label, domain, file_name),
                    )
                    logo_id_map[old_id] = str(cur.lastrowid)
                cur.execute("DROP TABLE custom_logos")
                cur.execute("ALTER TABLE custom_logos_new RENAME TO custom_logos")

        # --- entries: (id INTEGER PK, encrypted_blob, created_at, updated_at) ---
        entries_info = self._table_columns("entries")
        if not entries_info:
            cur.execute(
                """
                CREATE TABLE entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    encrypted_blob TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
        else:
            e_map = {c["name"]: c for c in entries_info}
            if str(e_map.get("id", {}).get("type", "")).upper() != "INTEGER":
                schema_migrated = True
                needs_entry_slim = True
                old_entries = cur.execute(
                    "SELECT id, encrypted_blob, created_at, updated_at FROM entries ORDER BY rowid ASC"
                ).fetchall()
                cur.execute("DROP TABLE IF EXISTS entries_new")
                cur.execute(
                    """
                    CREATE TABLE entries_new (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        encrypted_blob TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                    """
                )
                for row in old_entries:
                    cur.execute(
                        "INSERT INTO entries_new (encrypted_blob, created_at, updated_at) VALUES (?, ?, ?)",
                        (row["encrypted_blob"], row["created_at"], row["updated_at"]),
                    )
                cur.execute("DROP TABLE entries")
                cur.execute("ALTER TABLE entries_new RENAME TO entries")

        if (people_id_map or logo_id_map or needs_entry_slim) and (
            cur.execute("SELECT COUNT(*) FROM entries").fetchone()[0] > 0
        ):
            meta_row = cur.execute("SELECT settings_json FROM vault_meta WHERE id = 1").fetchone()
            if meta_row:
                try:
                    settings_obj = json.loads(meta_row["settings_json"])
                except Exception:
                    settings_obj = {}
                existing_pending = settings_obj.get(self._INTERNAL_META_KEY) or {}
                merged_people = dict(existing_pending.get("people") or {})
                merged_people.update(people_id_map)
                merged_logos = dict(existing_pending.get("logos") or {})
                merged_logos.update(logo_id_map)
                settings_obj[self._INTERNAL_META_KEY] = {
                    "people": merged_people,
                    "logos": merged_logos,
                    "needs_entry_slim": True,
                }
                cur.execute(
                    "UPDATE vault_meta SET settings_json = ? WHERE id = 1",
                    (json.dumps(settings_obj, ensure_ascii=False),),
                )

        self.conn.commit()
        if schema_migrated:
            try:
                self.conn.execute("VACUUM")
            except Exception:
                pass
        self._ensure_default_categories()

    def _ensure_default_categories(self) -> None:
        count = self.conn.execute("SELECT COUNT(*) FROM categories").fetchone()[0]
        if count == 0:
            for idx, name in enumerate(DEFAULT_CATEGORIES):
                self.conn.execute(
                    "INSERT OR IGNORE INTO categories (name, sort_order) VALUES (?, ?)",
                    (name, idx),
                )
            self.conn.commit()

    def _first_person_id(self) -> str:
        row = self.conn.execute("SELECT id FROM people ORDER BY id ASC LIMIT 1").fetchone()
        return str(row["id"]) if row else "1"

    def _build_entry_blob_payload(
        self,
        entry: Dict[str, Any],
        chosen_cat: str,
        default_person_id: str,
        custom_file: str,
        custom_logos: List[Dict[str, str]],
    ) -> Dict[str, Any]:
        """Builds a compact encrypted payload without duplicated SQLite columns or base64 blobs."""
        title = str(entry.get("title", "")).strip()
        site_url = str(entry.get("site_url", "")).strip()
        logo_key = str(entry.get("logo_key") or "").strip() or ImageValidator.match_logo_key(site_url, title, custom_logos)
        username = str(entry.get("username", "")).strip()
        username_is_email = bool(entry.get("username_is_email", False))
        email = "" if username_is_email else str(entry.get("email", "")).strip()
        notes = str(entry.get("notes", "")).strip()
        tags = [str(t).strip() for t in (entry.get("tags") or []) if str(t).strip()]
        is_favorite = bool(entry.get("is_favorite", False))
        person_id = str(entry.get("person_id") or default_person_id).strip() or default_person_id

        payload: Dict[str, Any] = {
            "title": title,
            "password": str(entry.get("password", "")),
            "category": chosen_cat,
            "person_id": person_id,
            "logo_key": logo_key,
        }
        if site_url:
            payload["site_url"] = site_url
        if custom_file:
            payload["custom_logo_file"] = custom_file
        if username:
            payload["username"] = username
        if username_is_email:
            payload["username_is_email"] = True
        if email:
            payload["email"] = email
        if notes:
            payload["notes"] = notes
        if tags:
            payload["tags"] = tags
        if is_favorite:
            payload["is_favorite"] = True
        return payload

    def _migrate_legacy_entries(self, dek: bytes) -> None:
        """Remaps legacy person/logo IDs inside encrypted entries and trims duplicate blob fields."""
        with self._lock:
            meta = self.get_meta()
            if not meta:
                return
            try:
                raw_settings = json.loads(meta["settings_json"])
            except Exception:
                return
            pending = raw_settings.get(self._INTERNAL_META_KEY)
            if not isinstance(pending, dict):
                return

            people_map: Dict[str, str] = {str(k): str(v) for k, v in (pending.get("people") or {}).items()}
            logos_map: Dict[str, str] = {str(k): str(v) for k, v in (pending.get("logos") or {}).items()}
            people = self.list_people()
            valid_pids = {p["id"] for p in people}
            fallback_pid = people[0]["id"] if people else "1"
            custom_logos = self.list_custom_logos()
            cats = self.list_categories()
            fallback_cat = cats[0] if cats else "General"

            rows = self.conn.execute("SELECT id, encrypted_blob FROM entries ORDER BY id ASC").fetchall()
            for r in rows:
                eid = str(r["id"])
                try:
                    data = SecurityService.decrypt_json(dek, r["encrypted_blob"])
                except Exception:
                    return
                raw_pid = str(data.get("person_id", "")).strip()
                mapped_pid = people_map.get(raw_pid, raw_pid)
                if mapped_pid not in valid_pids:
                    mapped_pid = fallback_pid
                data["person_id"] = mapped_pid

                lk = str(data.get("logo_key", "globe"))
                if lk.startswith("custom:"):
                    old_cid = lk.split(":", 1)[1]
                    if old_cid in logos_map:
                        data["logo_key"] = f"custom:{logos_map[old_cid]}"

                custom_file = str(data.get("custom_logo_file", "") or "")
                old_b64 = str(data.get("custom_logo_b64", "") or "")
                old_mime = str(data.get("custom_logo_mime", "image/png") or "image/png")
                if old_mime not in ALLOWED_IMAGE_MIMES:
                    old_mime = "image/png"
                if old_b64 and not custom_file:
                    custom_file = ImageValidator.save_logo_file(
                        old_b64,
                        old_mime,
                        f"entry_{eid}_{secrets.token_hex(3)}",
                        logos_dir=self.logos_dir,
                    )

                chosen_cat = str(data.get("category", "") or "").strip() or fallback_cat
                payload = self._build_entry_blob_payload(
                    data,
                    chosen_cat=chosen_cat,
                    default_person_id=fallback_pid,
                    custom_file=custom_file,
                    custom_logos=custom_logos,
                )
                new_blob = SecurityService.encrypt_json(dek, payload)
                self.conn.execute("UPDATE entries SET encrypted_blob = ? WHERE id = ?", (new_blob, r["id"]))

            raw_settings.pop(self._INTERNAL_META_KEY, None)
            self.conn.execute(
                "UPDATE vault_meta SET settings_json = ? WHERE id = 1",
                (json.dumps(raw_settings, ensure_ascii=False),),
            )
            self.conn.commit()
        try:
            self.conn.execute("VACUUM")
        except Exception:
            pass

    def is_initialized(self) -> bool:
        with self._lock:
            return self.conn.execute("SELECT id FROM vault_meta WHERE id = 1").fetchone() is not None

    def get_meta(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM vault_meta WHERE id = 1").fetchone()
            return dict(row) if row else None

    def create_vault(self, master_password: str, auth_mode: str = "custom") -> bytes:
        SecurityService.validate_login_password(master_password, auth_mode=auth_mode, label="Password")
        dek = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        salt_b64 = base64.b64encode(salt).decode("ascii")
        wrapped_dek = None
        dpapi_dek = None

        if auth_mode == "windows":
            if not WindowsAuthService.verify_windows_password(master_password):
                raise ValueError("Incorrect Windows account password.")
            dpapi_dek = WindowsAuthService.dpapi_protect(dek)
        else:
            kek = SecurityService.derive_key(master_password, salt)
            wrapped_dek = SecurityService.encrypt_bytes(kek, dek)

        default_settings = {
            "theme": "light",
            "auto_lock_minutes": 5,
            "local_auto_backup": False,
            "local_backup_dir": BACKUP_DIR,
            "online_auto_backup": False,
            "confirm_on_close": True,
            "cloud_sync_enabled": False,
            "sync_url": "http://localhost:3000",
            "sync_vault_id": secrets.token_hex(8),
        }
        now = datetime.datetime.now().isoformat(timespec="seconds")
        with self._lock:
            self.conn.execute(
                """
                INSERT OR REPLACE INTO vault_meta
                (id, auth_mode, salt_b64, wrapped_dek, dpapi_dek, settings_json, recovery_json, updated_at)
                VALUES (1, ?, ?, ?, ?, ?, '', ?)
                """,
                (auth_mode, salt_b64, wrapped_dek, dpapi_dek, json.dumps(default_settings), now),
            )
            self.conn.execute(
                "INSERT OR IGNORE INTO people (name, avatar_file, created_at) VALUES (?, '', ?)",
                ("Me", now[:10]),
            )
            self.conn.execute(
                "INSERT OR IGNORE INTO people (name, avatar_file, created_at) VALUES (?, '', ?)",
                ("Spouse", now[:10]),
            )
            self._ensure_default_categories()
            self.conn.commit()
        return dek

    def verify_current_password(self, password: str) -> bool:
        try:
            self.unlock(password)
            return True
        except Exception:
            return False

    def unlock(self, password: str) -> bytes:
        now = time.monotonic()
        if self._unlock_locked_until > now:
            wait = max(1, int(round(self._unlock_locked_until - now)))
            raise ValueError(f"Too many failed attempts. Please wait {wait}s before trying again.")

        meta = self.get_meta()
        if not meta:
            raise RuntimeError("Vault has not been created yet.")
        SecurityService.validate_login_password(password, auth_mode=meta["auth_mode"], label="Password")
        try:
            if meta["auth_mode"] == "windows":
                if not WindowsAuthService.verify_windows_password(password):
                    raise ValueError("Incorrect Windows account password.")
                if not meta["dpapi_dek"]:
                    raise RuntimeError("Windows DPAPI protected key not found.")
                dek = WindowsAuthService.dpapi_unprotect(meta["dpapi_dek"])
            else:
                salt = base64.b64decode(meta["salt_b64"])
                kek = SecurityService.derive_key(password, salt)
                dek = SecurityService.decrypt_bytes(kek, meta["wrapped_dek"])
        except Exception:
            self._failed_unlock_attempts += 1
            if self._failed_unlock_attempts >= 5:
                delay = min(15, 2 ** min(4, self._failed_unlock_attempts - 5))
                self._unlock_locked_until = time.monotonic() + delay
            raise

        self._failed_unlock_attempts = 0
        self._unlock_locked_until = 0.0
        self._migrate_legacy_entries(dek)
        return dek

    def update_auth_mode(self, dek: bytes, current_password: str, new_mode: str, new_password: str) -> None:
        meta = self.get_meta()
        if not meta:
            return
        if not current_password or not self.verify_current_password(current_password):
            raise ValueError("Current password is incorrect.")
        SecurityService.validate_login_password(new_password, auth_mode=new_mode, label="New password")

        salt = secrets.token_bytes(16)
        salt_b64 = base64.b64encode(salt).decode("ascii")
        wrapped_dek = None
        dpapi_dek = None

        if new_mode == "windows":
            if not WindowsAuthService.verify_windows_password(new_password):
                raise ValueError("Windows account password verification failed.")
            dpapi_dek = WindowsAuthService.dpapi_protect(dek)
        else:
            kek = SecurityService.derive_key(new_password, salt)
            wrapped_dek = SecurityService.encrypt_bytes(kek, dek)

        now = datetime.datetime.now().isoformat(timespec="seconds")
        with self._lock:
            self.conn.execute(
                """
                UPDATE vault_meta
                SET auth_mode = ?, salt_b64 = ?, wrapped_dek = ?, dpapi_dek = ?, updated_at = ?
                WHERE id = 1
                """,
                (new_mode, salt_b64, wrapped_dek, dpapi_dek, now),
            )
            self.conn.commit()

    def _get_recovery_blob(self) -> Dict[str, Any]:
        meta = self.get_meta()
        raw = (meta or {}).get("recovery_json") or ""
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except Exception:
            return {}

    def _save_recovery_blob(self, blob: Dict[str, Any]) -> None:
        now = datetime.datetime.now().isoformat(timespec="seconds")
        serialized = json.dumps(blob, ensure_ascii=False) if blob else ""
        with self._lock:
            self.conn.execute(
                "UPDATE vault_meta SET recovery_json = ?, updated_at = ? WHERE id = 1",
                (serialized, now),
            )
            self.conn.commit()

    def get_recovery_info(self) -> Dict[str, Any]:
        blob = self._get_recovery_blob()
        if not blob or not blob.get("enabled"):
            return {
                "enabled": False,
                "email_masked": "",
                "has_smtp": False,
                "smtp_sender": "",
                "locked_seconds": 0,
                "failed_attempts": 0,
            }
        now_ts = time.time()
        locked_until = float(blob.get("locked_until", 0.0) or 0.0)
        rem = max(0, int(round(locked_until - now_ts)))
        smtp = blob.get("smtp") or {}
        return {
            "enabled": True,
            "email_masked": blob.get("email_masked") or blob.get("contact_masked", ""),
            "has_smtp": bool(smtp.get("enabled") and smtp.get("sender_email")),
            "smtp_sender": smtp.get("sender_email", ""),
            "locked_seconds": rem,
            "failed_attempts": int(blob.get("failed_attempts", 0) or 0),
        }

    def configure_recovery(
        self,
        dek: bytes,
        recovery_email: str,
        google_smtp: Optional[Dict[str, Any]] = None,
    ) -> str:
        email_norm = RecoveryEmailService.normalize_email(recovery_email)
        rec_salt = secrets.token_bytes(16)
        recovery_key = RecoveryEmailService.generate_recovery_key()
        canonical_key = RecoveryEmailService.normalize_recovery_key(recovery_key)

        email_hash = base64.b64encode(SecurityService.derive_key(email_norm, rec_salt, 100_000)).decode("ascii")
        rec_kek = SecurityService.derive_key(f"{canonical_key}|{email_norm}", rec_salt, SecurityService.ITERATIONS)
        wrapped_dek = SecurityService.encrypt_bytes(rec_kek, dek)

        smtp_saved: Dict[str, Any] = {"enabled": False}
        if google_smtp and google_smtp.get("enabled"):
            sender = RecoveryEmailService.normalize_email(str(google_smtp.get("sender_email", "")))
            app_pw = str(google_smtp.get("app_password", "")).strip()
            prev_smtp = self._get_recovery_blob().get("smtp") or {}
            secret_dpapi = prev_smtp.get("secret_dpapi", "")
            secret_local = prev_smtp.get("secret_local", "")
            if app_pw:
                if WindowsAuthService.IS_WINDOWS:
                    secret_dpapi = WindowsAuthService.dpapi_protect(app_pw.encode("utf-8"))
                    secret_local = ""
                else:
                    local_key = SecurityService.derive_key(email_norm, rec_salt, 50_000)
                    secret_local = SecurityService.encrypt_bytes(local_key, app_pw.encode("utf-8"))
            if not secret_dpapi and not secret_local:
                raise ValueError("Google App Password is required to enable Gmail SMTP OTP.")
            smtp_saved = {
                "enabled": True,
                "host": RecoveryEmailService.GOOGLE_SMTP_HOST,
                "port": RecoveryEmailService.GOOGLE_SMTP_PORT,
                "sender_email": sender,
                "recipient_email": email_norm,
                "secret_dpapi": secret_dpapi,
                "secret_local": secret_local,
            }

        payload = {
            "enabled": True,
            "email_masked": RecoveryEmailService.mask_email(email_norm),
            "email_hash": email_hash,
            "salt_b64": base64.b64encode(rec_salt).decode("ascii"),
            "wrapped_dek": wrapped_dek,
            "failed_attempts": 0,
            "locked_until": 0.0,
            "smtp": smtp_saved,
        }
        self._save_recovery_blob(payload)
        return recovery_key

    def disable_recovery(self, current_password: str) -> None:
        if not current_password or not self.verify_current_password(current_password):
            raise ValueError("Current password is incorrect.")
        self._save_recovery_blob({})

    def _record_recovery_failure(self, blob: Dict[str, Any]) -> None:
        attempts = int(blob.get("failed_attempts", 0) or 0) + 1
        blob["failed_attempts"] = attempts
        wait_sec = RecoveryEmailService.compute_lockout_seconds(attempts)
        if wait_sec > 0:
            blob["locked_until"] = time.time() + wait_sec
        self._save_recovery_blob(blob)

    def record_recovery_otp_failure(self) -> int:
        blob = self._get_recovery_blob()
        if not blob or not blob.get("enabled"):
            return 0
        self._record_recovery_failure(blob)
        return max(0, int(round(float(blob.get("locked_until", 0.0) or 0.0) - time.time())))

    def send_recovery_otp(self, recovery_email: str) -> Tuple[str, bytes, int]:
        blob = self._get_recovery_blob()
        if not blob or not blob.get("enabled"):
            raise ValueError("Password recovery is not configured for this vault.")
        now_ts = time.time()
        locked_until = float(blob.get("locked_until", 0.0) or 0.0)
        if locked_until > now_ts:
            rem = int(round(locked_until - now_ts))
            raise ValueError(f"Too many failed attempts. Try again in {rem}s.")

        email_norm = RecoveryEmailService.normalize_email(recovery_email)
        rec_salt = base64.b64decode(blob["salt_b64"])
        given_hash = base64.b64encode(SecurityService.derive_key(email_norm, rec_salt, 100_000)).decode("ascii")
        expected_hash = blob.get("email_hash") or blob.get("contact_hash", "")
        if not hmac.compare_digest(given_hash, expected_hash):
            self._record_recovery_failure(blob)
            raise ValueError("Entered Email does not match the registered recovery Email.")

        smtp = blob.get("smtp") or {}
        if not smtp.get("enabled"):
            raise ValueError("Google SMTP Email OTP is not enabled. Use your Recovery Key directly.")
        app_pw = ""
        if smtp.get("secret_dpapi") and WindowsAuthService.IS_WINDOWS:
            app_pw = WindowsAuthService.dpapi_unprotect(smtp["secret_dpapi"]).decode("utf-8")
        elif smtp.get("secret_local"):
            local_key = SecurityService.derive_key(email_norm, rec_salt, 50_000)
            app_pw = SecurityService.decrypt_bytes(local_key, smtp["secret_local"]).decode("utf-8")
        if not app_pw:
            raise ValueError("Google App Password missing. Reconfigure recovery in Settings.")

        otp_code = RecoveryEmailService.generate_otp()
        otp_salt = secrets.token_bytes(16)
        otp_hash = RecoveryEmailService.hash_otp(otp_code, otp_salt)
        RecoveryEmailService.send_otp_email(
            sender_email=smtp["sender_email"],
            app_password=app_pw,
            recipient_email=email_norm,
            otp_code=otp_code,
            smtp_host=smtp.get("host", RecoveryEmailService.GOOGLE_SMTP_HOST),
            smtp_port=int(smtp.get("port", RecoveryEmailService.GOOGLE_SMTP_PORT) or 587),
        )
        return (otp_hash, otp_salt, int(time.time()) + 300)

    def reset_password_via_recovery(self, recovery_email: str, recovery_key: str, new_password: str) -> bytes:
        meta = self.get_meta()
        if not meta:
            raise RuntimeError("Vault has not been created yet.")
        if meta["auth_mode"] != "custom":
            raise ValueError("Password recovery is only for Custom Password vaults.")
        blob = self._get_recovery_blob()
        if not blob or not blob.get("enabled"):
            raise ValueError("Password recovery is not configured for this vault.")

        now_ts = time.time()
        locked_until = float(blob.get("locked_until", 0.0) or 0.0)
        if locked_until > now_ts:
            rem = int(round(locked_until - now_ts))
            raise ValueError(f"Recovery temporarily locked. Try again in {rem}s.")

        SecurityService.validate_login_password(new_password, auth_mode="custom", label="New password")
        email_norm = RecoveryEmailService.normalize_email(recovery_email)
        canonical_key = RecoveryEmailService.normalize_recovery_key(recovery_key)

        rec_salt = base64.b64decode(blob["salt_b64"])
        given_hash = base64.b64encode(SecurityService.derive_key(email_norm, rec_salt, 100_000)).decode("ascii")
        expected_hash = blob.get("email_hash") or blob.get("contact_hash", "")
        if not hmac.compare_digest(given_hash, expected_hash):
            self._record_recovery_failure(blob)
            raise ValueError("Registered Email or Recovery Key is incorrect.")

        try:
            rec_kek = SecurityService.derive_key(f"{canonical_key}|{email_norm}", rec_salt, SecurityService.ITERATIONS)
            dek = SecurityService.decrypt_bytes(rec_kek, blob["wrapped_dek"])
        except Exception:
            self._record_recovery_failure(blob)
            raise ValueError("Registered Email or Recovery Key is incorrect.")

        new_salt = secrets.token_bytes(16)
        new_salt_b64 = base64.b64encode(new_salt).decode("ascii")
        new_kek = SecurityService.derive_key(new_password, new_salt)
        new_wrapped = SecurityService.encrypt_bytes(new_kek, dek)

        blob["failed_attempts"] = 0
        blob["locked_until"] = 0.0
        now_iso = datetime.datetime.now().isoformat(timespec="seconds")
        with self._lock:
            self.conn.execute(
                """
                UPDATE vault_meta
                SET salt_b64 = ?, wrapped_dek = ?, dpapi_dek = NULL, recovery_json = ?, updated_at = ?
                WHERE id = 1
                """,
                (new_salt_b64, new_wrapped, json.dumps(blob, ensure_ascii=False), now_iso),
            )
            self.conn.commit()
        self._migrate_legacy_entries(dek)
        return dek

    def get_settings(self) -> Dict[str, Any]:
        meta = self.get_meta()
        if not meta:
            return {}
        data = json.loads(meta["settings_json"])
        if isinstance(data, dict):
            data.pop(self._INTERNAL_META_KEY, None)
        return data

    def save_settings(self, settings: Dict[str, Any]) -> None:
        now = datetime.datetime.now().isoformat(timespec="seconds")
        payload = dict(settings)
        with self._lock:
            meta = self.get_meta()
            if meta:
                try:
                    cur_settings = json.loads(meta["settings_json"])
                    if isinstance(cur_settings, dict) and self._INTERNAL_META_KEY in cur_settings:
                        payload[self._INTERNAL_META_KEY] = cur_settings[self._INTERNAL_META_KEY]
                except Exception:
                    pass
            self.conn.execute(
                "UPDATE vault_meta SET settings_json = ?, updated_at = ? WHERE id = 1",
                (json.dumps(payload, ensure_ascii=False), now),
            )
            self.conn.commit()

    def list_categories(self) -> List[str]:
        with self._lock:
            rows = self.conn.execute("SELECT name FROM categories ORDER BY sort_order ASC, id ASC").fetchall()
            return [r["name"] for r in rows]

    def add_category(self, name: str) -> str:
        clean = name.strip()
        if not clean:
            raise ValueError("Category name cannot be empty.")
        with self._lock:
            existing = self.list_categories()
            for c in existing:
                if c.lower() == clean.lower():
                    return c
            max_order = self.conn.execute("SELECT COALESCE(MAX(sort_order), -1) FROM categories").fetchone()[0]
            self.conn.execute(
                "INSERT INTO categories (name, sort_order) VALUES (?, ?)",
                (clean, max_order + 1),
            )
            self.conn.commit()
            return clean

    def move_category(self, name: str, direction: int) -> bool:
        """Moves category up (direction < 0) or down (direction > 0) and updates sort_order."""
        if direction == 0:
            return False
        step = -1 if direction < 0 else 1
        with self._lock:
            rows = [
                dict(r)
                for r in self.conn.execute(
                    "SELECT id, name, sort_order FROM categories ORDER BY sort_order ASC, id ASC"
                ).fetchall()
            ]
            idx = next((i for i, r in enumerate(rows) if r["name"] == name), -1)
            target_idx = idx + step
            if idx < 0 or not (0 <= target_idx < len(rows)):
                return False
            rows[idx], rows[target_idx] = rows[target_idx], rows[idx]
            for new_order, row in enumerate(rows):
                self.conn.execute(
                    "UPDATE categories SET sort_order = ? WHERE id = ?",
                    (new_order, row["id"]),
                )
            self.conn.commit()
            return True

    def rename_category(self, old_name: str, new_name: str, dek: bytes) -> str:
        clean = new_name.strip()
        if not clean:
            raise ValueError("Category name cannot be empty.")
        if old_name == clean:
            return clean
        with self._lock:
            existing = self.list_categories()
            if any(c.lower() == clean.lower() and c != old_name for c in existing):
                raise ValueError("A category with that name already exists.")
            row = self.conn.execute("SELECT id FROM categories WHERE name = ?", (old_name,)).fetchone()
            if row:
                self.conn.execute("UPDATE categories SET name = ? WHERE id = ?", (clean, row["id"]))
            else:
                max_order = self.conn.execute("SELECT COALESCE(MAX(sort_order), -1) FROM categories").fetchone()[0]
                self.conn.execute("INSERT INTO categories (name, sort_order) VALUES (?, ?)", (clean, max_order + 1))
            for entry in self.list_entries(dek):
                if entry.get("category") == old_name:
                    entry["category"] = clean
                    self.save_entry(entry, dek)
            self.conn.commit()
            return clean

    def delete_category(self, name: str, dek: bytes) -> str:
        with self._lock:
            cats = self.list_categories()
            if len(cats) <= 1:
                raise ValueError("At least one category must remain in the vault.")
            fallback = next(c for c in cats if c != name)
            for entry in self.list_entries(dek):
                if entry.get("category") == name:
                    entry["category"] = fallback
                    self.save_entry(entry, dek)
            self.conn.execute("DELETE FROM categories WHERE name = ?", (name,))
            self.conn.commit()
            return fallback

    def list_custom_logos(self) -> List[Dict[str, str]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT id, label, domain, file_name FROM custom_logos ORDER BY id DESC, label ASC"
            ).fetchall()
            return [
                {
                    "id": str(r["id"]),
                    "label": r["label"],
                    "domain": r["domain"],
                    "file_name": r["file_name"],
                }
                for r in rows
            ]

    def add_custom_logo(self, label: str, domain: str, mime_type: str, data_b64: str) -> str:
        clean_label = label.strip()
        if not clean_label:
            raise ValueError("Logo name is required.")
        if mime_type not in ALLOWED_IMAGE_MIMES:
            raise ValueError("Only PNG, JPG, JPEG, and GIF formats are allowed.")
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO custom_logos (label, domain, file_name) VALUES (?, ?, '')",
                (clean_label, domain.strip().lower()),
            )
            lid = str(cur.lastrowid)
            try:
                file_name = ImageValidator.save_logo_file(
                    data_b64,
                    mime_type,
                    f"default_{lid}_{secrets.token_hex(3)}",
                    logos_dir=self.logos_dir,
                )
            except Exception:
                self.conn.execute("DELETE FROM custom_logos WHERE id = ?", (cur.lastrowid,))
                self.conn.commit()
                raise
            self.conn.execute("UPDATE custom_logos SET file_name = ? WHERE id = ?", (file_name, cur.lastrowid))
            self.conn.commit()
        return lid

    def delete_custom_logo(self, logo_id: str, dek: bytes) -> None:
        key_ref = f"custom:{logo_id}"
        db_lid = self._db_id(logo_id)
        with self._lock:
            row = self.conn.execute("SELECT file_name FROM custom_logos WHERE id = ?", (db_lid,)).fetchone()
            old_file = row["file_name"] if row else ""
            customs = [c for c in self.list_custom_logos() if c["id"] != str(logo_id)]
            for entry in self.list_entries(dek):
                if entry.get("logo_key") == key_ref:
                    entry["logo_key"] = ImageValidator.match_logo_key(entry.get("site_url", ""), entry.get("title", ""), customs)
                    self.save_entry(entry, dek)
            self.conn.execute("DELETE FROM custom_logos WHERE id = ?", (db_lid,))
            self.conn.commit()
        if old_file:
            ImageValidator.delete_logo_file(old_file, logos_dir=self.logos_dir)

    def list_people(self) -> List[Dict[str, str]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT id, name, avatar_file, created_at FROM people ORDER BY id ASC"
            ).fetchall()
            return [
                {
                    "id": str(r["id"]),
                    "name": r["name"],
                    "avatar_file": r["avatar_file"],
                    "created_at": r["created_at"],
                }
                for r in rows
            ]

    def upsert_person(
        self,
        person_id: Optional[str],
        name: str,
        avatar_mime: str = "",
        avatar_b64: str = "",
        clear_avatar: bool = False,
    ) -> str:
        clean = name.strip()
        if not clean:
            raise ValueError("Person name cannot be empty.")
        if avatar_b64 and avatar_mime not in ALLOWED_IMAGE_MIMES:
            raise ValueError("Only PNG, JPG, JPEG, and GIF image formats are allowed.")
        old_file_to_delete = ""
        with self._lock:
            existing = self.list_people()
            for p in existing:
                if p["name"].strip().lower() == clean.lower() and p["id"] != str(person_id or ""):
                    raise ValueError(f"Person '{clean}' already exists.")
            now = datetime.date.today().isoformat()
            old_row = (
                self.conn.execute(
                    "SELECT id, avatar_file, created_at FROM people WHERE id = ?",
                    (self._db_id(person_id),),
                ).fetchone()
                if person_id is not None and str(person_id).strip() != ""
                else None
            )

            if old_row:
                pid = str(old_row["id"])
                old_file = old_row["avatar_file"] or ""
                if clear_avatar:
                    new_file = ""
                    if old_file:
                        old_file_to_delete = old_file
                elif avatar_b64:
                    new_file = ImageValidator.save_logo_file(
                        avatar_b64,
                        avatar_mime,
                        f"avatar_{pid}_{secrets.token_hex(3)}",
                        logos_dir=self.avatars_dir,
                    )
                    if old_file and old_file != new_file:
                        old_file_to_delete = old_file
                else:
                    new_file = old_file
                self.conn.execute(
                    "UPDATE people SET name = ?, avatar_file = ? WHERE id = ?",
                    (clean, new_file, old_row["id"]),
                )
            else:
                cur = self.conn.execute(
                    "INSERT INTO people (name, avatar_file, created_at) VALUES (?, '', ?)",
                    (clean, now),
                )
                pid = str(cur.lastrowid)
                if avatar_b64 and not clear_avatar:
                    try:
                        new_file = ImageValidator.save_logo_file(
                            avatar_b64,
                            avatar_mime,
                            f"avatar_{pid}_{secrets.token_hex(3)}",
                            logos_dir=self.avatars_dir,
                        )
                        self.conn.execute(
                            "UPDATE people SET avatar_file = ? WHERE id = ?",
                            (new_file, cur.lastrowid),
                        )
                    except Exception:
                        self.conn.execute("DELETE FROM people WHERE id = ?", (cur.lastrowid,))
                        self.conn.commit()
                        raise
            self.conn.commit()
        if old_file_to_delete:
            ImageValidator.delete_logo_file(old_file_to_delete, logos_dir=self.avatars_dir)
        return pid

    def delete_person(self, person_id: str, dek: bytes) -> None:
        old_file = ""
        target_pid = str(person_id)
        db_pid = self._db_id(person_id)
        with self._lock:
            people = self.list_people()
            if len(people) <= 1:
                raise ValueError("At least one person must remain in the vault.")
            row = self.conn.execute("SELECT avatar_file FROM people WHERE id = ?", (db_pid,)).fetchone()
            old_file = row["avatar_file"] if row else ""
            for entry in self.list_entries(dek):
                if entry.get("person_id") == target_pid:
                    self.delete_entry(entry["id"], dek=dek)
            self.conn.execute("DELETE FROM people WHERE id = ?", (db_pid,))
            self.conn.commit()
        if old_file:
            ImageValidator.delete_logo_file(old_file, logos_dir=self.avatars_dir)

    def list_entries(self, dek: bytes) -> List[Dict[str, Any]]:
        self._migrate_legacy_entries(dek)
        with self._lock:
            rows = self.conn.execute(
                "SELECT id, encrypted_blob, created_at, updated_at FROM entries ORDER BY updated_at DESC, id DESC"
            ).fetchall()
        result: List[Dict[str, Any]] = []
        for r in rows:
            data = SecurityService.decrypt_json(dek, r["encrypted_blob"])
            data["id"] = str(r["id"])
            data["created_at"] = r["created_at"]
            data["updated_at"] = r["updated_at"]
            data.setdefault("site_url", "")
            data.setdefault("logo_key", "globe")
            data.setdefault("custom_logo_file", "")
            data.setdefault("username", "")
            data.setdefault("username_is_email", False)
            if data["username_is_email"]:
                data["email"] = data["username"]
            else:
                data.setdefault("email", "")
            data.setdefault("notes", "")
            data.setdefault("tags", [])
            data.setdefault("is_favorite", False)
            if data.get("person_id") is not None:
                data["person_id"] = str(data["person_id"])
            result.append(data)
        return result

    def save_entry(self, entry: Dict[str, Any], dek: bytes) -> str:
        raw_id = entry.get("id")
        eid_int = int(str(raw_id).strip()) if (raw_id is not None and str(raw_id).strip().isdigit()) else None
        now_iso = datetime.datetime.now().isoformat(timespec="seconds")
        created_at = str(entry.get("created_at") or "").strip() or datetime.date.today().isoformat()
        with self._lock:
            cats = self.list_categories()
            chosen_cat = (entry.get("category") or "").strip() or (cats[0] if cats else "General")
            if chosen_cat not in cats:
                self.add_category(chosen_cat)

            custom_logos = self.list_custom_logos()
            default_pid = self._first_person_id()
            prev_row = (
                self.conn.execute("SELECT encrypted_blob FROM entries WHERE id = ?", (eid_int,)).fetchone()
                if eid_int is not None
                else None
            )
            prev_file = ""
            if prev_row:
                try:
                    prev_file = SecurityService.decrypt_json(dek, prev_row["encrypted_blob"]).get("custom_logo_file", "")
                except Exception:
                    prev_file = ""

            custom_b64 = str(entry.get("custom_logo_b64") or "")
            custom_mime = str(entry.get("custom_logo_mime") or "image/png")
            passed_file = str(entry.get("custom_logo_file") or "")

            if custom_b64:
                stem = f"entry_{eid_int}" if eid_int is not None else f"entry_{secrets.token_hex(4)}"
                custom_file = ImageValidator.save_logo_file(custom_b64, custom_mime, stem, logos_dir=self.logos_dir)
                if prev_file and prev_file != custom_file:
                    ImageValidator.delete_logo_file(prev_file, logos_dir=self.logos_dir)
            else:
                custom_file = passed_file
                if prev_file and prev_file != custom_file:
                    ImageValidator.delete_logo_file(prev_file, logos_dir=self.logos_dir)

            payload = self._build_entry_blob_payload(
                entry,
                chosen_cat=chosen_cat,
                default_person_id=default_pid,
                custom_file=custom_file,
                custom_logos=custom_logos,
            )
            blob = SecurityService.encrypt_json(dek, payload)
            if prev_row and eid_int is not None:
                self.conn.execute(
                    "UPDATE entries SET encrypted_blob = ?, created_at = ?, updated_at = ? WHERE id = ?",
                    (blob, created_at, now_iso, eid_int),
                )
            elif eid_int is not None:
                self.conn.execute(
                    "INSERT INTO entries (id, encrypted_blob, created_at, updated_at) VALUES (?, ?, ?, ?)",
                    (eid_int, blob, created_at, now_iso),
                )
            else:
                cur = self.conn.execute(
                    "INSERT INTO entries (encrypted_blob, created_at, updated_at) VALUES (?, ?, ?)",
                    (blob, created_at, now_iso),
                )
                eid_int = int(cur.lastrowid)
            self.conn.commit()
        return str(eid_int)

    def delete_entry(self, entry_id: str, dek: Optional[bytes] = None) -> None:
        db_eid = self._db_id(entry_id)
        with self._lock:
            if dek is not None:
                row = self.conn.execute("SELECT encrypted_blob FROM entries WHERE id = ?", (db_eid,)).fetchone()
                if row:
                    try:
                        old_file = SecurityService.decrypt_json(dek, row["encrypted_blob"]).get("custom_logo_file", "")
                        if old_file:
                            ImageValidator.delete_logo_file(old_file, logos_dir=self.logos_dir)
                    except Exception:
                        pass
            self.conn.execute("DELETE FROM entries WHERE id = ?", (db_eid,))
            self.conn.commit()

    def create_local_backup(self, backup_dir: Optional[str] = None) -> str:
        raw_dir = (backup_dir or self.get_settings().get("local_backup_dir") or BACKUP_DIR).strip().strip('"').strip("'").strip()
        target_dir = os.path.abspath(raw_dir or BACKUP_DIR)
        os.makedirs(target_dir, exist_ok=True)
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        target = os.path.join(target_dir, f"pass_vault_backup_{stamp}.db")
        with self._lock:
            self.conn.commit()
            dst = sqlite3.connect(target)
            try:
                self.conn.backup(dst)
            finally:
                dst.close()
        files = sorted(
            [os.path.join(target_dir, f) for f in os.listdir(target_dir) if f.endswith(".db")],
            reverse=True,
        )
        for old in files[15:]:
            try:
                os.remove(old)
            except OSError:
                pass
        return target

    @staticmethod
    def _mime_for_filename(filename: str) -> str:
        ext = os.path.splitext(filename.lower())[1]
        if ext in (".jpg", ".jpeg"):
            return "image/jpeg"
        if ext == ".gif":
            return "image/gif"
        return "image/png"

    def export_e2ee_envelope(self, dek: bytes) -> Tuple[Dict[str, Any], int]:
        with self._lock:
            raw_entries = self.list_entries(dek)
            entries_out: List[Dict[str, Any]] = []
            for e in raw_entries:
                item = dict(e)
                if item.get("custom_logo_file"):
                    b64 = ImageValidator.load_logo_b64(item["custom_logo_file"], logos_dir=self.logos_dir)
                    if b64:
                        item["custom_logo_b64"] = b64
                        item["custom_logo_mime"] = self._mime_for_filename(item["custom_logo_file"])
                entries_out.append(item)

            people_out: List[Dict[str, Any]] = []
            for p in self.list_people():
                item = dict(p)
                if item.get("avatar_file"):
                    b64 = ImageValidator.load_logo_b64(item["avatar_file"], logos_dir=self.avatars_dir)
                    if b64:
                        item["avatar_b64"] = b64
                        item["avatar_mime"] = self._mime_for_filename(item["avatar_file"])
                people_out.append(item)

            logos_out: List[Dict[str, Any]] = []
            for cl in self.list_custom_logos():
                item = dict(cl)
                if item.get("file_name"):
                    b64 = ImageValidator.load_logo_b64(item["file_name"], logos_dir=self.logos_dir)
                    if b64:
                        item["data_b64"] = b64
                        item["mime_type"] = self._mime_for_filename(item["file_name"])
                logos_out.append(item)

            snapshot = {
                "entries": entries_out,
                "people": people_out,
                "categories": self.list_categories(),
                "customLogos": logos_out,
                "settings": self.get_settings(),
                "exported_at": datetime.datetime.now().isoformat(),
            }
        salt = secrets.token_bytes(16)
        sync_key = SecurityService.derive_key(base64.b64encode(dek).decode("ascii"), salt, 100_000)
        packed = SecurityService.encrypt_json(sync_key, snapshot)
        return ({
            "version": 1,
            "algorithm": "AES-256-GCM",
            "salt": base64.b64encode(salt).decode("ascii"),
            "ciphertext": packed,
            "updatedAt": datetime.datetime.now().isoformat(),
        }, len(raw_entries))

    def push_cloud_sync(self, dek: bytes, is_auto_backup: bool = False) -> None:
        settings = self.get_settings()
        base_url = settings.get("sync_url", "").rstrip("/")
        vault_id = re.sub(r"[^a-zA-Z0-9_-]", "", settings.get("sync_vault_id", ""))[:64]
        if not base_url.startswith(("http://", "https://")) or not vault_id:
            if not is_auto_backup:
                raise RuntimeError("Valid sync server URL (http/https) and Cloud Vault ID are required.")
            return
        envelope, entry_count = self.export_e2ee_envelope(dek)
        endpoint = f"{base_url}/api/backup/{vault_id}" if is_auto_backup else f"{base_url}/api/sync/{vault_id}"
        req = urllib.request.Request(
            endpoint,
            data=json.dumps({"envelope": envelope, "entryCount": entry_count}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            if resp.status >= 400:
                raise RuntimeError(f"Cloud sync returned HTTP {resp.status}")

    def pull_cloud_sync(self, dek: bytes) -> int:
        settings = self.get_settings()
        base_url = settings.get("sync_url", "").rstrip("/")
        vault_id = re.sub(r"[^a-zA-Z0-9_-]", "", settings.get("sync_vault_id", ""))[:64]
        if not base_url.startswith(("http://", "https://")) or not vault_id:
            raise RuntimeError("Valid sync server URL (http/https) and Cloud Vault ID are required.")
        with urllib.request.urlopen(f"{base_url}/api/sync/{vault_id}", timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        if not data.get("exists"):
            raise RuntimeError("No encrypted snapshot found on the cloud sync server.")
        envelope = data.get("envelope")
        if not isinstance(envelope, dict) or not envelope.get("salt") or not envelope.get("ciphertext"):
            raise RuntimeError("Invalid encrypted snapshot payload received from sync server.")
        salt = base64.b64decode(envelope["salt"])
        sync_key = SecurityService.derive_key(base64.b64encode(dek).decode("ascii"), salt, 100_000)
        snapshot = SecurityService.decrypt_json(sync_key, envelope["ciphertext"])
        if not isinstance(snapshot, dict):
            raise RuntimeError("Decrypted cloud snapshot is malformed.")
        with self._lock:
            for cat in snapshot.get("categories", []):
                if isinstance(cat, str) and cat.strip():
                    self.add_category(cat)

            logo_id_remap: Dict[str, str] = {}
            existing_logos = self.list_custom_logos()
            for cl in snapshot.get("customLogos", []):
                if not isinstance(cl, dict) or not cl.get("id") or not cl.get("label"):
                    continue
                mime = cl.get("mime_type") or "image/png"
                b64 = cl.get("data_b64") or ""
                if not b64 or mime not in ALLOWED_IMAGE_MIMES:
                    continue
                old_cid = str(cl["id"])
                matched = next(
                    (
                        cur_l for cur_l in existing_logos
                        if ImageValidator.load_logo_b64(cur_l.get("file_name", ""), logos_dir=self.logos_dir) == b64
                    ),
                    None,
                )
                if matched:
                    logo_id_remap[old_cid] = matched["id"]
                else:
                    new_cid = self.add_custom_logo(str(cl["label"])[:60], str(cl.get("domain", "")), mime, b64)
                    logo_id_remap[old_cid] = new_cid
                    existing_logos = self.list_custom_logos()

            person_id_remap: Dict[str, str] = {}
            existing_people = self.list_people()
            for p in snapshot.get("people", []):
                if not isinstance(p, dict) or not p.get("name"):
                    continue
                old_pid = str(p.get("id", ""))
                pname = str(p["name"]).strip()
                existing_match = next((ep for ep in existing_people if ep["name"].strip().lower() == pname.lower()), None)
                avatar_b64 = str(p.get("avatar_b64") or "")
                avatar_mime = str(p.get("avatar_mime") or "image/png")
                new_pid = self.upsert_person(
                    existing_match["id"] if existing_match else None,
                    pname,
                    avatar_mime=avatar_mime if avatar_b64 else "",
                    avatar_b64=avatar_b64,
                )
                if old_pid:
                    person_id_remap[old_pid] = new_pid
                existing_people = self.list_people()

            entries = [e for e in snapshot.get("entries", []) if isinstance(e, dict)]
            for e in entries:
                entry_copy = dict(e)
                old_pid = str(entry_copy.get("person_id", ""))
                if old_pid in person_id_remap:
                    entry_copy["person_id"] = person_id_remap[old_pid]
                lk = str(entry_copy.get("logo_key", ""))
                if lk.startswith("custom:"):
                    old_cid = lk.split(":", 1)[1]
                    if old_cid in logo_id_remap:
                        entry_copy["logo_key"] = f"custom:{logo_id_remap[old_cid]}"
                self.save_entry(entry_copy, dek)
            self.conn.commit()
        return len(entries)


VaultDatabase = VaultRepository
