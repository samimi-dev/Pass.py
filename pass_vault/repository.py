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
        cols = [r["name"] for r in cur.execute("PRAGMA table_info(vault_meta)").fetchall()]
        if "recovery_json" not in cols:
            cur.execute("ALTER TABLE vault_meta ADD COLUMN recovery_json TEXT NOT NULL DEFAULT ''")

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS people (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                avatar_file TEXT NOT NULL DEFAULT '',
                avatar_mime TEXT NOT NULL DEFAULT '',
                avatar_b64 TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            )
            """
        )
        p_cols = [r["name"] for r in cur.execute("PRAGMA table_info(people)").fetchall()]
        for col_name in ("avatar_file", "avatar_mime", "avatar_b64"):
            if col_name not in p_cols:
                cur.execute(f"ALTER TABLE people ADD COLUMN {col_name} TEXT NOT NULL DEFAULT ''")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS categories (
                name TEXT PRIMARY KEY,
                sort_order INTEGER NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS custom_logos (
                id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                domain TEXT NOT NULL,
                mime_type TEXT NOT NULL,
                data_b64 TEXT NOT NULL,
                file_name TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            )
            """
        )
        cl_cols = [r["name"] for r in cur.execute("PRAGMA table_info(custom_logos)").fetchall()]
        if "file_name" not in cl_cols:
            cur.execute("ALTER TABLE custom_logos ADD COLUMN file_name TEXT NOT NULL DEFAULT ''")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS entries (
                id TEXT PRIMARY KEY,
                encrypted_blob TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self.conn.commit()
        self._ensure_default_categories()

    def _ensure_default_categories(self) -> None:
        count = self.conn.execute("SELECT COUNT(*) FROM categories").fetchone()[0]
        now = datetime.date.today().isoformat()
        if count == 0:
            for idx, name in enumerate(DEFAULT_CATEGORIES):
                self.conn.execute(
                    "INSERT OR IGNORE INTO categories (name, sort_order, created_at) VALUES (?, ?, ?)",
                    (name, idx, now),
                )
            self.conn.commit()
            return
        # Ensure newly added default categories exist and default order stays tidy
        existing = {r["name"] for r in self.conn.execute("SELECT name FROM categories").fetchall()}
        next_order = (self.conn.execute("SELECT COALESCE(MAX(sort_order), -1) FROM categories").fetchone()[0]) + 1
        changed = False
        for idx, name in enumerate(DEFAULT_CATEGORIES):
            if name not in existing:
                self.conn.execute(
                    "INSERT OR IGNORE INTO categories (name, sort_order, created_at) VALUES (?, ?, ?)",
                    (name, idx if existing.issubset(set(DEFAULT_CATEGORIES) | {"Banking & Finance", "Shopping & Media"}) else next_order, now),
                )
                next_order += 1
                changed = True
        if existing.issubset(set(DEFAULT_CATEGORIES) | {"Banking & Finance", "Shopping & Media"}):
            for idx, name in enumerate(DEFAULT_CATEGORIES):
                self.conn.execute("UPDATE categories SET sort_order = ? WHERE name = ?", (idx, name))
            changed = True
        if changed:
            self.conn.commit()

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
            self.conn.execute("INSERT OR IGNORE INTO people (id, name, created_at) VALUES (?, ?, ?)", ("person-self", "Me", now[:10]))
            self.conn.execute("INSERT OR IGNORE INTO people (id, name, created_at) VALUES (?, ?, ?)", ("person-spouse", "Spouse", now[:10]))
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
        return dek

    def get_settings(self) -> Dict[str, Any]:
        meta = self.get_meta()
        return json.loads(meta["settings_json"]) if meta else {}

    def save_settings(self, settings: Dict[str, Any]) -> None:
        now = datetime.datetime.now().isoformat(timespec="seconds")
        with self._lock:
            self.conn.execute(
                "UPDATE vault_meta SET settings_json = ?, updated_at = ? WHERE id = 1",
                (json.dumps(settings, ensure_ascii=False), now),
            )
            self.conn.commit()

    def list_categories(self) -> List[str]:
        with self._lock:
            rows = self.conn.execute("SELECT name FROM categories ORDER BY sort_order ASC, name ASC").fetchall()
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
                "INSERT INTO categories (name, sort_order, created_at) VALUES (?, ?, ?)",
                (clean, max_order + 1, datetime.date.today().isoformat()),
            )
            self.conn.commit()
            return clean

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
            row = self.conn.execute("SELECT sort_order, created_at FROM categories WHERE name = ?", (old_name,)).fetchone()
            sort_order = row["sort_order"] if row else len(existing)
            created_at = row["created_at"] if row else datetime.date.today().isoformat()
            self.conn.execute("DELETE FROM categories WHERE name = ?", (old_name,))
            self.conn.execute(
                "INSERT OR REPLACE INTO categories (name, sort_order, created_at) VALUES (?, ?, ?)",
                (clean, sort_order, created_at),
            )
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
                "SELECT id, label, domain, mime_type, data_b64, file_name, created_at FROM custom_logos ORDER BY created_at DESC, label ASC"
            ).fetchall()
            return [dict(r) for r in rows]

    def add_custom_logo(self, label: str, domain: str, mime_type: str, data_b64: str) -> str:
        clean_label = label.strip()
        if not clean_label:
            raise ValueError("Logo name is required.")
        if mime_type not in ALLOWED_IMAGE_MIMES:
            raise ValueError("Only PNG, JPG, JPEG, and GIF formats are allowed.")
        lid = f"clogo-{secrets.token_hex(4)}"
        file_name = ImageValidator.save_logo_file(data_b64, mime_type, f"default_{lid}", logos_dir=self.logos_dir)
        with self._lock:
            self.conn.execute(
                "INSERT INTO custom_logos (id, label, domain, mime_type, data_b64, file_name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (lid, clean_label, domain.strip().lower(), mime_type, data_b64, file_name, datetime.date.today().isoformat()),
            )
            self.conn.commit()
        return lid

    def delete_custom_logo(self, logo_id: str, dek: bytes) -> None:
        key_ref = f"custom:{logo_id}"
        with self._lock:
            row = self.conn.execute("SELECT file_name FROM custom_logos WHERE id = ?", (logo_id,)).fetchone()
            old_file = row["file_name"] if row else ""
            customs = [c for c in self.list_custom_logos() if c["id"] != logo_id]
            for entry in self.list_entries(dek):
                if entry.get("logo_key") == key_ref:
                    entry["logo_key"] = ImageValidator.match_logo_key(entry.get("site_url", ""), entry.get("title", ""), customs)
                    self.save_entry(entry, dek)
            self.conn.execute("DELETE FROM custom_logos WHERE id = ?", (logo_id,))
            self.conn.commit()
        if old_file:
            ImageValidator.delete_logo_file(old_file, logos_dir=self.logos_dir)

    def list_people(self) -> List[Dict[str, str]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT id, name, avatar_file, avatar_mime, avatar_b64, created_at FROM people ORDER BY created_at ASC, name ASC"
            ).fetchall()
            people = [dict(r) for r in rows]
        for p in people:
            if not p.get("avatar_b64") and p.get("avatar_file"):
                p["avatar_b64"] = ImageValidator.load_logo_b64(p["avatar_file"], logos_dir=self.avatars_dir)
        return people

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
                if p["name"].strip().lower() == clean.lower() and p["id"] != person_id:
                    raise ValueError(f"Person '{clean}' already exists.")
            pid = person_id or f"person-{secrets.token_hex(4)}"
            now = datetime.date.today().isoformat()
            old_row = (
                self.conn.execute(
                    "SELECT id, avatar_file, avatar_mime, avatar_b64, created_at FROM people WHERE id = ?",
                    (pid,),
                ).fetchone()
                if person_id
                else None
            )
            old_file = old_row["avatar_file"] if old_row else ""
            if clear_avatar:
                new_file, new_mime, new_b64 = "", "", ""
                if old_file:
                    old_file_to_delete = old_file
            elif avatar_b64:
                new_file = ImageValidator.save_logo_file(
                    avatar_b64,
                    avatar_mime,
                    f"avatar_{pid}_{secrets.token_hex(3)}",
                    logos_dir=self.avatars_dir,
                )
                new_mime = avatar_mime
                new_b64 = avatar_b64
                if old_file and old_file != new_file:
                    old_file_to_delete = old_file
            else:
                new_file = old_file
                new_mime = old_row["avatar_mime"] if old_row else ""
                new_b64 = old_row["avatar_b64"] if old_row else ""

            if old_row:
                self.conn.execute(
                    "UPDATE people SET name = ?, avatar_file = ?, avatar_mime = ?, avatar_b64 = ? WHERE id = ?",
                    (clean, new_file, new_mime, new_b64, pid),
                )
            else:
                cols = [r["name"] for r in self.conn.execute("PRAGMA table_info(people)").fetchall()]
                if "relation" in cols:
                    self.conn.execute(
                        "INSERT INTO people (id, name, relation, avatar_file, avatar_mime, avatar_b64, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (pid, clean, "", new_file, new_mime, new_b64, now),
                    )
                else:
                    self.conn.execute(
                        "INSERT INTO people (id, name, avatar_file, avatar_mime, avatar_b64, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                        (pid, clean, new_file, new_mime, new_b64, now),
                    )
            self.conn.commit()
        if old_file_to_delete:
            ImageValidator.delete_logo_file(old_file_to_delete, logos_dir=self.avatars_dir)
        return pid

    def delete_person(self, person_id: str, dek: bytes) -> None:
        old_file = ""
        with self._lock:
            people = self.list_people()
            if len(people) <= 1:
                raise ValueError("At least one person must remain in the vault.")
            row = self.conn.execute("SELECT avatar_file FROM people WHERE id = ?", (person_id,)).fetchone()
            old_file = row["avatar_file"] if row else ""
            for entry in self.list_entries(dek):
                if entry.get("person_id") == person_id:
                    self.delete_entry(entry["id"], dek=dek)
            self.conn.execute("DELETE FROM people WHERE id = ?", (person_id,))
            self.conn.commit()
        if old_file:
            ImageValidator.delete_logo_file(old_file, logos_dir=self.avatars_dir)

    def list_entries(self, dek: bytes) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute("SELECT id, encrypted_blob FROM entries ORDER BY updated_at DESC").fetchall()
        result: List[Dict[str, Any]] = []
        for r in rows:
            data = SecurityService.decrypt_json(dek, r["encrypted_blob"])
            data["id"] = r["id"]
            result.append(data)
        return result

    def save_entry(self, entry: Dict[str, Any], dek: bytes) -> str:
        eid = entry.get("id") or f"entry-{secrets.token_hex(6)}"
        now_iso = datetime.datetime.now().isoformat(timespec="seconds")
        created_at = entry.get("created_at") or datetime.date.today().isoformat()
        with self._lock:
            cats = self.list_categories()
            chosen_cat = (entry.get("category") or "").strip() or (cats[0] if cats else "General")
            if chosen_cat not in cats:
                self.add_category(chosen_cat)

            custom_logos = self.list_custom_logos()
            custom_b64 = entry.get("custom_logo_b64", "")
            custom_mime = entry.get("custom_logo_mime", "image/png")
            prev_row = self.conn.execute("SELECT encrypted_blob FROM entries WHERE id = ?", (eid,)).fetchone()
            prev_file = ""
            if prev_row:
                try:
                    prev_file = SecurityService.decrypt_json(dek, prev_row["encrypted_blob"]).get("custom_logo_file", "")
                except Exception:
                    prev_file = ""
            if custom_b64:
                custom_file = ImageValidator.save_logo_file(custom_b64, custom_mime, f"entry_{eid}", logos_dir=self.logos_dir)
                if prev_file and prev_file != custom_file:
                    ImageValidator.delete_logo_file(prev_file, logos_dir=self.logos_dir)
            else:
                custom_file = ""
                if prev_file:
                    ImageValidator.delete_logo_file(prev_file, logos_dir=self.logos_dir)

            payload = {
                "id": eid,
                "title": entry.get("title", "").strip(),
                "site_url": entry.get("site_url", "").strip(),
                "logo_key": entry.get("logo_key") or ImageValidator.match_logo_key(entry.get("site_url", ""), entry.get("title", ""), custom_logos),
                "custom_logo_b64": custom_b64,
                "custom_logo_mime": custom_mime,
                "custom_logo_file": custom_file,
                "username": entry.get("username", "").strip(),
                "username_is_email": bool(entry.get("username_is_email", False)),
                "password": entry.get("password", ""),
                "email": entry.get("username", "").strip() if entry.get("username_is_email") else entry.get("email", "").strip(),
                "notes": entry.get("notes", "").strip(),
                "category": chosen_cat,
                "tags": [t.strip() for t in entry.get("tags", []) if t.strip()],
                "is_favorite": bool(entry.get("is_favorite", False)),
                "person_id": entry.get("person_id") or "person-self",
                "created_at": created_at,
                "updated_at": now_iso,
            }
            blob = SecurityService.encrypt_json(dek, payload)
            self.conn.execute(
                "INSERT OR REPLACE INTO entries (id, encrypted_blob, created_at, updated_at) VALUES (?, ?, ?, ?)",
                (eid, blob, created_at, now_iso),
            )
            self.conn.commit()
        return eid

    def delete_entry(self, entry_id: str, dek: Optional[bytes] = None) -> None:
        with self._lock:
            if dek is not None:
                row = self.conn.execute("SELECT encrypted_blob FROM entries WHERE id = ?", (entry_id,)).fetchone()
                if row:
                    try:
                        old_file = SecurityService.decrypt_json(dek, row["encrypted_blob"]).get("custom_logo_file", "")
                        if old_file:
                            ImageValidator.delete_logo_file(old_file, logos_dir=self.logos_dir)
                    except Exception:
                        pass
            self.conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
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

    def export_e2ee_envelope(self, dek: bytes) -> Tuple[Dict[str, Any], int]:
        with self._lock:
            entries = self.list_entries(dek)
            snapshot = {
                "entries": entries,
                "people": self.list_people(),
                "categories": self.list_categories(),
                "customLogos": self.list_custom_logos(),
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
        }, len(entries))

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
            for cl in snapshot.get("customLogos", []):
                if not isinstance(cl, dict) or not cl.get("id") or not cl.get("label"):
                    continue
                mime = cl.get("mime_type") or "image/png"
                b64 = cl.get("data_b64") or ""
                if b64 and mime in ALLOWED_IMAGE_MIMES:
                    cid = re.sub(r"[^a-zA-Z0-9_-]", "", str(cl["id"]))[:40]
                    if not cid:
                        continue
                    fname = ImageValidator.save_logo_file(b64, mime, f"default_{cid}", logos_dir=self.logos_dir)
                    self.conn.execute(
                        "INSERT OR REPLACE INTO custom_logos (id, label, domain, mime_type, data_b64, file_name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (cid, str(cl["label"])[:60], str(cl.get("domain", "")), mime, b64, fname, str(cl.get("created_at") or datetime.date.today().isoformat())),
                    )
            for p in snapshot.get("people", []):
                if isinstance(p, dict) and p.get("id") and p.get("name"):
                    self.upsert_person(str(p["id"]), str(p["name"]))
            entries = [e for e in snapshot.get("entries", []) if isinstance(e, dict)]
            for e in entries:
                self.save_entry(e, dek)
            self.conn.commit()
        return len(entries)


VaultDatabase = VaultRepository
