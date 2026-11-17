# -*- coding: utf-8 -*-
"""Portable filesystem paths for Pass.py (keeps vault data beside Pass.py / Pass.exe)."""

import os
import sys


class VaultPaths:
    """Resolves portable zero-install application and vault storage paths."""

    @staticmethod
    def get_app_dir() -> str:
        if getattr(sys, "frozen", False):
            return os.path.dirname(os.path.abspath(sys.executable))
        # Point to the project root (parent of pass_vault package) where Pass.py resides
        pkg_dir = os.path.dirname(os.path.abspath(__file__))
        return os.path.dirname(pkg_dir)

    @staticmethod
    def ensure_dirs() -> None:
        os.makedirs(DATA_DIR, exist_ok=True)
        os.makedirs(BACKUP_DIR, exist_ok=True)
        os.makedirs(LOGOS_DIR, exist_ok=True)
        os.makedirs(AVATARS_DIR, exist_ok=True)


APP_DIR = VaultPaths.get_app_dir()
DATA_DIR = os.path.join(APP_DIR, "vault_data")
DB_PATH = os.path.join(DATA_DIR, "pass_vault.db")
BACKUP_DIR = os.path.join(DATA_DIR, "backups")
LOGOS_DIR = os.path.join(DATA_DIR, "logos")
AVATARS_DIR = os.path.join(DATA_DIR, "avatars")
