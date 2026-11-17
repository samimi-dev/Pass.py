# -*- coding: utf-8 -*-
"""Modular OOP package for Pass.py — Offline Encrypted Password Manager."""

from .app import HAS_TKINTER, PassApp, PassVaultApp
from .assets import (
    ALLOWED_IMAGE_EXTS,
    ALLOWED_IMAGE_MIMES,
    DEFAULT_CATEGORIES,
    EMBEDDED_ICONS,
    POPULAR_SITE_LOGOS,
    IconAssets,
)
from .calendar_picker import CalendarDatePicker
from .icons import IconLibrary, LogoRenderer
from .image_validator import HAS_PILLOW, ImageValidator
from .password_generator import PasswordGeneratorService
from .paths import APP_DIR, AVATARS_DIR, BACKUP_DIR, DATA_DIR, DB_PATH, LOGOS_DIR, VaultPaths
from .recovery import RecoveryEmailService
from .repository import VaultDatabase, VaultRepository
from .scroll_helper import ScrollHelper
from .security import HAS_CRYPTOGRAPHY, SecurityService, VaultCrypto
from .strength_bar import PasswordStrengthBar
from .theme import APP_VERSION, FONT_MONO, FONT_UI, THEMES, ThemeManager
from .theme_switch import ThemeSwitchWidget
from .windows_auth import WindowsAuthService, WindowsSecurity

__all__ = [
    "APP_DIR",
    "APP_VERSION",
    "AVATARS_DIR",
    "BACKUP_DIR",
    "DATA_DIR",
    "DB_PATH",
    "LOGOS_DIR",
    "ALLOWED_IMAGE_EXTS",
    "ALLOWED_IMAGE_MIMES",
    "DEFAULT_CATEGORIES",
    "EMBEDDED_ICONS",
    "POPULAR_SITE_LOGOS",
    "FONT_MONO",
    "FONT_UI",
    "THEMES",
    "HAS_CRYPTOGRAPHY",
    "HAS_PILLOW",
    "HAS_TKINTER",
    "VaultPaths",
    "IconAssets",
    "ThemeManager",
    "ImageValidator",
    "SecurityService",
    "VaultCrypto",
    "WindowsAuthService",
    "WindowsSecurity",
    "RecoveryEmailService",
    "VaultRepository",
    "VaultDatabase",
    "PasswordGeneratorService",
    "IconLibrary",
    "LogoRenderer",
    "ScrollHelper",
    "PasswordStrengthBar",
    "ThemeSwitchWidget",
    "CalendarDatePicker",
    "PassVaultApp",
    "PassApp",
]
