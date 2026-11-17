#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pass.py - Offline Encrypted Windows Password Manager (Modular Pure Python OOP)
==============================================================================
- Each OOP class resides in its own dedicated module inside `pass_vault/`
- AES-256-GCM (or pure-stdlib CTR-HMAC-SHA256) + PBKDF2-HMAC-SHA256 (600,000 iterations)
- Custom Master Password OR Windows Account Password (LogonUserW + DPAPI)
- Email Recovery + Google Gmail SMTP 6-digit OTP + Zero-Knowledge Recovery Key
"""

import ctypes
import sys

# Windows High-DPI Awareness
if sys.platform == "win32":
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass

from pass_vault import (  # noqa: E402
    ALLOWED_IMAGE_EXTS,
    ALLOWED_IMAGE_MIMES,
    APP_DIR,
    APP_VERSION,
    AVATARS_DIR,
    BACKUP_DIR,
    DATA_DIR,
    DB_PATH,
    DEFAULT_CATEGORIES,
    EMBEDDED_ICONS,
    FONT_MONO,
    FONT_UI,
    HAS_CRYPTOGRAPHY,
    HAS_PILLOW,
    HAS_TKINTER,
    LOGOS_DIR,
    POPULAR_SITE_LOGOS,
    THEMES,
    CalendarDatePicker,
    IconAssets,
    IconLibrary,
    ImageValidator,
    LogoRenderer,
    PassApp,
    PassVaultApp,
    PasswordGeneratorService,
    PasswordStrengthBar,
    RecoveryEmailService,
    ScrollHelper,
    SecurityService,
    ThemeManager,
    ThemeSwitchWidget,
    VaultCrypto,
    VaultDatabase,
    VaultPaths,
    VaultRepository,
    WindowsAuthService,
    WindowsSecurity,
)


def main() -> None:
    WindowsAuthService.minimize_console_window()
    app = PassVaultApp()
    app.mainloop()


if __name__ == "__main__":
    main()
