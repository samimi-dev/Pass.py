# -*- coding: utf-8 -*-
"""Native Windows LogonUserW authentication and DPAPI data protection."""

import base64
import ctypes
from ctypes import wintypes
import getpass
import sys


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


class WindowsAuthService:
    """Native Windows Authentication (LogonUserW) + DPAPI Key Wrapping."""

    IS_WINDOWS = sys.platform == "win32"

    if IS_WINDOWS:
        try:
            _advapi32 = ctypes.windll.advapi32
            _kernel32 = ctypes.windll.kernel32
            _crypt32 = ctypes.windll.crypt32

            _advapi32.GetUserNameW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(wintypes.DWORD)]
            _advapi32.GetUserNameW.restype = wintypes.BOOL

            _advapi32.LogonUserW.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                wintypes.DWORD,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.HANDLE),
            ]
            _advapi32.LogonUserW.restype = wintypes.BOOL

            _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            _kernel32.CloseHandle.restype = wintypes.BOOL

            _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
            _kernel32.LocalFree.restype = ctypes.c_void_p

            _crypt32.CryptProtectData.argtypes = [
                ctypes.POINTER(DATA_BLOB),
                ctypes.c_wchar_p,
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_void_p,
                wintypes.DWORD,
                ctypes.POINTER(DATA_BLOB),
            ]
            _crypt32.CryptProtectData.restype = wintypes.BOOL

            _crypt32.CryptUnprotectData.argtypes = [
                ctypes.POINTER(DATA_BLOB),
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_void_p,
                wintypes.DWORD,
                ctypes.POINTER(DATA_BLOB),
            ]
            _crypt32.CryptUnprotectData.restype = wintypes.BOOL
        except Exception:
            IS_WINDOWS = False

    @classmethod
    def current_username(cls) -> str:
        if cls.IS_WINDOWS:
            try:
                size = wintypes.DWORD(256)
                buf = ctypes.create_unicode_buffer(256)
                if cls._advapi32.GetUserNameW(buf, ctypes.byref(size)):
                    return buf.value
            except Exception:
                pass
        try:
            return getpass.getuser() or "User"
        except Exception:
            return "User"

    @classmethod
    def verify_windows_password(cls, password: str) -> bool:
        if not cls.IS_WINDOWS:
            raise RuntimeError("Windows password login is only supported on Windows.")
        username = cls.current_username()
        handle = wintypes.HANDLE()
        ok = cls._advapi32.LogonUserW(username, ".", password, 2, 0, ctypes.byref(handle))
        if ok:
            cls._kernel32.CloseHandle(handle)
            return True
        ok_net = cls._advapi32.LogonUserW(username, ".", password, 3, 0, ctypes.byref(handle))
        if ok_net:
            cls._kernel32.CloseHandle(handle)
            return True
        return False

    @classmethod
    def dpapi_protect(cls, raw_bytes: bytes) -> str:
        if not cls.IS_WINDOWS:
            raise RuntimeError("DPAPI requires Windows.")
        in_blob = DATA_BLOB(len(raw_bytes), ctypes.create_string_buffer(raw_bytes))
        out_blob = DATA_BLOB()
        if not cls._crypt32.CryptProtectData(ctypes.byref(in_blob), "Pass.py", None, None, None, 0x01, ctypes.byref(out_blob)):
            raise ctypes.WinError()
        try:
            encrypted = ctypes.string_at(out_blob.pbData, out_blob.cbData)
            return base64.b64encode(encrypted).decode("ascii")
        finally:
            cls._kernel32.LocalFree(out_blob.pbData)

    @classmethod
    def dpapi_unprotect(cls, b64_cipher: str) -> bytes:
        if not cls.IS_WINDOWS:
            raise RuntimeError("DPAPI requires Windows.")
        raw_cipher = base64.b64decode(b64_cipher)
        in_blob = DATA_BLOB(len(raw_cipher), ctypes.create_string_buffer(raw_cipher))
        out_blob = DATA_BLOB()
        if not cls._crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0x01, ctypes.byref(out_blob)):
            raise ctypes.WinError()
        try:
            return ctypes.string_at(out_blob.pbData, out_blob.cbData)
        finally:
            cls._kernel32.LocalFree(out_blob.pbData)

    @classmethod
    def minimize_console_window(cls) -> None:
        """Minimizes the attached Windows Command Prompt console window on startup."""
        if not cls.IS_WINDOWS:
            return
        try:
            hwnd = cls._kernel32.GetConsoleWindow()
            if hwnd:
                ctypes.windll.user32.ShowWindow(hwnd, 6)  # SW_MINIMIZE
        except Exception:
            pass


WindowsSecurity = WindowsAuthService
