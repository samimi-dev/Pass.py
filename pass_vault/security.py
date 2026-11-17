# -*- coding: utf-8 -*-
"""Cryptographic engine and login password validator for Pass.py."""

import base64
import hashlib
import hmac
import json
import secrets
from typing import Any

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_CRYPTOGRAPHY = True
except ImportError:
    AESGCM = None
    HAS_CRYPTOGRAPHY = False


class SecurityService:
    """AES-256-GCM (with pure-stdlib CTR-HMAC-SHA256 fallback) & PBKDF2-HMAC-SHA256."""

    ITERATIONS = 600_000

    @staticmethod
    def is_english_password(password: str, allow_spaces: bool = False) -> bool:
        low = 32 if allow_spaces else 33
        return all(low <= ord(ch) <= 126 for ch in password)

    @classmethod
    def validate_login_password(cls, password: str, auth_mode: str = "custom", label: str = "Password") -> str:
        if not password:
            raise ValueError(f"{label} is required.")
        if auth_mode == "windows":
            return password
        if len(password) < 2:
            raise ValueError(f"{label} must be at least 2 characters.")
        if not cls.is_english_password(password, allow_spaces=False):
            raise ValueError(f"{label} must use English characters and numbers only (no Persian or spaces).")
        return password

    @staticmethod
    def derive_key(secret: str, salt: bytes, iterations: int = ITERATIONS) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, iterations, dklen=32)

    @staticmethod
    def _xor_keystream(key: bytes, nonce: bytes, data: bytes) -> bytes:
        out = bytearray(len(data))
        counter = 0
        offset = 0
        while offset < len(data):
            block = hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
            chunk = data[offset:offset + 32]
            for i, b in enumerate(chunk):
                out[offset + i] = b ^ block[i]
            offset += 32
            counter += 1
        return bytes(out)

    @classmethod
    def encrypt_bytes(cls, key: bytes, plaintext: bytes) -> str:
        nonce = secrets.token_bytes(12)
        if HAS_CRYPTOGRAPHY and AESGCM is not None:
            ct = AESGCM(key).encrypt(nonce, plaintext, None)
            payload = {"alg": "AES-256-GCM", "iv": base64.b64encode(nonce).decode(), "ct": base64.b64encode(ct).decode()}
        else:
            enc_key = hashlib.sha256(key + b"enc").digest()
            mac_key = hashlib.sha256(key + b"mac").digest()
            ct = cls._xor_keystream(enc_key, nonce, plaintext)
            tag = hmac.new(mac_key, nonce + ct, hashlib.sha256).digest()
            payload = {
                "alg": "CTR-HMAC-SHA256",
                "iv": base64.b64encode(nonce).decode(),
                "ct": base64.b64encode(ct).decode(),
                "tag": base64.b64encode(tag).decode(),
            }
        return json.dumps(payload, separators=(",", ":"))

    @classmethod
    def decrypt_bytes(cls, key: bytes, packed: str) -> bytes:
        payload = json.loads(packed)
        alg = payload["alg"]
        nonce = base64.b64decode(payload["iv"])
        ct = base64.b64decode(payload["ct"])

        if alg == "AES-256-GCM":
            if not HAS_CRYPTOGRAPHY or AESGCM is None:
                raise RuntimeError("The 'cryptography' package is required to decrypt AES-256-GCM vaults.")
            try:
                return AESGCM(key).decrypt(nonce, ct, None)
            except Exception as exc:
                raise ValueError("Incorrect password or corrupted vault data.") from exc
        if alg == "CTR-HMAC-SHA256":
            enc_key = hashlib.sha256(key + b"enc").digest()
            mac_key = hashlib.sha256(key + b"mac").digest()
            expected_tag = hmac.new(mac_key, nonce + ct, hashlib.sha256).digest()
            given_tag = base64.b64decode(payload["tag"])
            if not hmac.compare_digest(expected_tag, given_tag):
                raise ValueError("Incorrect password or corrupted vault data.")
            return cls._xor_keystream(enc_key, nonce, ct)
        raise ValueError(f"Unsupported encryption algorithm: {alg}")

    @classmethod
    def encrypt_json(cls, key: bytes, obj: Any) -> str:
        return cls.encrypt_bytes(key, json.dumps(obj, ensure_ascii=False).encode("utf-8"))

    @classmethod
    def decrypt_json(cls, key: bytes, packed: str) -> Any:
        return json.loads(cls.decrypt_bytes(key, packed).decode("utf-8"))


VaultCrypto = SecurityService
