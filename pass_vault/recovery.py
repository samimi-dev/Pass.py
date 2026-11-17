# -*- coding: utf-8 -*-
"""Email-only password recovery with Google Gmail SMTP OTP & zero-knowledge Recovery Key."""

import base64
from email.message import EmailMessage
import hashlib
import hmac
import re
import secrets
import smtplib
import ssl


class RecoveryEmailService:
    """Zero-knowledge Email recovery + Google Gmail SMTP 6-digit OTP + brute-force lockout."""

    GOOGLE_SMTP_HOST = "smtp.gmail.com"
    GOOGLE_SMTP_PORT = 587
    RECOVERY_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
    MAX_FREE_ATTEMPTS = 5
    MAX_LOCKOUT_SECONDS = 900

    @staticmethod
    def normalize_email(email: str) -> str:
        email_val = (email or "").strip().lower()
        if not email_val:
            raise ValueError("Recovery Email address is required.")
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email_val):
            raise ValueError("Please enter a valid Email address (e.g. name@gmail.com).")
        return email_val

    @classmethod
    def mask_email(cls, normalized_email: str) -> str:
        local, dom = normalized_email.split("@", 1)
        head = local[:2] if len(local) > 2 else local[:1]
        return f"{head}***@{dom}"

    @classmethod
    def generate_recovery_key(cls) -> str:
        groups = ["".join(secrets.choice(cls.RECOVERY_ALPHABET) for _ in range(4)) for _ in range(4)]
        return "-".join(groups)

    @staticmethod
    def normalize_recovery_key(key: str) -> str:
        cleaned = re.sub(r"[^A-Za-z0-9]", "", key).upper()
        if len(cleaned) != 16:
            raise ValueError("Recovery key must contain 16 alphanumeric characters (XXXX-XXXX-XXXX-XXXX).")
        return cleaned

    @classmethod
    def compute_lockout_seconds(cls, failed_attempts: int) -> int:
        if failed_attempts < cls.MAX_FREE_ATTEMPTS:
            return 0
        return min(cls.MAX_LOCKOUT_SECONDS, 30 * (2 ** (failed_attempts - cls.MAX_FREE_ATTEMPTS)))

    @staticmethod
    def generate_otp() -> str:
        return f"{secrets.randbelow(1_000_000):06d}"

    @staticmethod
    def hash_otp(otp: str, salt: bytes) -> str:
        return base64.b64encode(
            hashlib.pbkdf2_hmac("sha256", otp.strip().encode("utf-8"), salt, 50_000, dklen=32)
        ).decode("ascii")

    @classmethod
    def verify_otp(cls, otp: str, salt: bytes, expected_hash_b64: str) -> bool:
        if not otp or not expected_hash_b64:
            return False
        return hmac.compare_digest(cls.hash_otp(otp, salt), expected_hash_b64)

    @classmethod
    def send_otp_email(
        cls,
        sender_email: str,
        app_password: str,
        recipient_email: str,
        otp_code: str,
        smtp_host: str = GOOGLE_SMTP_HOST,
        smtp_port: int = GOOGLE_SMTP_PORT,
        use_ssl: bool = False,
    ) -> None:
        if not sender_email or not app_password or not recipient_email:
            raise ValueError("Sender Gmail, Google App Password, and Recipient Email are required.")
        if any(ch in app_password for ch in ("\r", "\n")):
            raise ValueError("Google App Password contains invalid characters.")
        sender_clean = cls.normalize_email(sender_email)
        recipient_clean = cls.normalize_email(recipient_email)
        msg = EmailMessage()
        msg["Subject"] = "Pass.py Password Recovery Code"
        msg["From"] = sender_clean
        msg["To"] = recipient_clean
        msg.set_content(
            f"Your Pass.py verification code is: {otp_code}\n\n"
            "This code expires in 5 minutes. If you did not request a password reset, ignore this email."
        )
        ctx = ssl.create_default_context()
        if use_ssl or int(smtp_port) == 465:
            with smtplib.SMTP_SSL(smtp_host, int(smtp_port), timeout=12, context=ctx) as server:
                server.login(sender_email, app_password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(smtp_host, int(smtp_port), timeout=12) as server:
                server.ehlo()
                server.starttls(context=ctx)
                server.ehlo()
                server.login(sender_email, app_password)
                server.send_message(msg)
