# -*- coding: utf-8 -*-
"""Character-based random password generator and strength evaluator."""

import secrets
from typing import List, Tuple


class PasswordGeneratorService:
    """Generates random passwords by character count (default 8) and scores strength."""

    @staticmethod
    def generate(
        length: int = 8,
        lowercase: bool = True,
        uppercase: bool = True,
        numbers: bool = True,
        symbols: bool = True,
    ) -> str:
        target_len = max(4, min(64, int(length)))
        pools: List[str] = []
        if lowercase:
            pools.append("abcdefghijkmnopqrstuvwxyz")
        if uppercase:
            pools.append("ABCDEFGHJKLMNPQRSTUVWXYZ")
        if numbers:
            pools.append("23456789")
        if symbols:
            pools.append("!@#$%^&*-_=+?")
        if not pools:
            pools = ["abcdefghijkmnopqrstuvwxyz"]

        all_chars = "".join(pools)
        chars: List[str] = [secrets.choice(p) for p in pools[:target_len]]
        while len(chars) < target_len:
            chars.append(secrets.choice(all_chars))
        secrets.SystemRandom().shuffle(chars)
        return "".join(chars)

    @staticmethod
    def evaluate_strength(pw: str) -> Tuple[str, str, int]:
        if not pw:
            return ("Empty", "#64748B", 0)
        score = (len(pw) >= 8) + (len(pw) >= 12) + (len(pw) >= 16)
        score += (
            any(c.islower() for c in pw)
            + any(c.isupper() for c in pw)
            + any(c.isdigit() for c in pw)
            + any(not c.isalnum() for c in pw)
        )
        if score <= 2:
            return ("Weak", "#DC2626", 1)
        if score <= 4:
            return ("Medium", "#EA580C", 2)
        if score <= 5:
            return ("Strong", "#10B981", 3)
        return ("Very Strong", "#047857", 4)
