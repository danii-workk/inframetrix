"""Password hash algorithm detector."""

from __future__ import annotations

import re


class HashDetector:
    """Identifies cryptographic hash algorithms and password storage formats."""

    @classmethod
    def detect_algorithm(cls, hash_str: str) -> str:
        """Identify hash type based on format, length, and signature prefix."""
        h = hash_str.strip()

        # Modern salted password hashes
        if h.startswith(("$2a$", "$2b$", "$2y$", "$2x$")):
            return "bcrypt"
        if h.startswith(("$argon2i$", "$argon2d$", "$argon2id$")):
            return "Argon2"
        if h.startswith("$s0$"):
            return "scrypt"
        if h.startswith(("$pbkdf2$", "$pbkdf2-sha256$", "$pbkdf2-sha512$")):
            return "PBKDF2"
        if h.startswith("$6$"):
            return "SHA-512 crypt"
        if h.startswith("$5$"):
            return "SHA-256 crypt"
        if h.startswith("$1$"):
            return "MD5 crypt"

        # Raw unsalted hex hashes
        if re.fullmatch(r"[0-9a-fA-F]{32}", h):
            return "MD5 / NTLM"
        if re.fullmatch(r"[0-9a-fA-F]{40}", h):
            return "SHA-1"
        if re.fullmatch(r"[0-9a-fA-F]{64}", h):
            return "SHA-256"
        if re.fullmatch(r"[0-9a-fA-F]{128}", h):
            return "SHA-512"

        return "Unknown"
