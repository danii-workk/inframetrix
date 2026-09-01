"""Local dictionary audit for common weak passwords without external network calls."""

from __future__ import annotations

import hashlib

# High-frequency dictionary passwords
COMMON_PASSWORDS = [
    "password", "123456", "12345678", "123456789", "qwerty", "12345",
    "dragon", "pussy", "baseball", "football", "letmein", "monkey",
    "shadow", "master", "sunshine", "princess", "superman", "welcome",
    "password123", "admin", "root", "toor", "pass", "test", "guest",
]


class LocalLookup:
    """Performs fast offline dictionary lookup against common weak passwords."""

    @classmethod
    def audit_hash(cls, hash_str: str) -> str | None:
        """Return cleartext match if hash matches a top common password."""
        h = hash_str.strip().lower()

        for pwd in COMMON_PASSWORDS:
            # MD5
            if hashlib.md5(pwd.encode("utf-8")).hexdigest().lower() == h:
                return pwd
            # SHA1
            if hashlib.sha1(pwd.encode("utf-8")).hexdigest().lower() == h:
                return pwd
            # SHA256
            if hashlib.sha256(pwd.encode("utf-8")).hexdigest().lower() == h:
                return pwd

        return None
