"""Password storage strength analyzer."""

from __future__ import annotations

from dataclasses import dataclass

from inframetrix.engines.hash_audit.detector import HashDetector


@dataclass
class HashAssessment:
    algorithm: str
    risk_level: str  # critical, high, medium, secure
    reason: str
    recommendation: str
    is_salted: bool


class HashAnalyzer:
    """Evaluates password storage security and generates defensive recommendations."""

    @classmethod
    def assess_hash(cls, hash_str: str) -> HashAssessment:
        algo = HashDetector.detect_algorithm(hash_str)

        if algo == "MD5 / NTLM":
            return HashAssessment(
                algorithm=algo,
                risk_level="critical",
                reason="Fast unsalted 32-character hash. Vulnerable to instant rainbow table and GPU brute-force attacks.",
                recommendation="Migrate password storage to Argon2id, scrypt, or bcrypt with appropriate cost factors.",
                is_salted=False,
            )
        if algo == "SHA-1":
            return HashAssessment(
                algorithm=algo,
                risk_level="critical",
                reason="Cryptographically broken SHA-1 without salt or key stretching.",
                recommendation="Use Argon2id (RFC 9106) with memory cost >= 64MB or bcrypt cost >= 12.",
                is_salted=False,
            )
        if algo in ("SHA-256", "SHA-512"):
            return HashAssessment(
                algorithm=algo,
                risk_level="high",
                reason=f"Unsalted general-purpose {algo}. Not designed for password storage (high GPU throughput).",
                recommendation="Replace general-purpose hashes with memory-hard password hashing (Argon2id / PBKDF2).",
                is_salted=False,
            )
        if algo == "MD5 crypt":
            return HashAssessment(
                algorithm=algo,
                risk_level="high",
                reason="Legacy MD5-crypt with insufficient iterations for modern GPU clusters.",
                recommendation="Upgrade legacy crypt schemes to Argon2id.",
                is_salted=True,
            )
        if algo in ("bcrypt", "Argon2", "scrypt", "PBKDF2"):
            return HashAssessment(
                algorithm=algo,
                risk_level="secure",
                reason=f"Modern salted password hashing scheme ({algo}) with key stretching / memory hardness.",
                recommendation="Ensure work factor parameters are regularly reviewed to resist hardware advances.",
                is_salted=True,
            )

        return HashAssessment(
            algorithm="Unknown",
            risk_level="medium",
            reason="Unrecognized hash format. Unable to verify salt and work factor.",
            recommendation="Verify password scheme against OWASP Password Storage Cheat Sheet.",
            is_salted=False,
        )
