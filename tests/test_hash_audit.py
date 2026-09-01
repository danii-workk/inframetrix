"""Tests for Password Storage and Hash Audit."""

from inframetrix.engines.hash_audit.analyzer import HashAnalyzer
from inframetrix.engines.hash_audit.detector import HashDetector
from inframetrix.engines.hash_audit.local_lookup import LocalLookup


def test_hash_detector_algorithms():
    assert HashDetector.detect_algorithm("5f4dcc3b5aa765d61d8327deb882cf99") == "MD5 / NTLM"
    assert HashDetector.detect_algorithm("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12") == "SHA-1"
    assert HashDetector.detect_algorithm("$2y$12$e8vK3fP5l6K7/...") == "bcrypt"
    assert HashDetector.detect_algorithm("$argon2id$v=19$m=65536,t=3,p=4$...") == "Argon2"


def test_hash_analyzer_assessments():
    md5_eval = HashAnalyzer.assess_hash("5f4dcc3b5aa765d61d8327deb882cf99")
    assert md5_eval.risk_level == "critical"
    assert not md5_eval.is_salted

    argon2_eval = HashAnalyzer.assess_hash("$argon2id$v=19$m=65536,t=3,p=4$...")
    assert argon2_eval.risk_level == "secure"
    assert argon2_eval.is_salted


def test_local_dictionary_lookup():
    # MD5 of 'password'
    assert LocalLookup.audit_hash("5f4dcc3b5aa765d61d8327deb882cf99") == "password"
    # Random hash
    assert LocalLookup.audit_hash("00000000000000000000000000000000") is None
