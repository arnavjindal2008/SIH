import pytest
from backend.app.core.packet_parser import ParsedEmailSession
from backend.app.core.crypto_rules import CryptographicRulesEngine

def test_plaintext_auth_rule():
    session = ParsedEmailSession(
        session_id="sess_test_plain",
        src_ip="192.168.1.50",
        src_port=49152,
        dst_ip="10.0.0.25",
        dst_port=25,
        protocol="SMTP",
        is_encrypted=False,
        has_auth_plain=True,
        plaintext_commands=["AUTH PLAIN AGVtcGxveWVlADEyMzQ1Ng=="],
    )
    findings = CryptographicRulesEngine.evaluate_session(session, "an_test", {})
    categories = [f["category"] for f in findings]
    assert "PLAINTEXT_CREDENTIALS" in categories
    assert "UNENCRYPTED_TRAFFIC" in categories

def test_rfc8996_deprecated_tls_rule():
    session = ParsedEmailSession(
        session_id="sess_test_tls10",
        src_ip="192.168.1.51",
        src_port=51234,
        dst_ip="10.0.0.25",
        dst_port=465,
        protocol="SMTPS",
        is_encrypted=True,
        tls_version="TLS 1.0",
        cipher_suite="TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        forward_secrecy=False,
    )
    findings = CryptographicRulesEngine.evaluate_session(session, "an_test", {})
    categories = [f["category"] for f in findings]
    assert "DEPRECATED_TLS_VERSION" in categories
    assert "WEAK_CIPHER_SUITE" in categories
    assert "NO_FORWARD_SECRECY" in categories

def test_score_calculation():
    # 0 findings, 1 encrypted session -> 100.0
    score = CryptographicRulesEngine.calculate_security_score([], 1, 1)
    assert score == 100.0

    # Critical finding deduction
    findings = [{"severity": "CRITICAL"}]
    score_crit = CryptographicRulesEngine.calculate_security_score(findings, 1, 1)
    assert score_crit < 100.0
