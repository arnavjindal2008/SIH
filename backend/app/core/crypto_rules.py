"""
Deterministic Cryptographic Security Rules and Score Engine.
Evaluates passive network capture data against RFCs (RFC 8314, RFC 8996, RFC 7525, RFC 5280)
and NIST SP 800-52r2 standards. Generates evidence-backed security findings and computes
transparent 0-100 security posture scores across multiple categories.
"""
from __future__ import annotations
import uuid
from typing import Optional, List, Dict, Any
from backend.app.core.packet_parser import ParsedEmailSession
from backend.app.core.cert_inspector import InspectedCertificate

class CryptographicRulesEngine:
    """Evaluates cryptographic compliance against RFCs and NIST standards."""

    @staticmethod
    def evaluate_session(
        session: ParsedEmailSession,
        analysis_id: str,
        cert_map: dict[str, list[InspectedCertificate]],
    ) -> list[dict]:
        findings: list[dict] = []
        stream_desc = f"TCP stream {session.tcp_stream_id} ({session.src_ip}:{session.src_port} -> {session.dst_ip}:{session.dst_port})"

        # Rule 1: Plaintext Email Credentials Transmission (RFC 8314 / RFC 4954)
        if session.has_auth_plain and not session.is_encrypted:
            cmd_snippet = ", ".join(session.plaintext_commands[:3]) if session.plaintext_commands else "AUTH PLAIN/LOGIN"
            evidence_str = f"Observed unencrypted credentials ({cmd_snippet}) in {stream_desc}."
            findings.append({
                "id": f"find_{uuid.uuid4().hex[:12]}",
                "finding_id": f"find_{uuid.uuid4().hex[:12]}",
                "analysis_id": analysis_id,
                "session_id": session.session_id,
                "certificate_id": None,
                "severity": "Critical",
                "category": "PLAINTEXT_CREDENTIALS",
                "title": f"Cleartext Authentication Credentials Over {session.protocol}",
                "description": (
                    f"Authentication commands were transmitted over an unencrypted channel in {stream_desc}. "
                    f"Plaintext credentials can be passively captured by any adversary on the network path."
                ),
                "evidence": evidence_str,
                "technical_details": (
                    f"Protocol: {session.protocol}, Destination Port: {session.dst_port}. "
                    f"Detected unencrypted commands: {cmd_snippet}"
                ),
                "affected_component": f"{session.protocol} Stream ({session.src_ip} -> {session.dst_ip}:{session.dst_port})",
                "rfc_reference": "RFC 8314 Section 3 / RFC 4954",
                "recommendation": (
                    "Mandate TLS 1.3/1.2 before accepting AUTH commands. Reject plaintext authentication "
                    "or enforce SMTPS/IMAPS/POP3S on dedicated TLS ports (465, 993, 995)."
                ),
                "remediation": (
                    "Mandate TLS 1.3/1.2 before accepting AUTH commands. Reject plaintext authentication "
                    "or enforce SMTPS/IMAPS/POP3S on dedicated TLS ports (465, 993, 995)."
                ),
                "cve_reference": "CWE-319: Cleartext Transmission of Sensitive Information",
            })

        # Rule 2: Unencrypted Email Communication (No TLS / No STARTTLS)
        if not session.is_encrypted and session.protocol in {"SMTP", "IMAP", "POP3", "SMTPS", "IMAPS", "POP3S"}:
            evidence_str = f"Observed unencrypted {session.protocol} transmission in {stream_desc} without TLS protection."
            findings.append({
                "id": f"find_{uuid.uuid4().hex[:12]}",
                "finding_id": f"find_{uuid.uuid4().hex[:12]}",
                "analysis_id": analysis_id,
                "session_id": session.session_id,
                "certificate_id": None,
                "severity": "High",
                "category": "UNENCRYPTED_TRAFFIC",
                "title": f"Unencrypted {session.protocol} Session",
                "description": (
                    f"Session in {stream_desc} did not establish cryptographic channel protection (no TLS negotiation)."
                ),
                "evidence": evidence_str,
                "technical_details": (
                    f"STARTTLS requested: {session.starttls_requested}, STARTTLS accepted: {session.starttls_accepted}. "
                    f"Traffic payloads were transmitted in cleartext."
                ),
                "affected_component": f"{session.protocol} Client-Server link",
                "rfc_reference": "RFC 8314 / RFC 3207",
                "recommendation": (
                    "Enable and enforce STARTTLS or transition to implicit TLS endpoints. "
                    "Deploy MTA-STS (RFC 8461) to prevent STARTTLS stripping attacks."
                ),
                "remediation": (
                    "Enable and enforce STARTTLS or transition to implicit TLS endpoints. "
                    "Deploy MTA-STS (RFC 8461) to prevent STARTTLS stripping attacks."
                ),
                "cve_reference": "CWE-311: Missing Encryption of Sensitive Data",
            })

        # Rule 3: Deprecated TLS Protocol Version (RFC 8996)
        if session.tls_version in {"SSL 3.0", "TLS 1.0", "TLS 1.1"}:
            severity = "Critical" if session.tls_version in {"SSL 3.0", "TLS 1.0"} else "High"
            evidence_str = f"Observed {session.tls_version} in {stream_desc} (Cipher: {session.cipher_suite or 'Unknown'})."
            findings.append({
                "id": f"find_{uuid.uuid4().hex[:12]}",
                "finding_id": f"find_{uuid.uuid4().hex[:12]}",
                "analysis_id": analysis_id,
                "session_id": session.session_id,
                "certificate_id": None,
                "severity": severity,
                "category": "DEPRECATED_TLS_VERSION",
                "title": f"Obsolete Protocol Version Negotiated: {session.tls_version}",
                "description": (
                    f"The session negotiated {session.tls_version}, formally prohibited by RFC 8996 "
                    f"due to cryptographic vulnerabilities (BEAST, POODLE, Lucky 13)."
                ),
                "evidence": evidence_str,
                "technical_details": (
                    f"Negotiated version: {session.tls_version}, Cipher Suite: {session.cipher_suite or 'Unknown'}, "
                    f"Session: {session.src_ip}:{session.src_port} <-> {session.dst_ip}:{session.dst_port}"
                ),
                "affected_component": f"TLS Handshake ({session.tls_version})",
                "rfc_reference": "RFC 8996: Deprecating TLS 1.0 and TLS 1.1",
                "recommendation": (
                    "Disable TLS 1.0 and TLS 1.1 on mail transfer agents and clients. "
                    "Enforce TLS 1.2 as the minimum baseline and TLS 1.3 as preferred."
                ),
                "remediation": (
                    "Disable TLS 1.0 and TLS 1.1 on mail transfer agents and clients. "
                    "Enforce TLS 1.2 as the minimum baseline and TLS 1.3 as preferred."
                ),
                "cve_reference": "CVE-2011-3389, CVE-2014-3566",
            })

        # Rule 4: Weak or Deprecated Cipher Suite (RFC 7465 / RFC 7525)
        if session.cipher_suite and session.cipher_suite != "Not observed":
            upper_cipher = session.cipher_suite.upper()
            if any(w in upper_cipher for w in ["RC4", "3DES", "NULL", "DES", "MD5", "EXPORT"]):
                evidence_str = f"Observed weak cipher suite '{session.cipher_suite}' in {stream_desc}."
                findings.append({
                    "id": f"find_{uuid.uuid4().hex[:12]}",
                    "finding_id": f"find_{uuid.uuid4().hex[:12]}",
                    "analysis_id": analysis_id,
                    "session_id": session.session_id,
                    "certificate_id": None,
                    "severity": "High",
                    "category": "WEAK_CIPHER_SUITE",
                    "title": f"Vulnerable Cipher Suite In Use: {session.cipher_suite}",
                    "description": (
                        f"The TLS handshake negotiated cipher suite '{session.cipher_suite}', which relies "
                        f"on legacy algorithms vulnerable to Sweet32, Bar Mitzvah, or collision attacks."
                    ),
                    "evidence": evidence_str,
                    "technical_details": (
                        f"Cipher suite code: {session.cipher_suite_code or 'N/A'}. "
                        f"Algorithm: {session.cipher_suite}"
                    ),
                    "affected_component": f"TLS Cipher Negotiation ({session.cipher_suite})",
                    "rfc_reference": "RFC 7465 (Prohibiting RC4) / RFC 7525",
                    "recommendation": (
                        "Remove RC4, 3DES, and DES from MTA cipher suites. "
                        "Configure modern AEAD ciphers: AES-GCM and ChaCha20-Poly1305."
                    ),
                    "remediation": (
                        "Remove RC4, 3DES, and DES from MTA cipher suites. "
                        "Configure modern AEAD ciphers: AES-GCM and ChaCha20-Poly1305."
                    ),
                    "cve_reference": "CVE-2016-2183 (Sweet32), CVE-2015-2808 (Bar Mitzvah)",
                })

        # Rule 5: Lack of Perfect Forward Secrecy (PFS) (NIST SP 800-52r2)
        if session.is_encrypted and not session.forward_secrecy and session.tls_version not in {"TLS 1.3"}:
            evidence_str = f"Observed static key exchange ({session.key_exchange or 'RSA'}) without Forward Secrecy in {stream_desc}."
            findings.append({
                "id": f"find_{uuid.uuid4().hex[:12]}",
                "finding_id": f"find_{uuid.uuid4().hex[:12]}",
                "analysis_id": analysis_id,
                "session_id": session.session_id,
                "certificate_id": None,
                "severity": "Medium",
                "category": "NO_FORWARD_SECRECY",
                "title": "Absence of Ephemeral Key Exchange (No Forward Secrecy)",
                "description": (
                    f"The session used static key exchange ({session.key_exchange or 'RSA'}), meaning that "
                    f"intercepted traffic can be decrypted retroactively if the server private key is compromised."
                ),
                "evidence": evidence_str,
                "technical_details": (
                    f"Cipher Suite: {session.cipher_suite}. Key Exchange: {session.key_exchange}."
                ),
                "affected_component": "Key Exchange Mechanism",
                "rfc_reference": "NIST SP 800-52r2 / RFC 7525 Section 4.2",
                "recommendation": (
                    "Enforce Ephemeral Diffie-Hellman (ECDHE / DHE) key exchange algorithms to guarantee "
                    "Perfect Forward Secrecy for all encrypted mail sessions."
                ),
                "remediation": (
                    "Enforce Ephemeral Diffie-Hellman (ECDHE / DHE) key exchange algorithms to guarantee "
                    "Perfect Forward Secrecy for all encrypted mail sessions."
                ),
                "cve_reference": None,
            })

        # Rule 6: STARTTLS Advertised but Plaintext Traffic (Opportunistic Downgrade / Stripping Suspect)
        if getattr(session, "starttls_supported", False) and not session.is_encrypted:
            evidence_str = f"Server advertised STARTTLS capability in {stream_desc}, but client transmitted in cleartext."
            findings.append({
                "id": f"find_{uuid.uuid4().hex[:12]}",
                "finding_id": f"find_{uuid.uuid4().hex[:12]}",
                "analysis_id": analysis_id,
                "session_id": session.session_id,
                "certificate_id": None,
                "severity": "High",
                "category": "STARTTLS_STRIPPING_SUSPECT",
                "title": "STARTTLS Capability Advertised but Traffic Sent in Cleartext",
                "description": (
                    f"The server advertised STARTTLS support, but the client did not negotiate an encrypted tunnel. "
                    f"This pattern indicates either misconfigured clients or an active STARTTLS stripping attack."
                ),
                "evidence": evidence_str,
                "technical_details": (
                    f"Protocol: {session.protocol}, STARTTLS Advertised: True, TLS Upgraded: False."
                ),
                "affected_component": f"{session.protocol} Negotiation",
                "rfc_reference": "RFC 8314 / RFC 8461 (MTA-STS)",
                "recommendation": (
                    "Mandate TLS for outgoing connections and deploy MTA-STS / DANE (RFC 7672) "
                    "to enforce cryptographic transport and prevent network-level stripping."
                ),
                "remediation": (
                    "Mandate TLS for outgoing connections and deploy MTA-STS / DANE (RFC 7672) "
                    "to enforce cryptographic transport and prevent network-level stripping."
                ),
                "cve_reference": None,
            })

        # Rule 7: Failed Handshake or TLS Alerts Observed
        tls_alerts = getattr(session, "tls_alerts", [])
        if tls_alerts:
            alerts_summary = ", ".join(tls_alerts)
            evidence_str = f"Observed TLS alert records [{alerts_summary}] in {stream_desc}."
            findings.append({
                "id": f"find_{uuid.uuid4().hex[:12]}",
                "finding_id": f"find_{uuid.uuid4().hex[:12]}",
                "analysis_id": analysis_id,
                "session_id": session.session_id,
                "certificate_id": None,
                "severity": "High" if any("fatal" in a.lower() for a in tls_alerts) else "Medium",
                "category": "TLS_ALERT_FAILURE",
                "title": f"TLS Handshake Alert Encountered: {tls_alerts[0]}",
                "description": (
                    f"A TLS alert was observed during the handshake in {stream_desc}. "
                    f"Handshake was terminated due to cryptographic incompatibility or invalid certificate."
                ),
                "evidence": evidence_str,
                "technical_details": f"Alerts: {alerts_summary}",
                "affected_component": "TLS Handshake Layer",
                "rfc_reference": "RFC 8446 Section 6 / RFC 5246 Section 7.2",
                "recommendation": (
                    "Investigate certificate validity, cipher suite alignment, and client/server compatibility."
                ),
                "remediation": (
                    "Investigate certificate validity, cipher suite alignment, and client/server compatibility."
                ),
                "cve_reference": None,
            })

        # Rule 8: Incomplete Handshake
        handshake_status = getattr(session, "handshake_status", "Completed")
        if handshake_status and "incomplete" in handshake_status.lower():
            evidence_str = f"Observed incomplete TLS handshake ({handshake_status}) in {stream_desc}."
            findings.append({
                "id": f"find_{uuid.uuid4().hex[:12]}",
                "finding_id": f"find_{uuid.uuid4().hex[:12]}",
                "analysis_id": analysis_id,
                "session_id": session.session_id,
                "certificate_id": None,
                "severity": "Low",
                "category": "INCOMPLETE_HANDSHAKE",
                "title": f"Incomplete TLS Handshake Observed ({handshake_status})",
                "description": (
                    f"The TLS handshake in {stream_desc} did not complete successfully. "
                    f"Traffic terminated before finished frames or application data were transmitted."
                ),
                "evidence": evidence_str,
                "technical_details": f"Handshake Status: {handshake_status}",
                "affected_component": "TLS Handshake Reassembly",
                "rfc_reference": "RFC 8446 / RFC 5246",
                "recommendation": "Review network connectivity and check for premature TCP resets or packet loss.",
                "remediation": "Review network connectivity and check for premature TCP resets or packet loss.",
                "cve_reference": None,
            })

        # Rules 9–12: Certificate Trust and Validity Rules
        if session.session_id in cert_map:
            for cert in cert_map[session.session_id]:
                cert_id = getattr(cert, "id", None)

                if cert.is_expired:
                    exp_date = cert.valid_to.strftime('%Y-%m-%d') if cert.valid_to else 'unknown date'
                    evidence_str = f"Certificate observed in capture for '{cert.subject_cn or 'server'}' expired on {exp_date} (SHA-256: {cert.fingerprint_sha256[:20]}...)."
                    findings.append({
                        "id": f"find_{uuid.uuid4().hex[:12]}",
                        "finding_id": f"find_{uuid.uuid4().hex[:12]}",
                        "analysis_id": analysis_id,
                        "session_id": session.session_id,
                        "certificate_id": cert_id,
                        "severity": "High",
                        "category": "EXPIRED_CERTIFICATE",
                        "title": f"Expired Certificate Observed in Capture ({cert.subject_cn or 'Unknown CN'})",
                        "description": (
                            f"The X.509 certificate presented by the server expired on {exp_date}. "
                            f"Expired certificates cannot establish cryptographic identity assurance."
                        ),
                        "evidence": evidence_str,
                        "technical_details": (
                            f"Certificate SHA-256: {cert.fingerprint_sha256}. "
                            f"Issuer: {cert.issuer_cn or 'Unknown'}. Days remaining: {cert.days_remaining}."
                        ),
                        "affected_component": f"X.509 Certificate ({cert.subject_cn})",
                        "rfc_reference": "RFC 5280 Section 4.1.2.5",
                        "recommendation": "Renew and re-deploy a valid X.509 certificate from a trusted public or enterprise CA.",
                        "remediation": "Renew and re-deploy a valid X.509 certificate from a trusted public or enterprise CA.",
                        "cve_reference": "CWE-298: Improper Validation of Certificate Expiration",
                    })

                if cert.is_self_signed:
                    evidence_str = f"Self-signed certificate observed in capture (Subject CN: '{cert.subject_cn}' matches Issuer CN: '{cert.issuer_cn}')."
                    findings.append({
                        "id": f"find_{uuid.uuid4().hex[:12]}",
                        "finding_id": f"find_{uuid.uuid4().hex[:12]}",
                        "analysis_id": analysis_id,
                        "session_id": session.session_id,
                        "certificate_id": cert_id,
                        "severity": "High",
                        "category": "SELF_SIGNED_CERTIFICATE",
                        "title": f"Self-Signed Certificate Observed in Capture ({cert.subject_cn or 'Unknown CN'})",
                        "description": (
                            f"The certificate observed in {stream_desc} was issued and signed by itself. "
                            f"Self-signed certificates lack third-party root anchor validation."
                        ),
                        "evidence": evidence_str,
                        "technical_details": f"Subject DN: {cert.subject_dn}, Issuer DN: {cert.issuer_dn}",
                        "affected_component": f"X.509 Certificate ({cert.subject_cn})",
                        "rfc_reference": "RFC 5280 / RFC 8314 Section 3.3",
                        "recommendation": "Replace self-signed certificates with certificates issued by a recognized CA.",
                        "remediation": "Replace self-signed certificates with certificates issued by a recognized CA.",
                        "cve_reference": "CWE-295: Improper Certificate Validation",
                    })

                if cert.key_algorithm == "RSA" and cert.key_size and cert.key_size < 2048:
                    evidence_str = f"Observed RSA key size of {cert.key_size} bits in certificate for '{cert.subject_cn}' (minimum required is 2048 bits)."
                    findings.append({
                        "id": f"find_{uuid.uuid4().hex[:12]}",
                        "finding_id": f"find_{uuid.uuid4().hex[:12]}",
                        "analysis_id": analysis_id,
                        "session_id": session.session_id,
                        "certificate_id": cert_id,
                        "severity": "High",
                        "category": "WEAK_PUBLIC_KEY",
                        "title": f"Inadequate Public Key Length ({cert.key_size} bits)",
                        "description": (
                            f"The server certificate observed in {stream_desc} uses an RSA key size of {cert.key_size} bits. "
                            f"NIST SP 800-52r2 requires at least 2048 bits for RSA."
                        ),
                        "evidence": evidence_str,
                        "technical_details": f"Algorithm: {cert.key_algorithm}, Bit size: {cert.key_size}",
                        "affected_component": "Public Key Cryptosystem",
                        "rfc_reference": "NIST SP 800-52r2 Section 3.1 / RFC 7525",
                        "recommendation": "Re-issue certificate with at least 2048-bit RSA (or 256-bit ECDSA / secp256r1).",
                        "remediation": "Re-issue certificate with at least 2048-bit RSA (or 256-bit ECDSA / secp256r1).",
                        "cve_reference": "CWE-326: Inadequate Encryption Strength",
                    })

                if cert.signature_algorithm and any(h in cert.signature_algorithm.lower() for h in ["sha1", "md5"]):
                    evidence_str = f"Observed weak signature algorithm '{cert.signature_algorithm}' in certificate for '{cert.subject_cn}'."
                    findings.append({
                        "id": f"find_{uuid.uuid4().hex[:12]}",
                        "finding_id": f"find_{uuid.uuid4().hex[:12]}",
                        "analysis_id": analysis_id,
                        "session_id": session.session_id,
                        "certificate_id": cert_id,
                        "severity": "High",
                        "category": "BROKEN_SIGNATURE_ALGORITHM",
                        "title": f"Weak Signature Algorithm: {cert.signature_algorithm}",
                        "description": (
                            f"The certificate signature algorithm '{cert.signature_algorithm}' relies on "
                            f"collision-vulnerable hash functions (SHA-1/MD5), prohibited by modern standards."
                        ),
                        "evidence": evidence_str,
                        "technical_details": f"Signature Algorithm OID: {cert.signature_algorithm}",
                        "affected_component": "X.509 Digital Signature",
                        "rfc_reference": "RFC 6151 / RFC 9155",
                        "recommendation": "Re-issue certificate using SHA-256 (e.g. sha256WithRSAEncryption) or modern ECDSA.",
                        "remediation": "Re-issue certificate using SHA-256 (e.g. sha256WithRSAEncryption) or modern ECDSA.",
                        "cve_reference": "CWE-328: Use of Weak Hash",
                    })

        return findings

    @staticmethod
    def calculate_detailed_security_scores(
        findings: list[dict],
        total_sessions: int,
        encrypted_sessions: int,
        sessions: list[ParsedEmailSession],
    ) -> dict[str, Any]:
        """
        Computes a transparent 0-100 overall score and granular sub-scores:
        tls_score, certificate_score, cipher_score, protocol_score, starttls_score.
        Applies deduplicated penalties to avoid double-counting.
        """
        if total_sessions == 0:
            return {
                "overall_score": 100.0,
                "tls_score": 100.0,
                "certificate_score": 100.0,
                "cipher_score": 100.0,
                "protocol_score": 100.0,
                "starttls_score": 100.0,
                "score_label": "Excellent",
                "score_confidence_note": "Score confidence high: complete forensic capture.",
            }

        # Sub-score baselines
        tls_score = 100.0
        cert_score = 100.0
        cipher_score = 100.0
        proto_score = 100.0
        starttls_score = 100.0

        # Group findings by category and session to avoid double counting
        cat_dedup: dict[str, set[str]] = {}
        for f in findings:
            cat = f.get("category", "GENERAL")
            sess = f.get("session_id", "none")
            cat_dedup.setdefault(cat, set()).add(sess)

        # Penalties per category
        for cat, sessions_affected in cat_dedup.items():
            count = len(sessions_affected)
            if cat == "PLAINTEXT_CREDENTIALS":
                proto_score -= min(35.0, count * 30.0)
                tls_score -= min(20.0, count * 15.0)
            elif cat == "UNENCRYPTED_TRAFFIC":
                proto_score -= min(30.0, count * 15.0)
                tls_score -= min(30.0, count * 15.0)
            elif cat == "DEPRECATED_TLS_VERSION":
                tls_score -= min(40.0, count * 25.0)
            elif cat == "WEAK_CIPHER_SUITE":
                cipher_score -= min(35.0, count * 20.0)
            elif cat == "NO_FORWARD_SECRECY":
                cipher_score -= min(20.0, count * 10.0)
            elif cat == "STARTTLS_STRIPPING_SUSPECT":
                starttls_score -= min(35.0, count * 20.0)
            elif cat in {"EXPIRED_CERTIFICATE", "SELF_SIGNED_CERTIFICATE"}:
                cert_score -= min(35.0, count * 20.0)
            elif cat in {"WEAK_PUBLIC_KEY", "BROKEN_SIGNATURE_ALGORITHM"}:
                cert_score -= min(25.0, count * 15.0)
            elif cat in {"TLS_ALERT_FAILURE", "INCOMPLETE_HANDSHAKE"}:
                tls_score -= min(15.0, count * 10.0)
            else:
                # Severity-based fallback deduction for arbitrary or unclassified findings
                for s_id in sessions_affected:
                    f_sev = next((str(f.get("severity", "INFO")).upper() for f in findings if (f.get("session_id") == s_id or s_id == "none") and f.get("category", "GENERAL") == cat), "INFO")
                    if f_sev == "CRITICAL":
                        proto_score -= 25.0
                        tls_score -= 20.0
                    elif f_sev == "HIGH":
                        tls_score -= 15.0
                    elif f_sev == "MEDIUM":
                        tls_score -= 10.0
                    elif f_sev == "LOW":
                        tls_score -= 5.0

        # Clamp sub-scores to [0, 100]
        tls_score = max(0.0, round(tls_score, 1))
        cert_score = max(0.0, round(cert_score, 1))
        cipher_score = max(0.0, round(cipher_score, 1))
        proto_score = max(0.0, round(proto_score, 1))
        starttls_score = max(0.0, round(starttls_score, 1))

        # Weighted overall score
        # TLS: 25%, Certificate: 20%, Cipher: 20%, Protocol/Auth: 20%, STARTTLS: 15%
        overall = (
            tls_score * 0.25 +
            cert_score * 0.20 +
            cipher_score * 0.20 +
            proto_score * 0.20 +
            starttls_score * 0.15
        )
        overall_score = max(0.0, min(100.0, round(overall, 1)))

        # Score label
        if overall_score >= 90.0:
            score_label = "Excellent"
        elif overall_score >= 75.0:
            score_label = "Good"
        elif overall_score >= 50.0:
            score_label = "Moderate"
        elif overall_score >= 25.0:
            score_label = "Poor"
        else:
            score_label = "Critical"

        # Check for incomplete capture or missing handshakes
        incomplete_handshakes = any(
            "incomplete" in str(getattr(s, "handshake_status", "")).lower() for s in sessions
        )
        if incomplete_handshakes:
            confidence_note = "Score confidence limited by incomplete capture."
        else:
            confidence_note = "Score confidence high: complete forensic capture."

        return {
            "overall_score": overall_score,
            "tls_score": tls_score,
            "certificate_score": cert_score,
            "cipher_score": cipher_score,
            "protocol_score": proto_score,
            "starttls_score": starttls_score,
            "score_label": score_label,
            "score_confidence_note": confidence_note,
        }

    # Backward compatibility helper
    @classmethod
    def calculate_security_score(
        cls,
        findings: list[dict],
        total_sessions: int,
        encrypted_sessions: int,
    ) -> float:
        res = cls.calculate_detailed_security_scores(findings, total_sessions, encrypted_sessions, [])
        return res["overall_score"]
