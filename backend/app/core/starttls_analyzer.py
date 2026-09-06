"""
STARTTLS / STLS Upgrade Analysis Engine.
Passively evaluates command and response exchanges in SMTP, IMAP, and POP3 streams
to determine whether STARTTLS was advertised, requested, negotiated, or downgraded,
and verifies if TLS handshake frames follow the upgrade.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Optional, List

@dataclass
class StarttlsAnalysisResult:
    encryption_mode: str  # "IMPLICIT_TLS", "STARTTLS_UPGRADE", "FAILED_UPGRADE", "PLAINTEXT", "UNKNOWN"
    starttls_supported: bool = False
    starttls_requested: bool = False
    tls_upgrade_detected: bool = False
    tls_handshake_detected: bool = False
    starttls_evidence: list[str] = field(default_factory=list)
    details: str = ""

# Regex patterns for capability and commands
RE_SMTP_EHLO = re.compile(r"^(?:EHLO|HELO)\b", re.IGNORECASE)
RE_SMTP_STARTTLS_ADV = re.compile(r"^250[ -].*STARTTLS\b", re.IGNORECASE)
RE_SMTP_STARTTLS_CMD = re.compile(r"^STARTTLS\b", re.IGNORECASE)
RE_SMTP_STARTTLS_OK = re.compile(r"^220[ -].*(?:ready|start|tls|go ahead)", re.IGNORECASE)

RE_IMAP_CAPA_ADV = re.compile(r"^\* CAPABILITY\b.*STARTTLS\b", re.IGNORECASE)
RE_IMAP_STARTTLS_CMD = re.compile(r"^(?:[a-zA-Z0-9_\.]+\s+)?STARTTLS\b", re.IGNORECASE)
RE_IMAP_STARTTLS_OK = re.compile(r"^(?:[a-zA-Z0-9_\.]+\s+)?OK\b.*(?:begin|start|tls)", re.IGNORECASE)

RE_POP3_CAPA_ADV = re.compile(r"^STLS\b", re.IGNORECASE)
RE_POP3_STLS_CMD = re.compile(r"^STLS\b", re.IGNORECASE)
RE_POP3_STLS_OK = re.compile(r"^\+OK\b.*(?:begin|start|tls)", re.IGNORECASE)


class StarttlsAnalyzer:
    """
    Forensic passive analyzer for STARTTLS (SMTP/IMAP) and STLS (POP3).
    Evaluates actual evidence from payload lines and TLS record presence.
    """

    @classmethod
    def analyze_stream(
        cls,
        protocol: str,
        payload_lines: list[str],
        has_tls_records: bool,
        first_payload_is_tls: bool,
        src_port: int,
        dst_port: int,
    ) -> StarttlsAnalysisResult:
        ports = {src_port, dst_port}
        proto_upper = protocol.upper()
        evidence: list[str] = []

        # 1. Check for Implicit TLS (Direct TLS from connection start)
        if first_payload_is_tls or (has_tls_records and not payload_lines):
            mode = "IMPLICIT_TLS"
            evidence.append("Direct TLS connection initiated without plaintext command negotiation (Implicit TLS)")
            if 465 in ports:
                evidence.append("Negotiated on dedicated SMTPS port 465 (RFC 8314)")
            elif 993 in ports:
                evidence.append("Negotiated on dedicated IMAPS port 993 (RFC 8314)")
            elif 995 in ports:
                evidence.append("Negotiated on dedicated POP3S port 995 (RFC 8314)")

            return StarttlsAnalysisResult(
                encryption_mode="IMPLICIT_TLS",
                starttls_supported=False,
                starttls_requested=False,
                tls_upgrade_detected=False,
                tls_handshake_detected=True,
                starttls_evidence=evidence,
                details="Session established using direct implicit TLS encryption."
            )

        starttls_supported = False
        starttls_requested = False
        tls_upgrade_detected = False

        # 2. Protocol-Specific Plaintext Banner & Command Inspection
        if proto_upper.startswith("SMTP"):
            for line in payload_lines:
                if RE_SMTP_EHLO.search(line):
                    evidence.append(f"Client greeting: '{line[:40]}'")
                if RE_SMTP_STARTTLS_ADV.search(line):
                    starttls_supported = True
                    evidence.append(f"Server advertised STARTTLS capability: '{line[:40]}'")
                elif "STARTTLS" in line.upper() and line.startswith("250"):
                    starttls_supported = True
                    evidence.append(f"Server advertised STARTTLS: '{line[:40]}'")

                if RE_SMTP_STARTTLS_CMD.search(line):
                    starttls_requested = True
                    evidence.append(f"Client issued STARTTLS command: '{line[:40]}'")

                if starttls_requested and (RE_SMTP_STARTTLS_OK.search(line) or (line.startswith("220") and "TLS" in line.upper())):
                    tls_upgrade_detected = True
                    evidence.append(f"Server acknowledged STARTTLS ready: '{line[:40]}'")

        elif proto_upper.startswith("IMAP"):
            for line in payload_lines:
                if RE_IMAP_CAPA_ADV.search(line) or ("STARTTLS" in line.upper() and "CAPABILITY" in line.upper()):
                    starttls_supported = True
                    evidence.append(f"IMAP Server advertised STARTTLS capability: '{line[:40]}'")

                if RE_IMAP_STARTTLS_CMD.search(line):
                    starttls_requested = True
                    evidence.append(f"IMAP Client issued STARTTLS command: '{line[:40]}'")

                if starttls_requested and (RE_IMAP_STARTTLS_OK.search(line) or ("OK" in line.upper() and "TLS" in line.upper())):
                    tls_upgrade_detected = True
                    evidence.append(f"IMAP Server acknowledged STARTTLS upgrade: '{line[:40]}'")

        elif proto_upper.startswith("POP3"):
            for line in payload_lines:
                if RE_POP3_CAPA_ADV.search(line) or ("STLS" in line.upper() and not line.upper().startswith("+OK")):
                    starttls_supported = True
                    evidence.append(f"POP3 Server advertised STLS capability: '{line[:40]}'")

                if RE_POP3_STLS_CMD.search(line):
                    starttls_requested = True
                    evidence.append(f"POP3 Client issued STLS command: '{line[:40]}'")

                if starttls_requested and (RE_POP3_STLS_OK.search(line) or ("+OK" in line.upper() and "TLS" in line.upper())):
                    tls_upgrade_detected = True
                    evidence.append(f"POP3 Server acknowledged STLS upgrade: '{line[:40]}'")

        # 3. Determine Overall Encryption Mode
        if tls_upgrade_detected and has_tls_records:
            encryption_mode = "STARTTLS_UPGRADE"
            evidence.append("TLS handshake observed immediately following STARTTLS/STLS upgrade")
            details = "Successful in-band TLS upgrade negotiated and confirmed."
        elif tls_upgrade_detected and not has_tls_records:
            encryption_mode = "FAILED_UPGRADE"
            evidence.append("Server acknowledged upgrade, but no subsequent TLS handshake record was observed")
            details = "Incomplete/failed STARTTLS upgrade: Missing TLS handshake."
        elif starttls_requested and not tls_upgrade_detected:
            encryption_mode = "FAILED_UPGRADE"
            evidence.append("Client requested STARTTLS, but server did not acknowledge upgrade")
            details = "STARTTLS command was sent by client but rejected or unanswered by server."
        elif starttls_supported and not starttls_requested:
            encryption_mode = "PLAINTEXT"
            evidence.append("Server advertised STARTTLS, but client did not request upgrade (Cleartext transmission)")
            details = "Plaintext session despite STARTTLS capability (Potential opportunistic downgrade)."
        elif has_tls_records:
            encryption_mode = "STARTTLS_UPGRADE" if (starttls_requested or tls_upgrade_detected) else "IMPLICIT_TLS"
            details = "TLS handshake observed on stream."
        elif len(payload_lines) > 0:
            encryption_mode = "PLAINTEXT"
            evidence.append("Cleartext session: No TLS or STARTTLS exchange observed")
            details = "Unencrypted plaintext email communication."
        else:
            encryption_mode = "UNKNOWN"
            evidence.append("Insufficient payload evidence to determine encryption mode")
            details = "Zero payload application packets exchanged."

        return StarttlsAnalysisResult(
            encryption_mode=encryption_mode,
            starttls_supported=starttls_supported,
            starttls_requested=starttls_requested,
            tls_upgrade_detected=tls_upgrade_detected,
            tls_handshake_detected=has_tls_records,
            starttls_evidence=evidence,
            details=details,
        )
