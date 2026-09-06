"""
Email Protocol Identification Engine.
Analyzes TCP stream payloads, server greetings, client command tokens,
and cryptographic handshakes to identify email protocols (SMTP, IMAP, POP3)
and reject arbitrary non-email TCP traffic as UNKNOWN.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Optional, List, Tuple

# RFC Port Constants
SMTP_PORTS = {25, 465, 587, 2525}
IMAP_PORTS = {143, 993}
POP3_PORTS = {110, 995}
EMAIL_PORTS = SMTP_PORTS | IMAP_PORTS | POP3_PORTS

# Regex signatures for application protocols
RE_SMTP_BANNER = re.compile(r"^220[ -].*", re.IGNORECASE)
RE_SMTP_BANNER_STRONG = re.compile(r"^220[ -].*(?:esmtp|smtp|mail|postfix|sendmail|exim)", re.IGNORECASE)
RE_SMTP_COMMAND = re.compile(
    r"^(?:EHLO|HELO|MAIL FROM:|RCPT TO:|DATA|STARTTLS|RSET|VRFY|EXPN|HELP|NOOP|QUIT|AUTH PLAIN|AUTH LOGIN|AUTH CRAM-MD5|AUTH EXTERNAL|BDAT)\b",
    re.IGNORECASE
)
RE_SMTP_RESPONSE = re.compile(r"^(?:250|220|354|221|235|334|421|450|451|452|500|501|502|503|504|535|550|552|553|554)[ -]", re.IGNORECASE)

RE_IMAP_BANNER = re.compile(r"^\* OK\b.*", re.IGNORECASE)
RE_IMAP_BANNER_STRONG = re.compile(r"^\* OK\b.*(?:imap|ready|dovecot|cyrus|courier)", re.IGNORECASE)
RE_IMAP_COMMAND = re.compile(
    r"^(?:[a-zA-Z0-9_\.]+\s+)?(?:CAPABILITY|LOGIN|AUTHENTICATE|STARTTLS|SELECT|EXAMINE|CREATE|DELETE|RENAME|SUBSCRIBE|UNSUBSCRIBE|LIST|LSUB|STATUS|APPEND|CHECK|CLOSE|EXPUNGE|SEARCH|FETCH|STORE|COPY|MOVE|UID|NOOP|LOGOUT|ID|ENABLE)\b",
    re.IGNORECASE
)
RE_IMAP_RESPONSE = re.compile(
    r"^(?:\* (?:CAPABILITY|FLAGS|LIST|LSUB|SEARCH|STATUS|[0-9]+ EXISTS|[0-9]+ RECENT|[0-9]+ FETCH|BYE|PREAUTH)|[a-zA-Z0-9_\.]+\s+(?:OK|NO|BAD))\b",
    re.IGNORECASE
)

RE_POP3_BANNER = re.compile(r"^\+OK\b.*", re.IGNORECASE)
RE_POP3_BANNER_STRONG = re.compile(r"^\+OK\b.*(?:pop|ready|dovecot|cyrus|qpopper)", re.IGNORECASE)
RE_POP3_COMMAND = re.compile(
    r"^(?:USER|PASS|STAT|LIST|RETR|DELE|NOOP|RSET|QUIT|TOP|UIDL|APOP|STLS|CAPA|AUTH)\b",
    re.IGNORECASE
)
RE_POP3_RESPONSE = re.compile(r"^(?:\+OK|-ERR)\b", re.IGNORECASE)

# Non-email protocol signatures to prevent false positives
RE_HTTP_SIGNATURE = re.compile(r"^(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|TRACE|CONNECT|PATCH)\s+/\S*\s+HTTP/[0-9\.]|HTTP/[0-9\.]+\s+[0-9]{3}", re.IGNORECASE)
RE_SSH_SIGNATURE = re.compile(r"^SSH-[0-9\.]+-", re.IGNORECASE)


@dataclass
class ProtocolClassification:
    protocol: str  # "SMTP", "IMAP", "POP3", "UNKNOWN"
    confidence: float  # 0.0 to 1.0
    evidence: list[str] = field(default_factory=list)
    is_email: bool = False
    status: str = "UNKNOWN"  # "ENCRYPTED", "PLAINTEXT", "UNKNOWN"
    details: str = ""


class ProtocolIdentifier:
    """
    Forensic passive protocol identifier for email sessions.
    Inspects TCP stream payload data, protocol banners, command tokens,
    and TLS records to classify traffic into SMTP, IMAP, POP3, or UNKNOWN.
    """

    @staticmethod
    def extract_text_lines(payloads: list[bytes], max_lines: int = 40) -> list[str]:
        """Extract clean ASCII/UTF-8 lines from raw payload buffers."""
        lines: list[str] = []
        for p in payloads:
            if not p:
                continue
            try:
                text = p.decode("utf-8", errors="ignore")
                for line in text.splitlines():
                    cleaned = line.strip()
                    if cleaned:
                        lines.append(cleaned)
                        if len(lines) >= max_lines:
                            return lines
            except Exception:
                continue
        return lines

    @classmethod
    def classify_stream(
        cls,
        payloads: list[bytes],
        src_port: int,
        dst_port: int,
        tls_info: Optional[any] = None,
        is_tls: bool = False,
    ) -> ProtocolClassification:
        """
        Classifies a TCP stream into SMTP, IMAP, POP3, or UNKNOWN.
        Evaluates payload evidence before considering port hints.
        """
        ports = {src_port, dst_port}
        lines = cls.extract_text_lines(payloads)
        evidence: list[str] = []
        
        # 1. First, check for obvious non-email protocols (e.g. HTTP, SSH)
        for line in lines[:10]:
            if RE_HTTP_SIGNATURE.search(line):
                return ProtocolClassification(
                    protocol="UNKNOWN",
                    confidence=0.95,
                    evidence=[f"HTTP traffic detected: '{line[:50]}'"],
                    is_email=False,
                    status="PLAINTEXT",
                    details="Stream identified as HTTP traffic, not an email protocol."
                )
            if RE_SSH_SIGNATURE.search(line):
                return ProtocolClassification(
                    protocol="UNKNOWN",
                    confidence=0.95,
                    evidence=[f"SSH traffic detected: '{line[:50]}'"],
                    is_email=False,
                    status="PLAINTEXT",
                    details="Stream identified as SSH transport, not an email protocol."
                )

        # 2. Check TLS ALPN if present
        if tls_info and getattr(tls_info, "alpn", None):
            alpn = tls_info.alpn.lower()
            if "smtp" in alpn or "submission" in alpn:
                return ProtocolClassification(
                    protocol="SMTP",
                    confidence=0.99,
                    evidence=[f"TLS ALPN negotiated: '{tls_info.alpn}'"],
                    is_email=True,
                    status="ENCRYPTED",
                    details="SMTP protocol confirmed via TLS Application-Layer Protocol Negotiation (ALPN)."
                )
            if "imap" in alpn:
                return ProtocolClassification(
                    protocol="IMAP",
                    confidence=0.99,
                    evidence=[f"TLS ALPN negotiated: '{tls_info.alpn}'"],
                    is_email=True,
                    status="ENCRYPTED",
                    details="IMAP protocol confirmed via TLS Application-Layer Protocol Negotiation (ALPN)."
                )
            if "pop" in alpn:
                return ProtocolClassification(
                    protocol="POP3",
                    confidence=0.99,
                    evidence=[f"TLS ALPN negotiated: '{tls_info.alpn}'"],
                    is_email=True,
                    status="ENCRYPTED",
                    details="POP3 protocol confirmed via TLS Application-Layer Protocol Negotiation (ALPN)."
                )
            if "h2" in alpn or "http" in alpn:
                return ProtocolClassification(
                    protocol="UNKNOWN",
                    confidence=0.95,
                    evidence=[f"Non-email TLS ALPN negotiated: '{tls_info.alpn}'"],
                    is_email=False,
                    status="ENCRYPTED",
                    details="Stream negotiated HTTP over TLS via ALPN."
                )

        # 3. Deep Payload Inspection for Plaintext / STARTTLS streams
        smtp_score = 0
        imap_score = 0
        pop3_score = 0

        smtp_ev: list[str] = []
        imap_ev: list[str] = []
        pop3_ev: list[str] = []

        for line in lines:
            # Check SMTP signatures
            if RE_SMTP_BANNER_STRONG.search(line):
                smtp_score += 5
                smtp_ev.append(f"SMTP greeting banner: '{line[:60]}'")
            elif RE_SMTP_BANNER.search(line) and (25 in ports or 587 in ports or 2525 in ports):
                smtp_score += 3
                smtp_ev.append(f"Server 220 banner: '{line[:60]}'")

            if RE_SMTP_COMMAND.search(line):
                cmd_match = RE_SMTP_COMMAND.search(line).group(0)
                smtp_score += 4
                smtp_ev.append(f"SMTP command: '{cmd_match}'")
            elif RE_SMTP_RESPONSE.search(line) and smtp_score > 0:
                smtp_score += 1

            # Check IMAP signatures
            if RE_IMAP_BANNER_STRONG.search(line):
                imap_score += 5
                imap_ev.append(f"IMAP greeting banner: '{line[:60]}'")
            elif RE_IMAP_BANNER.search(line):
                imap_score += 3
                imap_ev.append(f"IMAP greeting: '{line[:60]}'")

            if RE_IMAP_COMMAND.search(line):
                cmd_token = line.split()[-1] if len(line.split()) > 1 else line
                imap_score += 3
                imap_ev.append(f"IMAP command: '{line[:50]}'")
            elif RE_IMAP_RESPONSE.search(line):
                imap_score += 2
                imap_ev.append(f"IMAP response: '{line[:50]}'")

            # Check POP3 signatures
            if RE_POP3_BANNER_STRONG.search(line):
                pop3_score += 5
                pop3_ev.append(f"POP3 greeting banner: '{line[:60]}'")
            elif RE_POP3_BANNER.search(line):
                pop3_score += 2
                pop3_ev.append(f"POP3 +OK greeting: '{line[:60]}'")

            if RE_POP3_COMMAND.search(line):
                cmd_match = RE_POP3_COMMAND.search(line).group(0)
                pop3_score += 3
                pop3_ev.append(f"POP3 command: '{cmd_match}'")
            elif RE_POP3_RESPONSE.search(line) and pop3_score > 0:
                pop3_score += 1

        # Evaluate highest payload score
        max_score = max(smtp_score, imap_score, pop3_score)
        if max_score >= 3:
            if max_score == smtp_score:
                status = "ENCRYPTED" if is_tls else "PLAINTEXT"
                return ProtocolClassification(
                    protocol="SMTP",
                    confidence=min(0.7 + (smtp_score * 0.05), 0.99),
                    evidence=smtp_ev[:5],
                    is_email=True,
                    status=status,
                    details=f"Identified as SMTP via packet payload characteristics ({len(smtp_ev)} matches)."
                )
            elif max_score == imap_score:
                status = "ENCRYPTED" if is_tls else "PLAINTEXT"
                return ProtocolClassification(
                    protocol="IMAP",
                    confidence=min(0.7 + (imap_score * 0.05), 0.99),
                    evidence=imap_ev[:5],
                    is_email=True,
                    status=status,
                    details=f"Identified as IMAP via packet payload characteristics ({len(imap_ev)} matches)."
                )
            elif max_score == pop3_score:
                status = "ENCRYPTED" if is_tls else "PLAINTEXT"
                return ProtocolClassification(
                    protocol="POP3",
                    confidence=min(0.7 + (pop3_score * 0.05), 0.99),
                    evidence=pop3_ev[:5],
                    is_email=True,
                    status=status,
                    details=f"Identified as POP3 via packet payload characteristics ({len(pop3_ev)} matches)."
                )

        # 4. Port hints correlation (Implicit TLS ports or verified email ports with TLS/handshake)
        # SMTPS: Port 465
        if 465 in ports:
            if is_tls:
                return ProtocolClassification(
                    protocol="SMTP",
                    confidence=0.90,
                    evidence=["Implicit TLS stream on designated SMTPS port 465 (RFC 8314)"],
                    is_email=True,
                    status="ENCRYPTED",
                    details="Identified as SMTPS via RFC 8314 port 465 implicit TLS handshake."
                )
            elif lines and any("220" in l or "EHLO" in l for l in lines):
                return ProtocolClassification(
                    protocol="SMTP",
                    confidence=0.85,
                    evidence=["Port 465 with SMTP plaintext exchange"],
                    is_email=True,
                    status="PLAINTEXT",
                    details="Port 465 SMTP conversation."
                )

        # IMAPS: Port 993
        if 993 in ports:
            if is_tls:
                return ProtocolClassification(
                    protocol="IMAP",
                    confidence=0.90,
                    evidence=["Implicit TLS stream on designated IMAPS port 993 (RFC 8314)"],
                    is_email=True,
                    status="ENCRYPTED",
                    details="Identified as IMAPS via RFC 8314 port 993 implicit TLS handshake."
                )

        # POP3S: Port 995
        if 995 in ports:
            if is_tls:
                return ProtocolClassification(
                    protocol="POP3",
                    confidence=0.90,
                    evidence=["Implicit TLS stream on designated POP3S port 995 (RFC 8314)"],
                    is_email=True,
                    status="ENCRYPTED",
                    details="Identified as POP3S via RFC 8314 port 995 implicit TLS handshake."
                )

        # Standard Plaintext Email Ports with partial handshake/evidence
        if (25 in ports or 587 in ports) and is_tls:
            return ProtocolClassification(
                protocol="SMTP",
                confidence=0.85,
                evidence=[f"TLS connection established on SMTP port {min(ports & {25, 587})}"],
                is_email=True,
                status="ENCRYPTED",
                details="SMTP connection with TLS negotiation."
            )
        if 143 in ports and is_tls:
            return ProtocolClassification(
                protocol="IMAP",
                confidence=0.85,
                evidence=["TLS connection established on IMAP port 143"],
                is_email=True,
                status="ENCRYPTED",
                details="IMAP connection with TLS negotiation."
            )
        if 110 in ports and is_tls:
            return ProtocolClassification(
                protocol="POP3",
                confidence=0.85,
                evidence=["TLS connection established on POP3 port 110"],
                is_email=True,
                status="ENCRYPTED",
                details="POP3 connection with TLS negotiation."
            )

        # If on standard port 25/587 and has minimal activity but not contradicting
        if (25 in ports or 587 in ports) and any("220" in l or "mail" in l.lower() for l in lines):
            return ProtocolClassification(
                protocol="SMTP",
                confidence=0.75,
                evidence=[f"Port {min(ports & {25, 587})} with 220 banner/mail keyword"],
                is_email=True,
                status="PLAINTEXT",
                details="SMTP port traffic with basic SMTP tokens."
            )

        # 5. Default Fallback: UNKNOWN / Arbitrary TCP traffic
        status = "ENCRYPTED" if is_tls else "PLAINTEXT"
        if not payloads or sum(len(p) for p in payloads) == 0:
            evidence = ["TCP connection without application data payload (handshake/RST only)"]
            details = "Zero application bytes exchanged; insufficient evidence to classify."
        else:
            evidence = [f"Payload does not match SMTP, IMAP, or POP3 signatures (Port {dst_port})"]
            details = "Arbitrary TCP payload with no email protocol signatures."

        return ProtocolClassification(
            protocol="UNKNOWN",
            confidence=0.30,
            evidence=evidence,
            is_email=False,
            status=status,
            details=details
        )
