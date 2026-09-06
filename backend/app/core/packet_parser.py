import datetime
import struct
from typing import Any, Optional
from dataclasses import dataclass, field

from backend.app.core.tls_analyzer import TLSAnalyzer, DetailedTLSHandshake, TLS_CIPHER_SUITES, TLS_VERSIONS
from backend.app.core.starttls_analyzer import StarttlsAnalyzer
from backend.app.core.protocol_identifier import ProtocolIdentifier

@dataclass
class ParsedTLSRecord:
    version: Optional[str] = None
    cipher_suite: Optional[str] = None
    cipher_suite_code: Optional[str] = None
    key_exchange: Optional[str] = None
    forward_secrecy: bool = False
    sni: Optional[str] = None
    alpn: Optional[str] = None
    client_hello: bool = False
    server_hello: bool = False
    raw_certificates: list[bytes] = field(default_factory=list)

@dataclass
class ParsedEmailSession:
    session_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str = "UNKNOWN"
    transport_protocol: str = "TCP"
    tcp_stream_id: int = 0
    is_encrypted: bool = False
    encryption_mode: str = "UNKNOWN"
    tls_version: str = "Not observed"
    cipher_suite: str = "Not observed"
    cipher_suite_code: Optional[str] = None
    key_exchange: str = "Not observed"
    forward_secrecy: bool = False
    elliptic_curve: str = "Not observed"
    signature_algorithm: str = "Not observed"
    handshake_status: str = "Not observed"
    tls_alerts: list[str] = field(default_factory=list)
    session_resumption: str = "Not observed"
    starttls_supported: bool = False
    starttls_requested: bool = False
    starttls_accepted: bool = False
    tls_handshake_detected: bool = False
    starttls_evidence: list[str] = field(default_factory=list)
    sni: Optional[str] = None
    alpn: Optional[str] = None
    packet_count: int = 0
    byte_count: int = 0
    duration_ms: float = 0.0
    client_hello_seen: bool = False
    server_hello_seen: bool = False
    certificate_seen: bool = False
    anomaly_score: Optional[float] = None
    is_anomalous: bool = False
    anomaly_status: str = "NORMAL"
    risk_priority: str = "INFORMATIONAL"
    anomaly_explanation: str = ""
    timestamp_first: Optional[datetime.datetime] = None
    timestamp_last: Optional[datetime.datetime] = None
    raw_certificates: list[bytes] = field(default_factory=list)
    plaintext_commands: list[str] = field(default_factory=list)
    has_auth_plain: bool = False
    status: str = "UNKNOWN"
    protocol_evidence: list[str] = field(default_factory=list)

def detect_protocol(port1: int, port2: int) -> str:
    ports = {port1, port2}
    if 465 in ports:
        return "SMTPS"
    if 25 in ports or 587 in ports:
        return "SMTP"
    if 993 in ports:
        return "IMAPS"
    if 143 in ports:
        return "IMAP"
    if 995 in ports:
        return "POP3S"
    if 110 in ports:
        return "POP3"
    return "UNKNOWN_EMAIL"

def parse_tls_record(payload: bytes) -> Optional[ParsedTLSRecord]:
    """Backward compatibility helper for single-packet TLS record inspection."""
    detailed = TLSAnalyzer.parse_tls_records(payload)
    if not detailed.client_hello_seen and not detailed.server_hello_seen:
        return None
    res = ParsedTLSRecord(
        version=detailed.tls_version if detailed.tls_version != "Not observed" else None,
        cipher_suite=detailed.cipher_suite if detailed.cipher_suite != "Not observed" else None,
        cipher_suite_code=detailed.cipher_suite_code,
        key_exchange=detailed.key_exchange if detailed.key_exchange != "Not observed" else None,
        forward_secrecy=detailed.forward_secrecy,
        sni=detailed.sni,
        alpn=detailed.alpn,
        client_hello=detailed.client_hello_seen,
        server_hello=detailed.server_hello_seen,
        raw_certificates=detailed.raw_certificates,
    )
    return res

@dataclass
class PacketProcessingMetrics:
    total_packets: int = 0
    ip_packet_count: int = 0
    tcp_packet_count: int = 0
    tcp_stream_count: int = 0
    email_packet_count: int = 0
    sessions: list[ParsedEmailSession] = field(default_factory=list)
    tshark_available: bool = False
    engine_note: str = ""
    corrupted_packets_skipped: int = 0

    def __iter__(self):
        yield self.total_packets
        yield self.email_packet_count
        yield self.sessions

class PcapParserEngine:
    """Forensic PCAP parser using Scapy with raw packet stream inspection and safe corruption handling."""

    @staticmethod
    def parse_pcap(filepath: str) -> PacketProcessingMetrics:
        import os
        import shutil

        tshark_installed = shutil.which("tshark") is not None
        engine_note = "Wireshark CLI (tshark) active" if tshark_installed else "Native Scapy Libpcap engine (tshark not found in PATH)"

        if not os.path.exists(filepath):
            return PacketProcessingMetrics(engine_note="File not found on disk")

        from scapy.utils import PcapReader
        from scapy.layers.inet import IP, TCP
        from scapy.layers.inet6 import IPv6
        from scapy.packet import Raw

        metrics = PacketProcessingMetrics(
            tshark_available=tshark_installed,
            engine_note=engine_note,
        )

        stream_key_to_id: dict[tuple, int] = {}
        sessions_map: dict[tuple, ParsedEmailSession] = {}
        stream_payloads: dict[tuple, list[bytes]] = {}
        stream_payload_lines: dict[tuple, list[str]] = {}
        stream_tls_handshakes: dict[tuple, DetailedTLSHandshake] = {}
        stream_first_payload_is_tls: dict[tuple, bool] = {}

        try:
            with PcapReader(filepath) as reader:
                while True:
                    try:
                        pkt = reader.read_packet()
                        if pkt is None:
                            break
                    except EOFError:
                        break
                    except Exception:
                        metrics.corrupted_packets_skipped += 1
                        continue

                    metrics.total_packets += 1

                    # Identify IP traffic (IPv4 or IPv6)
                    is_ip = IP in pkt or IPv6 in pkt
                    if is_ip:
                        metrics.ip_packet_count += 1

                    # Identify TCP traffic
                    if not is_ip or TCP not in pkt:
                        continue

                    metrics.tcp_packet_count += 1

                    src_ip = pkt[IP].src if IP in pkt else pkt[IPv6].src
                    dst_ip = pkt[IP].dst if IP in pkt else pkt[IPv6].dst
                    src_port = int(pkt[TCP].sport)
                    dst_port = int(pkt[TCP].dport)

                    # Track distinct TCP stream (5-tuple conversation)
                    conv_key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)]))
                    if conv_key not in stream_key_to_id:
                        stream_key_to_id[conv_key] = len(stream_key_to_id)
                    stream_id = stream_key_to_id[conv_key]

                    pkt_time = datetime.datetime.fromtimestamp(float(pkt.time))
                    pkt_len = len(pkt)

                    if conv_key not in sessions_map:
                        import uuid
                        session_id = f"sess_{uuid.uuid4().hex[:12]}"
                        sessions_map[conv_key] = ParsedEmailSession(
                            session_id=session_id,
                            src_ip=src_ip,
                            src_port=src_port,
                            dst_ip=dst_ip,
                            dst_port=dst_port,
                            protocol="UNKNOWN",
                            transport_protocol="TCP",
                            tcp_stream_id=stream_id,
                            timestamp_first=pkt_time,
                            timestamp_last=pkt_time,
                        )

                    session = sessions_map[conv_key]
                    session.packet_count += 1
                    session.byte_count += pkt_len
                    session.timestamp_last = pkt_time

                    # Inspect TCP payload if available
                    if Raw in pkt:
                        raw_payload = bytes(pkt[Raw].load)
                        if len(stream_payloads.setdefault(conv_key, [])) < 30:
                            stream_payloads[conv_key].append(raw_payload)

                        # Check if first payload is TLS record
                        if conv_key not in stream_first_payload_is_tls:
                            is_tls_hdr = len(raw_payload) >= 5 and raw_payload[0] in {20, 21, 22, 23} and raw_payload[1] == 3
                            stream_first_payload_is_tls[conv_key] = is_tls_hdr

                        # Dissect TLS Handshake layers
                        cur_tls = stream_tls_handshakes.get(conv_key)
                        updated_tls = TLSAnalyzer.parse_tls_records(raw_payload, cur_tls)
                        stream_tls_handshakes[conv_key] = updated_tls

                        # Extract text lines for plaintext / STARTTLS analysis
                        try:
                            text = raw_payload.decode("utf-8", errors="ignore")
                            for line in text.splitlines():
                                cl = line.strip()
                                if cl:
                                    stream_payload_lines.setdefault(conv_key, []).append(cl)
                                    up = cl.upper()
                                    if "AUTH PLAIN" in up or "AUTH LOGIN" in up or up.startswith("USER ") or up.startswith("PASS "):
                                        session.has_auth_plain = True
                                        session.plaintext_commands.append(cl[:40])
                        except Exception:
                            pass

        except Exception as e:
            metrics.engine_note = f"Reader terminated with notice: {str(e)}"

        # Final processing, protocol classification, and STARTTLS state resolution
        for conv_key, session in sessions_map.items():
            if session.timestamp_first and session.timestamp_last:
                delta = (session.timestamp_last - session.timestamp_first).total_seconds() * 1000.0
                session.duration_ms = max(round(delta, 2), 0.1)

            tls_info = stream_tls_handshakes.get(conv_key)
            has_tls_records = False
            if tls_info and (tls_info.client_hello_seen or tls_info.server_hello_seen or tls_info.app_data_seen or tls_info.change_cipher_spec_seen or tls_info.tls_alerts):
                has_tls_records = True
                session.is_encrypted = True
                session.tls_version = tls_info.tls_version
                session.cipher_suite = tls_info.cipher_suite
                session.cipher_suite_code = tls_info.cipher_suite_code
                session.key_exchange = tls_info.key_exchange
                session.forward_secrecy = tls_info.forward_secrecy
                session.elliptic_curve = tls_info.elliptic_curve
                session.signature_algorithm = tls_info.signature_algorithm
                session.handshake_status = tls_info.handshake_status
                session.tls_alerts = tls_info.tls_alerts
                session.session_resumption = tls_info.session_resumption
                session.sni = tls_info.sni
                session.alpn = tls_info.alpn
                session.client_hello_seen = tls_info.client_hello_seen
                session.server_hello_seen = tls_info.server_hello_seen
                session.certificate_seen = tls_info.certificate_seen
                session.raw_certificates = tls_info.raw_certificates

            # Protocol classification
            payloads = stream_payloads.get(conv_key, [])
            classification = ProtocolIdentifier.classify_stream(
                payloads=payloads,
                src_port=session.src_port,
                dst_port=session.dst_port,
                tls_info=tls_info,
                is_tls=session.is_encrypted,
            )
            session.protocol = classification.protocol
            session.protocol_evidence = classification.evidence
            session.status = classification.status
            if classification.is_email:
                metrics.email_packet_count += session.packet_count

            # STARTTLS / STLS Analysis
            starttls_res = StarttlsAnalyzer.analyze_stream(
                protocol=session.protocol,
                payload_lines=stream_payload_lines.get(conv_key, []),
                has_tls_records=has_tls_records,
                first_payload_is_tls=stream_first_payload_is_tls.get(conv_key, False),
                src_port=session.src_port,
                dst_port=session.dst_port,
            )
            session.encryption_mode = starttls_res.encryption_mode
            session.starttls_supported = starttls_res.starttls_supported
            session.starttls_requested = starttls_res.starttls_requested
            session.starttls_accepted = starttls_res.tls_upgrade_detected
            session.tls_handshake_detected = starttls_res.tls_handshake_detected
            session.starttls_evidence = starttls_res.starttls_evidence

            # If STARTTLS upgrade succeeded, mark status as ENCRYPTED
            if session.encryption_mode == "STARTTLS_UPGRADE":
                session.is_encrypted = True
                session.status = "ENCRYPTED"

        metrics.tcp_stream_count = len(stream_key_to_id)
        metrics.sessions = list(sessions_map.values())
        return metrics
