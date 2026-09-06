"""
Comprehensive TLS Handshake Analysis Engine.
Dissects TLS record layers and handshake protocols (TLS 1.0, 1.1, 1.2, 1.3),
extracting real negotiated cipher suites, key exchanges, elliptic curves/groups,
signature algorithms, alert notifications, session resumption, and completion status.
Handles fragmented packets and corrupted frames safely without crashing.
"""
from __future__ import annotations
import struct
from dataclasses import dataclass, field
from typing import Optional, List, Tuple

# Known TLS Versions
TLS_VERSIONS = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

# Known TLS Cipher Suites: (Name, Algorithm, ForwardSecrecy, KeyExchange)
TLS_CIPHER_SUITES = {
    0x0004: ("TLS_RSA_WITH_RC4_128_MD5", "RC4", False, "RSA"),
    0x0005: ("TLS_RSA_WITH_RC4_128_SHA", "RC4", False, "RSA"),
    0x000A: ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "3DES", False, "RSA"),
    0x002F: ("TLS_RSA_WITH_AES_128_CBC_SHA", "AES-CBC", False, "RSA"),
    0x0035: ("TLS_RSA_WITH_AES_256_CBC_SHA", "AES-CBC", False, "RSA"),
    0x003C: ("TLS_RSA_WITH_AES_128_CBC_SHA256", "AES-CBC", False, "RSA"),
    0x003D: ("TLS_RSA_WITH_AES_256_CBC_SHA256", "AES-CBC", False, "RSA"),
    0x009C: ("TLS_RSA_WITH_AES_128_GCM_SHA256", "AES-GCM", False, "RSA"),
    0x009D: ("TLS_RSA_WITH_AES_256_GCM_SHA384", "AES-GCM", False, "RSA"),
    0xC013: ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "AES-CBC", True, "ECDHE"),
    0xC014: ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "AES-CBC", True, "ECDHE"),
    0xC027: ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "AES-CBC", True, "ECDHE"),
    0xC028: ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "AES-CBC", True, "ECDHE"),
    0xC02F: ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "AES-GCM", True, "ECDHE"),
    0xC030: ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "AES-GCM", True, "ECDHE"),
    0xCCA8: ("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "CHACHA20", True, "ECDHE"),
    0xCCA9: ("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "CHACHA20", True, "ECDHE"),
    # TLS 1.3 AEAD Ciphers
    0x1301: ("TLS_AES_128_GCM_SHA256", "AES-GCM", True, "ECDHE/DHE"),
    0x1302: ("TLS_AES_256_GCM_SHA384", "AES-GCM", True, "ECDHE/DHE"),
    0x1303: ("TLS_CHACHA20_POLY1305_SHA256", "CHACHA20", True, "ECDHE/DHE"),
    0x1304: ("TLS_AES_128_CCM_SHA256", "AES-CCM", True, "ECDHE/DHE"),
    0x1305: ("TLS_AES_128_CCM_8_SHA256", "AES-CCM", True, "ECDHE/DHE"),
}

# Elliptic Curves and Supported Groups
NAMED_GROUPS = {
    0x0017: "secp256r1 (NIST P-256)",
    0x0018: "secp384r1 (NIST P-384)",
    0x0019: "secp521r1 (NIST P-521)",
    0x001D: "x25519 (Curve25519)",
    0x001E: "x448 (Curve448)",
    0x0100: "ffdhe2048 (Finite Field DHE)",
    0x0101: "ffdhe3072 (Finite Field DHE)",
    0x0102: "ffdhe4096 (Finite Field DHE)",
}

# Signature Algorithms
SIGNATURE_ALGORITHMS = {
    0x0401: "rsa_pkcs1_sha256",
    0x0501: "rsa_pkcs1_sha384",
    0x0601: "rsa_pkcs1_sha512",
    0x0403: "ecdsa_secp256r1_sha256",
    0x0503: "ecdsa_secp384r1_sha384",
    0x0804: "rsa_pss_rsae_sha256",
    0x0805: "rsa_pss_rsae_sha384",
    0x0806: "rsa_pss_rsae_sha512",
    0x0807: "ed25519",
    0x0808: "ed448",
}

# TLS Alert Descriptions
ALERT_DESCRIPTIONS = {
    0: "close_notify",
    10: "unexpected_message",
    20: "bad_record_mac",
    21: "decryption_failed_RESERVED",
    22: "record_overflow",
    30: "decompression_failure",
    40: "handshake_failure",
    41: "no_certificate_RESERVED",
    42: "bad_certificate",
    43: "unsupported_certificate",
    44: "certificate_revoked",
    45: "certificate_expired",
    46: "certificate_unknown",
    47: "illegal_parameter",
    48: "unknown_ca",
    49: "access_denied",
    50: "decode_error",
    51: "decrypt_error",
    70: "protocol_version",
    71: "insufficient_security",
    80: "internal_error",
    90: "user_canceled",
    100: "no_renegotiation",
    110: "unsupported_extension",
    112: "unrecognized_name",
    115: "unknown_psk_identity",
}


@dataclass
class DetailedTLSHandshake:
    tls_version: str = "Not observed"
    client_hello_seen: bool = False
    server_hello_seen: bool = False
    cipher_suite: str = "Not observed"
    cipher_suite_code: Optional[str] = None
    key_exchange: str = "Not observed"
    forward_secrecy: bool = False
    elliptic_curve: str = "Not observed"
    signature_algorithm: str = "Not observed"
    handshake_status: str = "Not observed"
    tls_alerts: list[str] = field(default_factory=list)
    session_resumption: str = "Not observed"
    sni: Optional[str] = None
    alpn: Optional[str] = None
    certificate_seen: bool = False
    raw_certificates: list[bytes] = field(default_factory=list)
    change_cipher_spec_seen: bool = False
    app_data_seen: bool = False


class TLSAnalyzer:
    """Dissects raw packet payloads for complete TLS handshake analysis."""

    @classmethod
    def parse_tls_records(cls, payload: bytes, existing: Optional[DetailedTLSHandshake] = None) -> DetailedTLSHandshake:
        res = existing or DetailedTLSHandshake()
        if len(payload) < 5:
            return res

        offset = 0
        while offset + 5 <= len(payload):
            content_type = payload[offset]
            rec_ver_major = payload[offset + 1]
            rec_ver_minor = payload[offset + 2]
            rec_len = int.from_bytes(payload[offset + 3 : offset + 5], "big")
            rec_end = offset + 5 + rec_len
            
            # Guard against truncated/damaged records
            if rec_end > len(payload):
                body = payload[offset + 5 :]
            else:
                body = payload[offset + 5 : rec_end]

            # 1. Alert Record (Type 21)
            if content_type == 21 and len(body) >= 2:
                level_code = body[0]
                desc_code = body[1]
                level = "Fatal" if level_code == 2 else "Warning"
                desc_name = ALERT_DESCRIPTIONS.get(desc_code, f"alert_code_{desc_code}")
                alert_msg = f"{level}: {desc_name}"
                if alert_msg not in res.tls_alerts:
                    res.tls_alerts.append(alert_msg)
                res.handshake_status = "Failed"

            # 2. ChangeCipherSpec (Type 20)
            elif content_type == 20:
                res.change_cipher_spec_seen = True

            # 3. Application Data (Type 23)
            elif content_type == 23:
                res.app_data_seen = True

            # 4. Handshake Record (Type 22)
            elif content_type == 22 and len(body) >= 4:
                hs_offset = 0
                while hs_offset + 4 <= len(body):
                    hs_type = body[hs_offset]
                    hs_len = int.from_bytes(body[hs_offset + 1 : hs_offset + 4], "big")
                    hs_body = body[hs_offset + 4 : hs_offset + 4 + hs_len]

                    # ClientHello (1)
                    if hs_type == 1 and len(hs_body) >= 34:
                        res.client_hello_seen = True
                        client_ver = int.from_bytes(hs_body[:2], "big")
                        if res.tls_version == "Not observed" and client_ver in TLS_VERSIONS:
                            res.tls_version = TLS_VERSIONS[client_ver]

                        # Session ID
                        sess_id_len = hs_body[34] if len(hs_body) > 34 else 0
                        if sess_id_len > 0:
                            res.session_resumption = "Possible Session ID Resumption"

                        ciphers_offset = 35 + sess_id_len
                        if ciphers_offset + 2 <= len(hs_body):
                            ciphers_len = int.from_bytes(hs_body[ciphers_offset : ciphers_offset + 2], "big")
                            ext_offset = ciphers_offset + 2 + ciphers_len
                            if ext_offset + 1 < len(hs_body):
                                comp_methods_len = hs_body[ext_offset]
                                ext_data_offset = ext_offset + 1 + comp_methods_len
                                if ext_data_offset + 2 <= len(hs_body):
                                    ext_total_len = int.from_bytes(hs_body[ext_data_offset : ext_data_offset + 2], "big")
                                    cur_ext = ext_data_offset + 2
                                    while cur_ext + 4 <= len(hs_body) and cur_ext < ext_data_offset + 2 + ext_total_len:
                                        ext_type = int.from_bytes(hs_body[cur_ext : cur_ext + 2], "big")
                                        ext_size = int.from_bytes(hs_body[cur_ext + 2 : cur_ext + 4], "big")
                                        cur_data = hs_body[cur_ext + 4 : cur_ext + 4 + ext_size]
                                        # SNI (0)
                                        if ext_type == 0 and len(cur_data) > 5:
                                            sni_len = int.from_bytes(cur_data[3:5], "big")
                                            res.sni = cur_data[5 : 5 + sni_len].decode("utf-8", errors="ignore")
                                        # Supported Groups (10)
                                        elif ext_type == 10 and len(cur_data) >= 4:
                                            first_group = int.from_bytes(cur_data[2:4], "big")
                                            res.elliptic_curve = NAMED_GROUPS.get(first_group, f"Group 0x{first_group:04X}")
                                        # Signature Algorithms (13)
                                        elif ext_type == 13 and len(cur_data) >= 4:
                                            first_sig = int.from_bytes(cur_data[2:4], "big")
                                            res.signature_algorithm = SIGNATURE_ALGORITHMS.get(first_sig, f"Sig 0x{first_sig:04X}")
                                        # ALPN (16)
                                        elif ext_type == 16 and len(cur_data) > 3:
                                            proto_len = cur_data[2]
                                            res.alpn = cur_data[3 : 3 + proto_len].decode("ascii", errors="ignore")
                                        # Session Ticket (35)
                                        elif ext_type == 35:
                                            res.session_resumption = "Resumed via Session Ticket"
                                        # Supported Versions (43)
                                        elif ext_type == 43 and b"\x03\x04" in cur_data:
                                            res.tls_version = "TLS 1.3"

                                        cur_ext += 4 + ext_size

                    # ServerHello (2)
                    elif hs_type == 2 and len(hs_body) >= 34:
                        res.server_hello_seen = True
                        server_ver = int.from_bytes(hs_body[:2], "big")
                        res.tls_version = TLS_VERSIONS.get(server_ver, f"TLS ({hex(server_ver)})")

                        sess_id_len = hs_body[34] if len(hs_body) > 34 else 0
                        cipher_offset = 35 + sess_id_len
                        if cipher_offset + 2 <= len(hs_body):
                            cipher_code = int.from_bytes(hs_body[cipher_offset : cipher_offset + 2], "big")
                            res.cipher_suite_code = f"0x{cipher_code:04X}"
                            if cipher_code in TLS_CIPHER_SUITES:
                                name, algo, fs, kx = TLS_CIPHER_SUITES[cipher_code]
                                res.cipher_suite = name
                                res.forward_secrecy = fs
                                res.key_exchange = kx
                            else:
                                res.cipher_suite = f"UNKNOWN_CIPHER_{res.cipher_suite_code}"
                                res.key_exchange = "Unknown"

                            # Parse extensions for TLS 1.3 supported_versions & key_share
                            ext_offset = cipher_offset + 3  # skip cipher + 1 byte compression
                            if ext_offset + 2 <= len(hs_body):
                                ext_total_len = int.from_bytes(hs_body[ext_offset : ext_offset + 2], "big")
                                cur_ext = ext_offset + 2
                                while cur_ext + 4 <= len(hs_body) and cur_ext < ext_offset + 2 + ext_total_len:
                                    ext_type = int.from_bytes(hs_body[cur_ext : cur_ext + 2], "big")
                                    ext_size = int.from_bytes(hs_body[cur_ext + 2 : cur_ext + 4], "big")
                                    ext_body = hs_body[cur_ext + 4 : cur_ext + 4 + ext_size]
                                    if ext_type == 43 and len(ext_body) >= 2:
                                        sel_ver = int.from_bytes(ext_body[:2], "big")
                                        if sel_ver == 0x0304:
                                            res.tls_version = "TLS 1.3"
                                            res.forward_secrecy = True
                                            res.key_exchange = "ECDHE/DHE"
                                    elif ext_type == 51 and len(ext_body) >= 2:
                                        # Key Share selected group
                                        group_code = int.from_bytes(ext_body[:2], "big")
                                        res.elliptic_curve = NAMED_GROUPS.get(group_code, f"Group 0x{group_code:04X}")

                                    cur_ext += 4 + ext_size

                    # Certificate (11)
                    elif hs_type == 11 and len(hs_body) >= 3:
                        res.certificate_seen = True
                        certs_len = int.from_bytes(hs_body[:3], "big")
                        cert_offset = 3
                        while cert_offset + 3 < len(hs_body) and cert_offset < 3 + certs_len:
                            one_cert_len = int.from_bytes(hs_body[cert_offset : cert_offset + 3], "big")
                            cert_bytes = hs_body[cert_offset + 3 : cert_offset + 3 + one_cert_len]
                            if cert_bytes:
                                res.raw_certificates.append(cert_bytes)
                            cert_offset += 3 + one_cert_len

                    # ServerKeyExchange (12)
                    elif hs_type == 12 and len(hs_body) >= 4:
                        curve_type = hs_body[0]
                        if curve_type == 3 and len(hs_body) >= 3:  # named_curve
                            curve_id = int.from_bytes(hs_body[1:3], "big")
                            res.elliptic_curve = NAMED_GROUPS.get(curve_id, f"Curve 0x{curve_id:04X}")
                            res.forward_secrecy = True

                    hs_offset += 4 + hs_len

            offset = rec_end if rec_end <= len(payload) else len(payload)

        # Evaluate Handshake Completion Status
        if res.server_hello_seen:
            if res.app_data_seen or res.change_cipher_spec_seen:
                res.handshake_status = "Completed"
            elif res.handshake_status != "Failed":
                res.handshake_status = "Incomplete"
        elif res.client_hello_seen:
            if res.handshake_status != "Failed":
                res.handshake_status = "Incomplete (ClientHello only)"

        return res
