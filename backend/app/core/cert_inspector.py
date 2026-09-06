"""
Forensic X.509 Certificate Inspector.
Parses DER-encoded certificates observed in passive network captures using Python cryptography.
Extracts subject/issuer DNs, validity status, remaining days, public key algorithms,
key sizes, signature algorithms, SANs, and chain position without live server interaction.
"""
from __future__ import annotations
import datetime
import hashlib
from dataclasses import dataclass, field
from typing import Optional, List

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, ed448

@dataclass
class InspectedCertificate:
    fingerprint_sha256: str
    subject_cn: Optional[str] = None
    subject_org: Optional[str] = None
    subject_dn: Optional[str] = None
    issuer_cn: Optional[str] = None
    issuer_org: Optional[str] = None
    issuer_dn: Optional[str] = None
    san_list: list[str] = field(default_factory=list)
    valid_from: Optional[datetime.datetime] = None
    valid_to: Optional[datetime.datetime] = None
    is_expired: bool = False
    validity_status: str = "VALID"  # "VALID", "EXPIRED", "NOT_YET_VALID"
    days_remaining: Optional[int] = None
    is_self_signed: bool = False
    key_algorithm: Optional[str] = None
    key_size: Optional[int] = None
    signature_algorithm: Optional[str] = None
    serial_number: Optional[str] = None
    trust_warnings: list[str] = field(default_factory=list)
    raw_pem: Optional[str] = None
    chain_index: int = 0
    chain_info: str = "Server / Leaf Certificate"
    observed_context: str = "Certificate observed in capture"


class CertificateInspector:
    """Forensic passive inspector for X.509 certificates extracted from TLS sessions."""

    @staticmethod
    def inspect_der(der_bytes: bytes, chain_index: int = 0) -> Optional[InspectedCertificate]:
        if not der_bytes:
            return None

        try:
            cert = x509.load_der_x509_certificate(der_bytes)
        except Exception:
            # Safe recovery from corrupted/malformed ASN.1 DER records
            return None

        sha256_fp = hashlib.sha256(der_bytes).hexdigest().upper()
        formatted_fp = ":".join(sha256_fp[i : i + 2] for i in range(0, len(sha256_fp), 2))

        # Subject & Issuer
        subject_cn = None
        subject_org = None
        for attr in cert.subject:
            if attr.oid == x509.NameOID.COMMON_NAME:
                subject_cn = str(attr.value)
            elif attr.oid == x509.NameOID.ORGANIZATION_NAME:
                subject_org = str(attr.value)

        issuer_cn = None
        issuer_org = None
        for attr in cert.issuer:
            if attr.oid == x509.NameOID.COMMON_NAME:
                issuer_cn = str(attr.value)
            elif attr.oid == x509.NameOID.ORGANIZATION_NAME:
                issuer_org = str(attr.value)

        try:
            subject_dn = cert.subject.rfc4514_string()
        except Exception:
            subject_dn = f"CN={subject_cn}" if subject_cn else "Unknown Subject"

        try:
            issuer_dn = cert.issuer.rfc4514_string()
        except Exception:
            issuer_dn = f"CN={issuer_cn}" if issuer_cn else "Unknown Issuer"

        # SANs
        san_list: list[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_list = [str(name.value) for name in san_ext.value]
        except Exception:
            pass

        # Validity dates
        try:
            valid_from = cert.not_valid_before_utc.replace(tzinfo=None)
            valid_to = cert.not_valid_after_utc.replace(tzinfo=None)
        except AttributeError:
            valid_from = cert.not_valid_before
            valid_to = cert.not_valid_after

        now_naive = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        is_expired = now_naive > valid_to
        is_not_yet_valid = now_naive < valid_from

        if is_expired:
            validity_status = "EXPIRED"
            days_remaining = -(now_naive - valid_to).days
        elif is_not_yet_valid:
            validity_status = "NOT_YET_VALID"
            days_remaining = (valid_to - now_naive).days
        else:
            validity_status = "VALID"
            days_remaining = max(0, (valid_to - now_naive).days)

        # Self-signed check
        is_self_signed = (cert.subject == cert.issuer)

        # Public Key details
        try:
            pub_key = cert.public_key()
            key_algorithm = pub_key.__class__.__name__.replace("_", "").replace("PublicKey", "")
            key_size = None
            if isinstance(pub_key, rsa.RSAPublicKey):
                key_algorithm = "RSA"
                key_size = pub_key.key_size
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                key_algorithm = "ECDSA"
                key_size = pub_key.curve.key_size
            elif isinstance(pub_key, ed25519.Ed25519PublicKey):
                key_algorithm = "Ed25519"
                key_size = 256
            elif isinstance(pub_key, ed448.Ed448PublicKey):
                key_algorithm = "Ed448"
                key_size = 448
        except Exception:
            key_algorithm = "Unknown"
            key_size = None

        # Signature Algorithm
        try:
            sig_algo = cert.signature_algorithm_oid._name
        except Exception:
            sig_algo = "Unknown"

        # Serial Number
        serial_str = hex(cert.serial_number)[2:].upper()

        # Chain position
        chain_info = "Server / Leaf Certificate" if chain_index == 0 else f"Intermediate Certificate #{chain_index}"

        # PEM representation
        try:
            raw_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        except Exception:
            raw_pem = None

        # Trust warnings
        warnings = []
        if is_expired:
            warnings.append(f"Certificate observed in capture has expired on {valid_to.strftime('%Y-%m-%d')}")
        if is_not_yet_valid:
            warnings.append(f"Certificate observed in capture is not yet valid until {valid_from.strftime('%Y-%m-%d')}")
        if is_self_signed:
            warnings.append("Self-signed certificate: Untrusted root authority observed in handshake (RFC 5280)")
        if key_algorithm == "RSA" and key_size and key_size < 2048:
            warnings.append(f"Weak RSA key length ({key_size} bits); minimum recommended is 2048 bits (NIST SP 800-52r2)")
        if sig_algo and ("sha1" in sig_algo.lower() or "md5" in sig_algo.lower()):
            warnings.append(f"Cryptographically deprecated signature algorithm ({sig_algo})")

        return InspectedCertificate(
            fingerprint_sha256=formatted_fp,
            subject_cn=subject_cn,
            subject_org=subject_org,
            subject_dn=subject_dn,
            issuer_cn=issuer_cn,
            issuer_org=issuer_org,
            issuer_dn=issuer_dn,
            san_list=san_list,
            valid_from=valid_from,
            valid_to=valid_to,
            is_expired=is_expired,
            validity_status=validity_status,
            days_remaining=days_remaining,
            is_self_signed=is_self_signed,
            key_algorithm=key_algorithm,
            key_size=key_size,
            signature_algorithm=sig_algo,
            serial_number=serial_str,
            trust_warnings=warnings,
            raw_pem=raw_pem,
            chain_index=chain_index,
            chain_info=chain_info,
            observed_context="Certificate observed in capture",
        )
