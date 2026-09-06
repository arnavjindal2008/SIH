import datetime
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from backend.app.core.cert_inspector import CertificateInspector

def test_x509_cert_inspection():
    # Generate private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "mail.enterprise.local"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Enterprise Security Org"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("mail.enterprise.local")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    der_bytes = cert.public_bytes(serialization.Encoding.DER)
    inspected = CertificateInspector.inspect_der(der_bytes)

    assert inspected is not None
    assert inspected.subject_cn == "mail.enterprise.local"
    assert inspected.issuer_cn == "mail.enterprise.local"
    assert inspected.is_self_signed is True
    assert inspected.is_expired is False
    assert inspected.key_algorithm == "RSA"
    assert inspected.key_size == 2048
    assert "Self-signed certificate" in " ".join(inspected.trust_warnings)
