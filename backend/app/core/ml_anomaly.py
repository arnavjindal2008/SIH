"""
AI-Assisted Anomaly Detection Engine.
Uses unsupervised machine learning (scikit-learn Isolation Forest) to identify
behavioral deviations, unusual cipher combinations, and abnormal session parameters.
Operates in baseline prototype mode and provides risk prioritization and explanations.
"""
from __future__ import annotations
import numpy as np
from typing import Optional, List, Dict, Any
from sklearn.ensemble import IsolationForest
from backend.app.core.packet_parser import ParsedEmailSession
from backend.app.core.cert_inspector import InspectedCertificate

class SessionAnomalyDetector:
    """
    Passive ML Anomaly Detector using scikit-learn Isolation Forest.
    Evaluates protocol, TLS version, cipher combinations, key exchange,
    session duration, and certificate parameters without replacing deterministic rules.
    """

    PROTOTYPE_NOTE = "AI anomaly detection is operating in prototype/baseline mode."

    def __init__(self, contamination: float = 0.15):
        self.contamination = contamination

    @classmethod
    def encode_feature_vector(
        cls,
        session: ParsedEmailSession,
        cert: Optional[InspectedCertificate] = None,
    ) -> list[float]:
        """Encodes session and certificate characteristics into a numeric feature vector."""
        # 1. Protocol code
        p_up = session.protocol.upper()
        p_code = 1.0 if "SMTP" in p_up else (2.0 if "IMAP" in p_up else (3.0 if "POP3" in p_up else 0.0))

        # 2. TLS Version code
        tls_ver = str(session.tls_version or "").upper()
        if "1.3" in tls_ver:
            tls_code = 4.0
        elif "1.2" in tls_ver:
            tls_code = 3.0
        elif "1.1" in tls_ver:
            tls_code = 2.0
        elif "1.0" in tls_ver or "SSL" in tls_ver:
            tls_code = 1.0
        else:
            tls_code = 0.0

        # 3. Cipher strength indicator
        cipher = str(session.cipher_suite or "").upper()
        if "GCM" in cipher or "CHACHA" in cipher:
            cipher_code = 3.0  # Modern AEAD
        elif "AES" in cipher or "CBC" in cipher:
            cipher_code = 2.0  # Legacy CBC
        elif any(w in cipher for w in ["3DES", "RC4", "DES", "NULL"]):
            cipher_code = 0.0  # Broken/weak
        else:
            cipher_code = 1.0  # Default / unclassified

        # 4. Key Exchange code
        kx = str(session.key_exchange or "").upper()
        kx_code = 2.0 if "ECDHE" in kx else (1.0 if "DHE" in kx else 0.0)

        # 5. Forward Secrecy
        fs_code = 1.0 if session.forward_secrecy else 0.0

        # 6. STARTTLS behavior
        mode = getattr(session, "encryption_mode", "UNKNOWN").upper()
        mode_code = 3.0 if "IMPLICIT" in mode else (2.0 if "UPGRADE" in mode else (1.0 if "PLAINTEXT" in mode else 0.0))

        # 7. Handshake completion status
        hs_status = str(getattr(session, "handshake_status", "Completed")).lower()
        hs_code = 2.0 if "completed" in hs_status else (1.0 if "incomplete" in hs_status else 0.0)

        # 8. Certificate properties
        if cert:
            key_size = float(cert.key_size or 2048) / 4096.0
            is_expired = 1.0 if cert.is_expired else 0.0
            is_self_signed = 1.0 if cert.is_self_signed else 0.0
        else:
            key_size = 0.5
            is_expired = 0.0
            is_self_signed = 0.0

        # 9. Packet and volume dynamics
        pkt_cnt = float(min(session.packet_count, 500)) / 500.0
        byte_cnt = float(min(session.byte_count, 100000)) / 100000.0
        duration = float(min(session.duration_ms, 30000)) / 30000.0

        return [
            p_code,
            tls_code,
            cipher_code,
            kx_code,
            fs_code,
            mode_code,
            hs_code,
            key_size,
            is_expired,
            is_self_signed,
            pkt_cnt,
            byte_cnt,
            duration,
        ]

    def fit_and_score(
        self,
        sessions: list[ParsedEmailSession],
        cert_map: Optional[dict[str, list[InspectedCertificate]]] = None,
    ) -> None:
        """
        Extracts multi-dimensional features and scores anomalies using scikit-learn IsolationForest.
        Annotates sessions with anomaly_score, anomaly_status, risk_priority, and explanation.
        """
        if not sessions:
            return

        # Reference baseline vectors to anchor the Isolation Forest even with small captures
        # Baseline normal: modern TLS 1.3/1.2 ECDHE AES-GCM
        synthetic_baseline = [
            [1.0, 4.0, 3.0, 2.0, 1.0, 3.0, 2.0, 0.5, 0.0, 0.0, 0.05, 0.05, 0.02],
            [1.0, 3.0, 3.0, 2.0, 1.0, 2.0, 2.0, 0.5, 0.0, 0.0, 0.08, 0.08, 0.05],
            [2.0, 4.0, 3.0, 2.0, 1.0, 3.0, 2.0, 0.5, 0.0, 0.0, 0.04, 0.04, 0.01],
            [3.0, 4.0, 3.0, 2.0, 1.0, 3.0, 2.0, 0.5, 0.0, 0.0, 0.06, 0.06, 0.03],
        ]

        vectors = []
        for s in sessions:
            cert = None
            if cert_map and s.session_id in cert_map and cert_map[s.session_id]:
                cert = cert_map[s.session_id][0]
            v = self.encode_feature_vector(s, cert)
            vectors.append(v)

        X_train = np.array(synthetic_baseline + vectors, dtype=float)
        X_target = np.array(vectors, dtype=float)

        try:
            clf = IsolationForest(
                n_estimators=100,
                contamination=self.contamination,
                random_state=42,
            )
            clf.fit(X_train)
            decision_scores = clf.decision_function(X_target)  # higher is normal, lower is anomalous
            preds = clf.predict(X_target)                     # -1 is anomalous, 1 is normal

            # Score normalization: 0.0 (normal) to 1.0 (highly anomalous)
            for i, s in enumerate(sessions):
                raw_s = float(decision_scores[i])
                # Logistic sigmoid style mapping: lower decision function -> higher anomaly score
                anomaly_score = round(float(1.0 / (1.0 + np.exp(raw_s * 5.0))), 4)
                is_anom = preds[i] == -1 or anomaly_score > 0.60

                s.anomaly_score = anomaly_score
                s.is_anomalous = is_anom
                s.anomaly_status = "ANOMALOUS" if is_anom else "NORMAL"

                # Formulate dynamic contextual explanation
                reasons = []
                if not s.is_encrypted and s.protocol != "UNKNOWN":
                    reasons.append("Unencrypted plaintext transport")
                if s.tls_version in {"TLS 1.0", "TLS 1.1", "SSL 3.0"}:
                    reasons.append(f"Observed legacy protocol version ({s.tls_version})")
                if s.cipher_suite and any(w in s.cipher_suite.upper() for w in ["RC4", "3DES", "NULL"]):
                    reasons.append(f"Observed weak cipher suite ({s.cipher_suite})")
                if not s.forward_secrecy and s.is_encrypted:
                    reasons.append("Absence of Perfect Forward Secrecy (PFS)")
                if getattr(s, "starttls_supported", False) and not s.is_encrypted:
                    reasons.append("STARTTLS capability advertised but unencrypted session maintained")
                if getattr(s, "tls_alerts", []):
                    reasons.append("Handshake alert record encountered")
                if s.is_anomalous and not reasons:
                    reasons.append("Statistical deviation in packet volume, timing, or protocol sequencing")

                s.anomaly_explanation = "; ".join(reasons) if reasons else "Parameters consistent with expected baseline."

                # Risk prioritization
                if is_anom and ("Unencrypted plaintext" in s.anomaly_explanation or "legacy protocol" in s.anomaly_explanation):
                    s.risk_priority = "HIGH"
                elif is_anom:
                    s.risk_priority = "MEDIUM"
                elif reasons:
                    s.risk_priority = "LOW"
                else:
                    s.risk_priority = "INFORMATIONAL"

        except Exception:
            for s in sessions:
                s.anomaly_score = 0.0
                s.is_anomalous = False
                s.anomaly_status = "BASELINE"
                s.risk_priority = "INFORMATIONAL"
                s.anomaly_explanation = "Baseline profile active."
