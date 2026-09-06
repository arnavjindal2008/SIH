import asyncio
import os
import tempfile
import pytest
from httpx import AsyncClient, ASGITransport
from scapy.utils import wrpcap
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from backend.app.main import app
from backend.app.database import init_db
from backend.app.core.protocol_identifier import ProtocolIdentifier
from backend.app.core.packet_parser import PcapParserEngine

def test_protocol_identifier_smtp_banners_and_commands():
    # Test standard SMTP banner and EHLO
    payloads = [
        b"220 mail.corp.internal ESMTP Postfix (Ubuntu)\r\n",
        b"EHLO workstation.corp\r\n",
        b"250-mail.corp.internal\r\n250 STARTTLS\r\n",
    ]
    res = ProtocolIdentifier.classify_stream(payloads, 50001, 25)
    assert res.protocol == "SMTP"
    assert res.is_email is True
    assert res.confidence >= 0.8
    assert any("SMTP greeting banner" in ev or "Server 220 banner" in ev for ev in res.evidence)

def test_protocol_identifier_smtp_on_nonstandard_port():
    # Test SMTP running on non-standard port 2525
    payloads = [
        b"220 custom-relay.net ESMTP ready\r\n",
        b"HELO app.backend.local\r\n",
        b"250 Ok\r\n",
        b"MAIL FROM:<alerts@corp.net>\r\n",
    ]
    res = ProtocolIdentifier.classify_stream(payloads, 44211, 2525)
    assert res.protocol == "SMTP"
    assert res.is_email is True
    assert any("SMTP command" in ev or "SMTP greeting banner" in ev for ev in res.evidence)

def test_protocol_identifier_imap_banners_and_commands():
    # Test IMAP banner and tagged command
    payloads = [
        b"* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR] Dovecot ready.\r\n",
        b"A001 CAPABILITY\r\n",
        b"* CAPABILITY IMAP4rev1 IDLE STARTTLS\r\n",
        b"A001 OK Capability completed\r\n",
        b"A002 LOGIN user@corp.net MySecretPass123\r\n",
    ]
    res = ProtocolIdentifier.classify_stream(payloads, 51000, 143)
    assert res.protocol == "IMAP"
    assert res.is_email is True
    assert res.confidence >= 0.8
    assert any("IMAP greeting banner" in ev for ev in res.evidence)

def test_protocol_identifier_imap_on_nonstandard_port():
    # Test IMAP running on non-standard port 10143
    payloads = [
        b"* OK IMAP4rev1 Server Ready\r\n",
        b"tag1 LOGIN test pass\r\n",
        b"tag1 OK Logged in\r\n",
        b"tag2 SELECT INBOX\r\n",
    ]
    res = ProtocolIdentifier.classify_stream(payloads, 52000, 10143)
    assert res.protocol == "IMAP"
    assert res.is_email is True

def test_protocol_identifier_pop3_banners_and_commands():
    # Test POP3 banner and commands
    payloads = [
        b"+OK Dovecot POP3 ready.\r\n",
        b"USER testuser\r\n",
        b"+OK send password\r\n",
        b"PASS secret99\r\n",
        b"+OK Logged in.\r\n",
        b"STAT\r\n",
        b"+OK 2 3200\r\n",
    ]
    res = ProtocolIdentifier.classify_stream(payloads, 53000, 110)
    assert res.protocol == "POP3"
    assert res.is_email is True
    assert any("POP3 greeting banner" in ev for ev in res.evidence)
    assert any("POP3 command" in ev for ev in res.evidence)

def test_protocol_identifier_pop3_on_nonstandard_port():
    # Test POP3 on non-standard port 11000
    payloads = [
        b"+OK POP3 service ready\r\n",
        b"USER auditor\r\n",
        b"PASS pass123\r\n",
        b"LIST\r\n",
        b"+OK 0 messages\r\n",
    ]
    res = ProtocolIdentifier.classify_stream(payloads, 54000, 11000)
    assert res.protocol == "POP3"
    assert res.is_email is True

def test_arbitrary_tcp_classified_as_unknown():
    # HTTP traffic on port 80
    http_payloads = [
        b"GET /api/v1/health HTTP/1.1\r\nHost: api.internal\r\nAccept: */*\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}",
    ]
    res_http = ProtocolIdentifier.classify_stream(http_payloads, 40000, 80)
    assert res_http.protocol == "UNKNOWN"
    assert res_http.is_email is False
    assert any("HTTP" in ev for ev in res_http.evidence)

    # SSH traffic on port 22
    ssh_payloads = [
        b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n",
    ]
    res_ssh = ProtocolIdentifier.classify_stream(ssh_payloads, 40001, 22)
    assert res_ssh.protocol == "UNKNOWN"
    assert res_ssh.is_email is False
    assert any("SSH" in ev for ev in res_ssh.evidence)

    # Arbitrary binary on arbitrary port
    bin_payloads = [
        b"\x00\x01\x02\x03\xff\xfe\xfd\xaa\xbb\xcc\xdd",
    ]
    res_bin = ProtocolIdentifier.classify_stream(bin_payloads, 40002, 9999)
    assert res_bin.protocol == "UNKNOWN"
    assert res_bin.is_email is False

def test_no_false_classification_on_port_25():
    # Port 25 sending HTTP requests (e.g. attacker or scanner) must NOT be classified as SMTP
    bogus_payloads = [
        b"GET /admin/setup HTTP/1.1\r\nHost: target\r\n\r\n",
    ]
    res = ProtocolIdentifier.classify_stream(bogus_payloads, 40003, 25)
    assert res.protocol == "UNKNOWN"
    assert res.is_email is False

    # Port 25 with 0 payload (e.g. port scan TCP SYN only) must be UNKNOWN
    empty_res = ProtocolIdentifier.classify_stream([], 40004, 25)
    assert empty_res.protocol == "UNKNOWN"
    assert empty_res.is_email is False


def test_full_pcap_analysis_with_all_protocols_and_filtering():
    async def _run():
        await init_db()

        # Build multi-protocol PCAP containing SMTP, IMAP, POP3, and UNKNOWN streams
        pkts = []

        # Stream 0: Plaintext SMTP (Port 25)
        pkts.append(Ether()/IP(src="192.168.1.10", dst="10.0.0.25")/TCP(sport=50001, dport=25, flags="S", seq=100))
        pkts.append(Ether()/IP(src="10.0.0.25", dst="192.168.1.10")/TCP(sport=25, dport=50001, flags="SA", seq=200, ack=101))
        pkts.append(Ether()/IP(src="10.0.0.25", dst="192.168.1.10")/TCP(sport=25, dport=50001, flags="PA", seq=201, ack=101)/Raw(b"220 mail.corp.net ESMTP Postfix\r\n"))
        pkts.append(Ether()/IP(src="192.168.1.10", dst="10.0.0.25")/TCP(sport=50001, dport=25, flags="PA", seq=101, ack=234)/Raw(b"EHLO client.corp.net\r\n"))

        # Stream 1: Plaintext POP3 (Port 110)
        pkts.append(Ether()/IP(src="192.168.1.20", dst="10.0.0.110")/TCP(sport=50002, dport=110, flags="S", seq=300))
        pkts.append(Ether()/IP(src="10.0.0.110", dst="192.168.1.20")/TCP(sport=110, dport=50002, flags="SA", seq=400, ack=301))
        pkts.append(Ether()/IP(src="10.0.0.110", dst="192.168.1.20")/TCP(sport=110, dport=50002, flags="PA", seq=401, ack=301)/Raw(b"+OK POP3 server ready\r\n"))
        pkts.append(Ether()/IP(src="192.168.1.20", dst="10.0.0.110")/TCP(sport=50002, dport=110, flags="PA", seq=301, ack=424)/Raw(b"USER employee1\r\n"))

        # Stream 2: Plaintext IMAP (Port 143)
        pkts.append(Ether()/IP(src="192.168.1.30", dst="10.0.0.143")/TCP(sport=50003, dport=143, flags="S", seq=500))
        pkts.append(Ether()/IP(src="10.0.0.143", dst="192.168.1.30")/TCP(sport=143, dport=50003, flags="SA", seq=600, ack=501))
        pkts.append(Ether()/IP(src="10.0.0.143", dst="192.168.1.30")/TCP(sport=143, dport=50003, flags="PA", seq=601, ack=501)/Raw(b"* OK [CAPABILITY IMAP4rev1] Dovecot ready\r\n"))
        pkts.append(Ether()/IP(src="192.168.1.30", dst="10.0.0.143")/TCP(sport=50003, dport=143, flags="PA", seq=501, ack=642)/Raw(b"A01 CAPABILITY\r\n"))

        # Stream 3: Arbitrary HTTP traffic (Port 80) -> UNKNOWN
        pkts.append(Ether()/IP(src="192.168.1.40", dst="10.0.0.80")/TCP(sport=50004, dport=80, flags="S", seq=700))
        pkts.append(Ether()/IP(src="10.0.0.80", dst="192.168.1.40")/TCP(sport=80, dport=50004, flags="SA", seq=800, ack=701))
        pkts.append(Ether()/IP(src="192.168.1.40", dst="10.0.0.80")/TCP(sport=50004, dport=80, flags="PA", seq=701, ack=801)/Raw(b"GET /index.html HTTP/1.1\r\nHost: web.internal\r\n\r\n"))

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            pcap_path = f.name
        wrpcap(pcap_path, pkts)

        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                with open(pcap_path, "rb") as f:
                    resp = await ac.post(
                        "/api/analyze",
                        files={"file": ("multi_proto_test.pcap", f, "application/vnd.tcpdump.pcap")}
                    )
                assert resp.status_code == 200, f"Analysis failed: {resp.text}"
                analysis = resp.json()
                analysis_id = analysis["id"]
                assert analysis["tcp_stream_count"] == 4
                assert analysis["session_count"] == 4

                # Retrieve all sessions
                resp_sess = await ac.get(f"/api/analysis/{analysis_id}/sessions")
                assert resp_sess.status_code == 200
                sessions = resp_sess.json()
                assert len(sessions) == 4

                # Check all required session fields
                for s in sessions:
                    assert "session_id" in s or "id" in s
                    assert s["analysis_id"] == analysis_id
                    assert s["protocol"] in ["SMTP", "IMAP", "POP3", "UNKNOWN"]
                    assert "source_ip" in s or "src_ip" in s
                    assert "source_port" in s or "src_port" in s
                    assert "destination_ip" in s or "dst_ip" in s
                    assert "destination_port" in s or "dst_port" in s
                    assert s["transport_protocol"] == "TCP"
                    assert s["packet_count"] > 0
                    assert s["first_seen"] is not None
                    assert s["last_seen"] is not None
                    assert "tcp_stream_id" in s

                protocols_detected = {s["protocol"] for s in sessions}
                assert "SMTP" in protocols_detected
                assert "IMAP" in protocols_detected
                assert "POP3" in protocols_detected
                assert "UNKNOWN" in protocols_detected

                # Test filtering by SMTP
                resp_smtp = await ac.get(f"/api/analysis/{analysis_id}/sessions?protocol=SMTP")
                assert resp_smtp.status_code == 200
                smtp_sessions = resp_smtp.json()
                assert len(smtp_sessions) == 1
                assert smtp_sessions[0]["protocol"] == "SMTP"

                # Test filtering by IMAP
                resp_imap = await ac.get(f"/api/analysis/{analysis_id}/sessions?protocol=IMAP")
                assert resp_imap.status_code == 200
                imap_sessions = resp_imap.json()
                assert len(imap_sessions) == 1
                assert imap_sessions[0]["protocol"] == "IMAP"

                # Test filtering by POP3
                resp_pop3 = await ac.get(f"/api/analysis/{analysis_id}/sessions?protocol=POP3")
                assert resp_pop3.status_code == 200
                pop3_sessions = resp_pop3.json()
                assert len(pop3_sessions) == 1
                assert pop3_sessions[0]["protocol"] == "POP3"

                # Test filtering by UNKNOWN
                resp_unk = await ac.get(f"/api/analysis/{analysis_id}/sessions?protocol=UNKNOWN")
                assert resp_unk.status_code == 200
                unk_sessions = resp_unk.json()
                assert len(unk_sessions) == 1
                assert unk_sessions[0]["protocol"] == "UNKNOWN"

        finally:
            if os.path.exists(pcap_path):
                os.remove(pcap_path)

    asyncio.run(_run())
