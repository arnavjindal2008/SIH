import asyncio
import os
import tempfile
import pytest
from httpx import AsyncClient, ASGITransport
from scapy.utils import PcapNgWriter
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from backend.app.main import app
from backend.app.database import init_db
from backend.app.config import settings
from tests.generate_test_pcap import create_sample_email_pcap

def test_reject_empty_file():
    async def _run():
        await init_db()
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            empty_path = f.name

        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                with open(empty_path, "rb") as f:
                    resp = await ac.post(
                        "/api/analyze",
                        files={"file": ("empty.pcap", f, "application/vnd.tcpdump.pcap")}
                    )
                assert resp.status_code == 400
                data = resp.json()
                assert "empty (0 bytes)" in data["detail"].lower()
        finally:
            if os.path.exists(empty_path):
                os.remove(empty_path)

    asyncio.run(_run())

def test_reject_corrupted_pcap():
    async def _run():
        await init_db()
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            f.write(b"CORRUPTED_GARBAGE_PAYLOAD_NOT_A_PCAP_FILE_AT_ALL")
            corrupt_path = f.name

        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                with open(corrupt_path, "rb") as f:
                    resp = await ac.post(
                        "/api/analyze",
                        files={"file": ("corrupt.pcap", f, "application/vnd.tcpdump.pcap")}
                    )
                assert resp.status_code == 400
                data = resp.json()
                assert "unsupported or corrupted" in data["detail"].lower() or "signature" in data["detail"].lower()
        finally:
            if os.path.exists(corrupt_path):
                os.remove(corrupt_path)

    asyncio.run(_run())

def test_reject_unsupported_format():
    async def _run():
        await init_db()
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"Hello World text file")
            txt_path = f.name

        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                with open(txt_path, "rb") as f:
                    resp = await ac.post(
                        "/api/analyze",
                        files={"file": ("test.txt", f, "text/plain")}
                    )
                assert resp.status_code == 400
                data = resp.json()
                assert "unsupported" in data["detail"].lower()
        finally:
            if os.path.exists(txt_path):
                os.remove(txt_path)

    asyncio.run(_run())

def test_preflight_validation_endpoint():
    async def _run():
        await init_db()
        sample_path = settings.SAMPLES_DIR / "sample_enterprise_email.pcap"
        if not sample_path.exists():
            create_sample_email_pcap(str(sample_path))

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            # Valid PCAP check
            with open(sample_path, "rb") as f:
                resp = await ac.post(
                    "/api/pcap/validate",
                    files={"file": ("sample.pcap", f, "application/vnd.tcpdump.pcap")}
                )
            assert resp.status_code == 200
            val_data = resp.json()
            assert val_data["is_valid"] is True
            assert val_data["format"] == "pcap"
            assert val_data["file_size"] > 0
            assert val_data["error"] is None

            # Empty file check via validation endpoint
            with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
                empty_path = f.name
            try:
                with open(empty_path, "rb") as f:
                    resp2 = await ac.post(
                        "/api/pcap/validate",
                        files={"file": ("empty.pcap", f, "application/vnd.tcpdump.pcap")}
                    )
                assert resp2.status_code == 200
                val_data2 = resp2.json()
                assert val_data2["is_valid"] is False
                assert "empty (0 bytes)" in val_data2["error"].lower()
            finally:
                if os.path.exists(empty_path):
                    os.remove(empty_path)

    asyncio.run(_run())

def test_accurate_counts_and_streams():
    async def _run():
        await init_db()
        sample_path = settings.SAMPLES_DIR / "sample_enterprise_email.pcap"
        if not sample_path.exists():
            create_sample_email_pcap(str(sample_path))

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            with open(sample_path, "rb") as f:
                resp = await ac.post(
                    "/api/analyze",
                    files={"file": ("sample.pcap", f, "application/vnd.tcpdump.pcap")}
                )
            assert resp.status_code == 200
            analysis = resp.json()
            # Verified real counts from PCAP:
            assert analysis["packet_count"] > 0
            assert analysis["ip_packet_count"] > 0
            assert analysis["tcp_packet_count"] > 0
            assert analysis["tcp_stream_count"] >= 2
            assert analysis["session_count"] >= 2
            assert analysis["file_size"] > 0
            assert analysis["status"] == "COMPLETED"

    asyncio.run(_run())

def test_pcapng_acceptance_and_stream_extraction():
    async def _run():
        await init_db()
        with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as f:
            ng_path = f.name

        try:
            writer = PcapNgWriter(ng_path)
            # Add 2 packets in 2 distinct TCP streams (port 25 and port 993)
            writer.write(Ether()/IP(src="10.0.1.10", dst="10.0.2.25")/TCP(sport=40001, dport=25)/Raw(b"220 mail.ng\r\n"))
            writer.write(Ether()/IP(src="10.0.1.20", dst="10.0.2.99")/TCP(sport=40002, dport=993)/Raw(b"\x16\x03\x03\x00\x05\x01\x00\x00\x01\x00"))
            writer.close()

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                with open(ng_path, "rb") as f:
                    resp = await ac.post(
                        "/api/analyze",
                        files={"file": ("capture.pcapng", f, "application/x-pcapng")}
                    )
                assert resp.status_code == 200, f"PCAPNG analysis failed: {resp.text}"
                data = resp.json()
                assert data["status"] == "COMPLETED"
                assert data["packet_count"] == 2
                assert data["ip_packet_count"] == 2
                assert data["tcp_packet_count"] == 2
                assert data["tcp_stream_count"] == 2
        finally:
            if os.path.exists(ng_path):
                os.remove(ng_path)

    asyncio.run(_run())
