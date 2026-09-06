import asyncio
import os
import pytest
from httpx import AsyncClient, ASGITransport
from backend.app.main import app
from backend.app.database import init_db
from backend.app.config import settings
from tests.generate_test_pcap import create_sample_email_pcap

def test_full_analysis_lifecycle():
    async def _run():
        await init_db()
        sample_path = settings.SAMPLES_DIR / "test_api_pcap.pcap"
        create_sample_email_pcap(str(sample_path))

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            # 1. Upload/Analyze PCAP
            with open(sample_path, "rb") as f:
                resp = await ac.post(
                    "/api/analyze",
                    files={"file": ("test_api_pcap.pcap", f, "application/vnd.tcpdump.pcap")}
                )
            assert resp.status_code == 200, f"Upload failed: {resp.text}"
            analysis = resp.json()
            analysis_id = analysis["id"]
            assert analysis["status"] == "COMPLETED"
            assert analysis["session_count"] >= 2
            assert analysis["total_packets"] > 0

            # 2. Get Analysis Detail
            resp = await ac.get(f"/api/analysis/{analysis_id}")
            assert resp.status_code == 200
            detail = resp.json()
            assert detail["id"] == analysis_id
            assert "severity_breakdown" in detail

            # 3. Get Sessions
            resp = await ac.get(f"/api/analysis/{analysis_id}/sessions")
            assert resp.status_code == 200
            sessions = resp.json()
            assert len(sessions) >= 2

            # 4. Get Findings & verify Phase 6 enriched fields and filtering
            resp = await ac.get(f"/api/analysis/{analysis_id}/findings")
            assert resp.status_code == 200
            findings = resp.json()
            assert len(findings) > 0
            # Phase 6 enriched finding fields
            first_f = findings[0]
            assert "status" in first_f
            assert first_f["status"] == "DETECTED"
            assert "risk" in first_f

            # Test filtering by protocol and severity
            resp_filtered = await ac.get(f"/api/analysis/{analysis_id}/findings?severity=CRITICAL")
            assert resp_filtered.status_code == 200

            resp_proto = await ac.get(f"/api/analysis/{analysis_id}/findings?protocol=SMTP")
            assert resp_proto.status_code == 200

            # 5. Get Protocols
            resp = await ac.get(f"/api/analysis/{analysis_id}/protocols")
            assert resp.status_code == 200
            protocols_data = resp.json()
            assert len(protocols_data["protocols"]) > 0

            # 6. Get Recommendations & verify Phase 6 fields
            resp = await ac.get(f"/api/analysis/{analysis_id}/recommendations")
            assert resp.status_code == 200
            recs = resp.json()
            assert recs["total_recommendations"] > 0
            first_rec = recs["recommendations"][0]
            assert "priority" in first_rec
            assert "finding" in first_rec
            assert "recommended_action" in first_rec
            assert "reason" in first_rec
            assert "affected_sessions" in first_rec

            # 7. Test Exports
            # JSON export
            resp = await ac.get(f"/api/analysis/{analysis_id}/export/json")
            assert resp.status_code == 200
            assert "application/json" in resp.headers["content-type"]

            # HTML export
            resp = await ac.get(f"/api/analysis/{analysis_id}/export/html")
            assert resp.status_code == 200
            assert "text/html" in resp.headers["content-type"]
            assert "Email Cryptographic Forensic Report" in resp.text

            # PDF export
            resp = await ac.get(f"/api/analysis/{analysis_id}/export/pdf")
            assert resp.status_code == 200
            assert "application/pdf" in resp.headers["content-type"]
            assert resp.content.startswith(b"%PDF")

    asyncio.run(_run())
