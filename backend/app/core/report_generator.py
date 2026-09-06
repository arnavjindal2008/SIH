import datetime
import io
import json
from pathlib import Path
from typing import Any

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

class ReportGenerator:
    """Generates enterprise forensic reports in JSON, HTML, and PDF formats."""

    @staticmethod
    def generate_json_report(analysis_dict: dict[str, Any]) -> str:
        return json.dumps(analysis_dict, indent=2, default=str)

    @staticmethod
    def generate_html_report(data: dict[str, Any]) -> str:
        analysis = data.get("analysis", {})
        findings = data.get("findings", [])
        sessions = data.get("sessions", [])
        certs = data.get("certificates", [])
        recs = data.get("recommendations", [])

        # Finding rows
        finding_rows = ""
        for f in findings:
            sev = f.get("severity", "INFO")
            color_map = {
                "CRITICAL": "#ef4444",
                "HIGH": "#f97316",
                "MEDIUM": "#eab308",
                "LOW": "#3b82f6",
                "INFO": "#64748b",
            }
            color = color_map.get(sev, "#64748b")
            finding_rows += f"""
            <tr style="border-bottom: 1px solid #1e293b;">
                <td style="padding: 12px 16px;"><span style="background: {color}22; color: {color}; border: 1px solid {color}55; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 11px;">{sev}</span></td>
                <td style="padding: 12px 16px; font-weight: 600; color: #f1f5f9;">{f.get('title')}</td>
                <td style="padding: 12px 16px; color: #94a3b8; font-size: 13px;">{f.get('description')}</td>
                <td style="padding: 12px 16px; color: #38bdf8; font-family: monospace; font-size: 12px;">{f.get('rfc_reference') or 'N/A'}</td>
                <td style="padding: 12px 16px; color: #cbd5e1; font-size: 12px;">{f.get('remediation')}</td>
            </tr>
            """

        # Session rows
        session_rows = ""
        for s in sessions[:30]:
            enc_badge = '<span style="color:#10b981;">Encrypted</span>' if s.get('is_encrypted') else '<span style="color:#ef4444;">Plaintext</span>'
            session_rows += f"""
            <tr style="border-bottom: 1px solid #1e293b;">
                <td style="padding: 10px 14px; font-family: monospace; color: #38bdf8;">{s.get('protocol')}</td>
                <td style="padding: 10px 14px; font-family: monospace; color: #94a3b8;">{s.get('src_ip')}:{s.get('src_port')} &rarr; {s.get('dst_ip')}:{s.get('dst_port')}</td>
                <td style="padding: 10px 14px;">{enc_badge}</td>
                <td style="padding: 10px 14px; font-family: monospace; color: #cbd5e1;">{s.get('tls_version') or 'None'}</td>
                <td style="padding: 10px 14px; font-family: monospace; font-size: 11px; color: #64748b;">{s.get('cipher_suite') or 'N/A'}</td>
                <td style="padding: 10px 14px; text-align: right; color: #94a3b8;">{s.get('packet_count')}</td>
            </tr>
            """

        score = analysis.get("security_score")
        score_display = f"{score}/100" if score is not None else "N/A"
        score_color = "#10b981" if (score or 0) >= 80 else ("#eab308" if (score or 0) >= 50 else "#ef4444")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Forensic Security Audit: {analysis.get('filename')}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background-color: #090d16;
            color: #e2e8f0;
            margin: 0;
            padding: 32px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            border-bottom: 1px solid #1e293b;
            padding-bottom: 24px;
            margin-bottom: 32px;
        }}
        .title {{
            font-size: 26px;
            font-weight: 700;
            color: #f8fafc;
            margin: 0 0 6px 0;
        }}
        .subtitle {{
            font-size: 14px;
            color: #64748b;
            margin: 0;
        }}
        .score-box {{
            background: #111827;
            border: 1px solid #1e293b;
            border-radius: 8px;
            padding: 16px 24px;
            text-align: center;
        }}
        .score-val {{
            font-size: 32px;
            font-weight: 800;
            color: {score_color};
            margin-bottom: 4px;
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 32px;
        }}
        .card {{
            background: #111827;
            border: 1px solid #1e293b;
            border-radius: 8px;
            padding: 20px;
        }}
        .card-label {{
            font-size: 12px;
            color: #64748b;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 8px;
        }}
        .card-val {{
            font-size: 22px;
            font-weight: 700;
            color: #f1f5f9;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            margin-bottom: 32px;
            background: #111827;
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid #1e293b;
        }}
        th {{
            background: #161f30;
            color: #94a3b8;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            padding: 12px 16px;
        }}
        .section-title {{
            font-size: 18px;
            font-weight: 600;
            color: #f1f5f9;
            margin: 32px 0 16px 0;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1 class="title">Email Cryptographic Forensic Report</h1>
                <p class="subtitle">Smart India Hackathon &bull; Passive PCAP Security Analysis &bull; File: <strong>{analysis.get('filename')}</strong></p>
                <p class="subtitle" style="margin-top: 4px;">SHA-256: <code style="color: #38bdf8;">{analysis.get('sha256_hash')}</code></p>
            </div>
            <div class="score-box">
                <div class="score-val">{score_display}</div>
                <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase;">Cryptographic Score</div>
            </div>
        </div>

        <div class="grid">
            <div class="card">
                <div class="card-label">Total Packets</div>
                <div class="card-val">{analysis.get('total_packets', 0):,}</div>
            </div>
            <div class="card">
                <div class="card-label">Email Sessions</div>
                <div class="card-val">{analysis.get('session_count', 0)}</div>
            </div>
            <div class="card">
                <div class="card-label">Security Findings</div>
                <div class="card-val" style="color: {'#ef4444' if (analysis.get('finding_count', 0) > 0) else '#10b981'};">{analysis.get('finding_count', 0)}</div>
            </div>
            <div class="card">
                <div class="card-label">Encryption Ratio</div>
                <div class="card-val">{int((analysis.get('encryption_ratio', 0.0)) * 100)}%</div>
            </div>
        </div>

        <h2 class="section-title">Cryptographic Security Findings ({len(findings)})</h2>
        {'<p style="color: #64748b; font-style: italic;">No security vulnerabilities or cryptographic compliance defects detected in analyzed email sessions.</p>' if not findings else f'''
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Vulnerability Title</th>
                    <th>Description</th>
                    <th>Standard</th>
                    <th>Remediation Guidance</th>
                </tr>
            </thead>
            <tbody>
                {finding_rows}
            </tbody>
        </table>
        '''}

        <h2 class="section-title">Analyzed Forensic Sessions ({len(sessions)})</h2>
        {'<p style="color: #64748b; font-style: italic;">No email communication sessions recorded in this capture.</p>' if not sessions else f'''
        <table>
            <thead>
                <tr>
                    <th>Protocol</th>
                    <th>Stream (Src &rarr; Dst)</th>
                    <th>Security</th>
                    <th>TLS Version</th>
                    <th>Cipher Suite</th>
                    <th style="text-align: right;">Packets</th>
                </tr>
            </thead>
            <tbody>
                {session_rows}
            </tbody>
        </table>
        '''}

        <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #1e293b; color: #475569; font-size: 12px; display: flex; justify-content: space-between;">
            <span>Generated by Enterprise Email Cryptographic Security Analyzer</span>
            <span>{datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</span>
        </div>
    </div>
</body>
</html>
"""
        return html

    @staticmethod
    def generate_pdf_report(data: dict[str, Any]) -> bytes:
        """Generates a downloadable PDF audit report."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'DocTitle',
            parent=styles['Heading1'],
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#0f172a"),
            fontName="Helvetica-Bold",
        )
        sub_style = ParagraphStyle(
            'DocSub',
            parent=styles['Normal'],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#475569"),
        )
        h2_style = ParagraphStyle(
            'Heading2Custom',
            parent=styles['Heading2'],
            fontSize=13,
            leading=16,
            textColor=colors.HexColor("#1e293b"),
            spaceBefore=14,
            spaceAfter=6,
            fontName="Helvetica-Bold",
        )
        body_style = ParagraphStyle(
            'BodyCustom',
            parent=styles['Normal'],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#334155"),
        )

        analysis = data.get("analysis", {})
        findings = data.get("findings", [])

        elements = []

        # Header
        elements.append(Paragraph("Email Cryptographic Security Analyzer - Forensic Report", title_style))
        elements.append(Paragraph(f"File: <b>{analysis.get('filename')}</b> | SHA-256: {analysis.get('sha256_hash')[:32]}...", sub_style))
        elements.append(Paragraph(f"Generated: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | Status: {analysis.get('status')}", sub_style))
        elements.append(Spacer(1, 10))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceBefore=5, spaceAfter=15))

        # Metrics Table
        metrics_data = [
            ["Security Score", "Total Packets", "Email Sessions", "Findings", "Encryption Ratio"],
            [
                f"{analysis.get('security_score', 'N/A')}/100",
                str(analysis.get('total_packets', 0)),
                str(analysis.get('session_count', 0)),
                str(analysis.get('finding_count', 0)),
                f"{int(analysis.get('encryption_ratio', 0) * 100)}%",
            ]
        ]
        t_metrics = Table(metrics_data, colWidths=[105, 105, 105, 105, 110])
        t_metrics.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor("#475569")),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ]))
        elements.append(t_metrics)
        elements.append(Spacer(1, 15))

        # Findings Section
        elements.append(Paragraph("Cryptographic Security Findings", h2_style))
        if not findings:
            elements.append(Paragraph("No security vulnerabilities identified in the analyzed PCAP sessions.", body_style))
        else:
            findings_table_data = [["Severity", "Title", "Standard", "Remediation Summary"]]
            for f in findings[:15]:
                findings_table_data.append([
                    f.get("severity", "INFO"),
                    Paragraph(f.get("title", ""), body_style),
                    f.get("rfc_reference") or "N/A",
                    Paragraph(f.get("remediation", "")[:120] + "...", body_style),
                ])
            t_find = Table(findings_table_data, colWidths=[65, 160, 95, 215])
            t_find.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ]))
            elements.append(t_find)

        doc.build(elements)
        buffer.seek(0)
        return buffer.getvalue()
