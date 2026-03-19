"""PDF report generation utilities for recon scan outputs."""

import json
import os
from typing import Any, Dict, Iterable, List


def _is_primitive(value: Any) -> bool:
    return isinstance(value, (str, int, float, bool)) or value is None


def _to_pretty_json(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False, default=str)


def _table_from_dict(data: Dict[str, Any], include_header: bool = True) -> List[List[str]]:
    rows: List[List[str]] = []
    if include_header:
        rows.append(["Field", "Value"])
    for key, value in data.items():
        if isinstance(value, (dict, list)):
            rows.append([str(key), _to_pretty_json(value)])
        else:
            rows.append([str(key), str(value)])
    return rows


def generate_pdf_report(scan_data, filename):
    """Generate a professional PDF report from scan result payload."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            PageBreak,
            Paragraph,
            Preformatted,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:
        raise RuntimeError(
            "reportlab is required for PDF export. Install it with: pip install reportlab"
        ) from exc

    if not isinstance(scan_data, dict):
        raise RuntimeError("scan_data must be a dictionary.")
    if not filename:
        raise RuntimeError("filename is required for PDF export.")

    output_dir = os.path.dirname(os.path.abspath(filename))
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    data = scan_data.get("data", {}) if isinstance(scan_data.get("data"), dict) else {}
    target = data.get("target", "Unknown")
    report_time = scan_data.get("scan_datetime", "Unknown")
    status = str(scan_data.get("status", "unknown")).upper()

    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        leftMargin=0.65 * inch,
        rightMargin=0.65 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.65 * inch,
    )

    styles = getSampleStyleSheet()
    section_style = ParagraphStyle(
        name="SectionHeader",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#0B3D91"),
        spaceAfter=8,
        spaceBefore=8,
    )
    code_style = ParagraphStyle(
        name="CodeBlock",
        parent=styles["Code"],
        fontName="Courier",
        fontSize=8,
        leading=10,
    )

    story: List[Any] = []

    story.append(Paragraph("Cybersecurity Reconnaissance Report", styles["Title"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph(f"<b>Target:</b> {target}", styles["Normal"]))
    story.append(Paragraph(f"<b>Scan Date/Time:</b> {report_time}", styles["Normal"]))
    story.append(Paragraph(f"<b>Scan Status:</b> {status}", styles["Normal"]))
    story.append(Spacer(1, 12))

    metadata_rows = _table_from_dict(
        {
            "URL": data.get("url", "N/A"),
            "Selected Scan Types": data.get("selected_scan_types", []),
            "Executed Scan Types": data.get("executed_scan_types", []),
        }
    )
    metadata_table = Table(metadata_rows, colWidths=[2.1 * inch, 4.4 * inch], repeatRows=1)
    metadata_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#D9E2F3")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(metadata_table)
    story.append(Spacer(1, 12))

    executive_summary = data.get("executive_summary", {})
    if isinstance(executive_summary, dict) and executive_summary:
        story.append(Paragraph("Risk Summary", section_style))
        risk_rows = _table_from_dict(
            {
                "Attack Surface Score": executive_summary.get("attack_surface_score", "N/A"),
                "Overall Risk": executive_summary.get("overall_risk", "N/A"),
                "Confidence": executive_summary.get("confidence", "N/A"),
                "Key Findings": executive_summary.get("key_findings", []),
            }
        )
        risk_table = Table(risk_rows, colWidths=[2.1 * inch, 4.4 * inch], repeatRows=1)
        risk_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#FCE4D6")),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(risk_table)
        story.append(Spacer(1, 10))

    sections = [
        ("Executive Summary", data.get("executive_summary", {})),
        ("Service Detection", data.get("nmap", {})),
        ("SSL Information", data.get("ssl", {})),
        ("OSINT Intelligence", data.get("osint", {})),
        ("Subdomains", data.get("subdomains", [])),
        ("Headers Analysis", data.get("headers", {})),
        ("Technology Fingerprinting", data.get("technology", {})),
        (
            "Hosting / CDN Distinction",
            {
                "hosting_provider": data.get("hosting_provider"),
                "cdn_provider": data.get("cdn_provider"),
                "waf_provider": data.get("waf_provider"),
            },
        ),
    ]

    section_count = 0
    for title, payload in sections:
        if not payload:
            continue

        section_count += 1
        if section_count > 1 and section_count % 3 == 0:
            story.append(PageBreak())

        story.append(Paragraph(title, section_style))

        if isinstance(payload, dict) and payload and all(_is_primitive(v) for v in payload.values()):
            detail_rows = _table_from_dict(payload)
            detail_table = Table(detail_rows, colWidths=[2.1 * inch, 4.4 * inch], repeatRows=1)
            detail_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2F0D9")),
                        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]
                )
            )
            story.append(detail_table)
        else:
            story.append(Preformatted(_to_pretty_json(payload), code_style))
        story.append(Spacer(1, 8))

    doc.build(story)
