"""
ENISA Reporter Module
Generates mock ENISA API submissions, PDF compliance artifacts,
CycloneDX SBOM exports, and CSV audit logs.
"""

from datetime import datetime
from io import BytesIO, StringIO
import base64
import uuid
import csv
import json

# ReportLab for PDF
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                    TableStyle, HRFlowable, KeepTogether)
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


def generate_enisa_submission_json(decision, cve, product_name, sbom_match, submission_id):
    """Generate mock ENISA submission JSON payload"""
    return {
        "submission_id": submission_id,
        "submission_type": "INITIAL_REPORT",
        "submitted_at": datetime.now().isoformat(),
        "manufacturer": "J-TEC Co., Ltd.",
        "product": product_name,
        "cve_id": cve["cve_id"],
        "vulnerability_description": cve["description"],
        "severity": cve["severity"],
        "cvss_score": cve["cvss_score"],
        "affected_component": sbom_match["matching_component"],
        "affected_version": sbom_match["component_version"],
        "vulnerable_version_range": f"{cve['affected_versions']['range_start']} - {cve['affected_versions']['range_end']}",
        "exploit_available": cve.get("exploit_available", False),
        "action_taken": decision["final_decision_type"],
        "supporting_evidence": {
            "sbom_match": sbom_match["match_reason"],
            "risk_assessment": f"CVSS {cve['cvss_score']} severity",
            "justification": decision["justification"]
        },
        "contact": "info@jtec.tokyo",
        "sla_deadline": "24 hours from submission"
    }


def generate_compliance_artifact_html(decision_id, cve, product_name, sbom_match, decision, audit_trail):
    """Generate HTML compliance artifact report"""
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>CRA Compliance Decision Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; color: #333; }}
            h1 {{ color: #003d82; border-bottom: 3px solid #003d82; padding-bottom: 10px; }}
            h2 {{ color: #005fa3; margin-top: 30px; }}
            .section {{ margin: 20px 0; padding: 15px; background: #f9f9f9; border-left: 4px solid #003d82; }}
            .header-info {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }}
            .info-box {{ padding: 10px; background: white; border: 1px solid #ddd; border-radius: 4px; }}
            .info-label {{ font-weight: bold; color: #005fa3; }}
            .decision-approve {{ color: green; font-weight: bold; }}
            .decision-report {{ color: red; font-weight: bold; }}
            .decision-notreport {{ color: orange; font-weight: bold; }}
            table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
            th, td {{ padding: 10px; text-align: left; border: 1px solid #ddd; }}
            th {{ background: #005fa3; color: white; }}
            tr:nth-child(even) {{ background: #f9f9f9; }}
            .rule {{ background: #e3f2fd; padding: 8px; margin: 5px 0; border-radius: 3px; }}
            .audit-log {{ font-size: 12px; background: #fafafa; padding: 10px; border-radius: 4px; max-height: 300px; overflow-y: auto; }}
            .audit-entry {{ margin: 5px 0; padding: 5px; border-left: 2px solid #ccc; padding-left: 10px; }}
            .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 12px; color: #666; }}
        </style>
    </head>
    <body>
        <h1>CRA Compliance Decision Report</h1>
        <p><em>EU Cyber Resilience Act (2024/2847) - Decision Traceability & Audit Trail</em></p>
        
        <div class="header-info">
            <div class="info-box">
                <div class="info-label">Decision ID:</div>
                <div>{decision_id}</div>
            </div>
            <div class="info-box">
                <div class="info-label">Report Generated:</div>
                <div>{datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</div>
            </div>
        </div>
        
        <div class="section">
            <h2>1. Vulnerability Details</h2>
            <table>
                <tr>
                    <th>Attribute</th>
                    <th>Value</th>
                </tr>
                <tr>
                    <td>CVE ID</td>
                    <td><strong>{cve["cve_id"]}</strong></td>
                </tr>
                <tr>
                    <td>Description</td>
                    <td>{cve["description"]}</td>
                </tr>
                <tr>
                    <td>Severity</td>
                    <td><strong>{cve["severity"]}</strong></td>
                </tr>
                <tr>
                    <td>CVSS Score</td>
                    <td><strong>{cve["cvss_score"]}</strong></td>
                </tr>
                <tr>
                    <td>Exploit Available</td>
                    <td>{"✓ YES" if cve.get("exploit_available") else "✗ NO"}</td>
                </tr>
                <tr>
                    <td>Affected Version Range</td>
                    <td>{cve["affected_versions"]["range_start"]} - {cve["affected_versions"]["range_end"]}</td>
                </tr>
            </table>
        </div>
        
        <div class="section">
            <h2>2. Product Assessment</h2>
            <table>
                <tr>
                    <th>Attribute</th>
                    <th>Value</th>
                </tr>
                <tr>
                    <td>Product Name</td>
                    <td><strong>{product_name}</strong></td>
                </tr>
                <tr>
                    <td>Manufacturer</td>
                    <td>J-TEC Co., Ltd.</td>
                </tr>
                <tr>
                    <td>Component Assessed</td>
                    <td>{sbom_match["matching_component"]}</td>
                </tr>
                <tr>
                    <td>Component Version</td>
                    <td><strong>{sbom_match["component_version"]}</strong></td>
                </tr>
                <tr>
                    <td>Match Confidence</td>
                    <td>{sbom_match["match_confidence"]:.0%}</td>
                </tr>
                <tr>
                    <td>Match Reason</td>
                    <td>{sbom_match["match_reason"]}</td>
                </tr>
            </table>
        </div>
        
        <div class="section">
            <h2>3. Decision Rules Applied</h2>
            {_format_rules_html(decision.get("rules_fired", []))}
        </div>
        
        <div class="section">
            <h2>4. Evidence Weighting</h2>
            <table>
                <tr>
                    <th>Evidence Source</th>
                    <th>Confidence</th>
                </tr>
                <tr>
                    <td>SBOM Matching</td>
                    <td>{decision.get("evidence_weighting", {}).get("sbom_confidence", 0):.0%}</td>
                </tr>
                <tr>
                    <td>CVE Data (NVD)</td>
                    <td>{decision.get("evidence_weighting", {}).get("cve_data_confidence", 0):.0%}</td>
                </tr>
                <tr>
                    <td>VEX Statement</td>
                    <td>{decision.get("evidence_weighting", {}).get("vex_confidence", 0):.0%}</td>
                </tr>
                <tr>
                    <td><strong>Overall Confidence</strong></td>
                    <td><strong>{decision.get("confidence_score", 0):.0%}</strong></td>
                </tr>
            </table>
        </div>
        
        <div class="section">
            <h2>5. Final Decision</h2>
            <table>
                <tr>
                    <th>Attribute</th>
                    <th>Value</th>
                </tr>
                <tr>
                    <td>Decision Type</td>
                    <td>
                        <span class="decision-{decision.get('final_decision_type', 'unknown').lower()}">
                            {decision.get('final_decision_type', 'UNKNOWN')}
                        </span>
                    </td>
                </tr>
                <tr>
                    <td>Decision Maker</td>
                    <td>Compliance Officer (Human Review)</td>
                </tr>
                <tr>
                    <td>Auto-Decidable</td>
                    <td>{"✓ Yes" if decision.get("auto_decidable") else "✗ No (Required Human Review)"}</td>
                </tr>
                <tr>
                    <td>Justification</td>
                    <td>{decision.get("justification", "N/A")}</td>
                </tr>
            </table>
        </div>
        
        <div class="section">
            <h2>6. Audit Trail (Complete History)</h2>
            <div class="audit-log">
                {_format_audit_trail_html(audit_trail)}
            </div>
        </div>
        
        <div class="footer">
            <p><strong>Legal Notice:</strong> This report documents the CRA compliance decision for {product_name}. This decision is subject to regulatory audit and must be retained for 10+ years per EU Cyber Resilience Act Article 20.</p>
            <p>Generated by Geoglyph Inc. CRA Decision Traceability System</p>
        </div>
    </body>
    </html>
    """
    
    return html_content


def _format_rules_html(rules):
    """Format rules list as HTML"""
    html = ""
    for rule in rules:
        if rule["triggered"]:
            html += f"""
            <div class="rule">
                <strong>{rule['rule']}</strong><br>
                <em>{rule['reasoning']}</em>
            </div>
            """
    return html if html else "<p>No rules fired.</p>"


def _format_audit_trail_html(audit_trail):
    """Format audit trail as HTML"""
    html = ""
    for i, entry in enumerate(audit_trail, 1):
        html += f"""
        <div class="audit-entry">
            <strong>[{i}] {entry['action']}</strong> @ {entry['timestamp']}<br>
            {entry['details']}
        </div>
        """
    return html


def generate_html_download_link(html_content, filename="cra-compliance-decision.html"):
    """Generate downloadable HTML link"""
    html_bytes = html_content.encode('utf-8')
    b64 = base64.b64encode(html_bytes).decode()
    href = f'<a href="data:text/html;base64,{b64}" download="{filename}">📥 Download Compliance Report (HTML)</a>'
    return href


# ─────────────────────────────────────────────────────────────────────────────
# CycloneDX SBOM Export (CycloneDX 1.6 JSON)
# ─────────────────────────────────────────────────────────────────────────────

def generate_cyclonedx_sbom(product_name, product_data, cve=None, sbom_match=None):
    """
    Generate a CycloneDX 1.6-compliant SBOM JSON for the given product.
    Optionally annotates the vulnerable component if CVE/match data is provided.
    """
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    serial = f"urn:uuid:{uuid.uuid4()}"

    components = []
    for comp in product_data.get("sbom", {}).get("components", []):
        is_vuln = (
            sbom_match and sbom_match.get("match_found") and
            comp["name"].lower() in (sbom_match.get("matching_component") or "").lower()
        )
        entry = {
            "type": comp.get("type", "library"),
            "bom-ref": f"{comp['name']}-{comp['version']}",
            "name": comp["name"],
            "version": comp["version"],
            "supplier": {"name": comp.get("vendor", "Unknown")},
            "purl": comp.get("purl", f"pkg:generic/{comp['name']}@{comp['version']}"),
        }
        if is_vuln and cve:
            entry["evidence"] = {
                "licenses": [],
                "occurrences": []
            }
            # Inline vulnerability annotation
            entry["properties"] = [
                {"name": "cra:cve_id",       "value": cve["cve_id"]},
                {"name": "cra:cvss_score",    "value": str(cve["cvss_score"])},
                {"name": "cra:severity",      "value": cve["severity"]},
                {"name": "cra:exploit",       "value": str(cve.get("exploit_available", False))},
                {"name": "cra:report_status", "value": sbom_match.get("match_reason", "")},
            ]
        components.append(entry)

    vulnerabilities = []
    if cve and sbom_match and sbom_match.get("match_found"):
        vuln_ref = f"{sbom_match.get('matching_component','unknown')}-{sbom_match.get('component_version','')}"
        vulnerabilities.append({
            "bom-ref": f"vuln-{cve['cve_id']}",
            "id": cve["cve_id"],
            "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cve['cve_id']}"},
            "ratings": [{"source": {"name": "NVD"}, "score": cve["cvss_score"],
                         "severity": cve["severity"].lower(), "method": "CVSSv3"}],
            "description": cve.get("description", ""),
            "affects": [{"ref": vuln_ref, "versions": [
                {"version": sbom_match.get("component_version",""),
                 "status": "affected"}
            ]}],
        })

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [{"vendor": "Geoglyph Inc.",
                       "name": "CRA Decision Traceability System",
                       "version": "1.0.0"}],
            "component": {
                "type": "device",
                "bom-ref": f"product-{product_name.replace(' ','-')}",
                "manufacturer": {"name": "J-TEC Co., Ltd."},
                "name": product_name,
                "version": product_data.get("version", "unknown"),
                "description": product_data.get("description", ""),
                "properties": [
                    {"name": "cra:product_type",  "value": product_data.get("type","")},
                    {"name": "cra:manufacturer",  "value": "J-TEC Co., Ltd."},
                    {"name": "cra:cra_regulation","value": "EU CRA 2024/2847"},
                ],
            },
            "manufacture": {"name": "J-TEC Co., Ltd.",
                            "contact": [{"email": "security@jtec.example.com"}]},
            "supplier":    {"name": "J-TEC Co., Ltd."},
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
    }
    return bom


# ─────────────────────────────────────────────────────────────────────────────
# Enhanced ENISA Article 14 JSON
# ─────────────────────────────────────────────────────────────────────────────

def generate_enisa_article14_json(decision, cve, product_name, product_data,
                                   sbom_match, submission_id, audit_trail=None):
    """
    Full CRA Article 14 structured notification payload.
    Extends the basic ENISA JSON with timeline, evidence block,
    affected version list, and SBOM component reference.
    """
    now = datetime.utcnow()
    return {
        "schema_version": "CRA-Article14-v1.0",
        "submission_id": submission_id,
        "submission_type": "EARLY_WARNING",               # Art. 14(2) — 24h
        "report_stage": "INITIAL",
        "submitted_at": now.isoformat() + "Z",
        "submitted_by": {
            "organization": "J-TEC Co., Ltd.",
            "role": "Manufacturer",
            "contact_email": "security@jtec.example.com",
            "country": "JP",
            "eu_representative": "Geoglyph Inc. (EU Representative)",
        },
        "regulatory_basis": {
            "regulation": "EU Cyber Resilience Act",
            "regulation_ref": "Regulation (EU) 2024/2847",
            "article": "Article 14 — Reporting obligations",
            "paragraph": "14(2) — Early warning within 24 hours",
            "enisa_portal": "https://vulnerability.enisa.europa.eu/",
        },
        "product": {
            "name": product_name,
            "manufacturer": "J-TEC Co., Ltd.",
            "type": product_data.get("type", "Industrial Equipment"),
            "version": product_data.get("version", ""),
            "description": product_data.get("description", ""),
            "product_category": "Industrial Control System",
            "cra_class": "Class I",
        },
        "vulnerability": {
            "cve_id": cve["cve_id"],
            "description": cve.get("description", ""),
            "severity": cve["severity"],
            "cvss_score": cve["cvss_score"],
            "cvss_vector": cve.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            "exploit_available": cve.get("exploit_available", False),
            "exploit_maturity": "functional" if cve.get("exploit_available") else "unproven",
            "affected_versions": {
                "range_start": cve["affected_versions"]["range_start"],
                "range_end":   cve["affected_versions"]["range_end"],
            },
            "affected_component": sbom_match.get("matching_component", ""),
            "component_version":  sbom_match.get("component_version", ""),
            "vendor_of_component": "OpenSSL Project",
            "patch_available": False,
            "workaround_available": True,
        },
        "impact_assessment": {
            "match_found": sbom_match.get("match_found", False),
            "match_confidence": sbom_match.get("match_confidence", 0),
            "match_reason": sbom_match.get("match_reason", ""),
            "estimated_affected_systems": "847",
            "affected_markets": ["DE", "FR", "IT", "ES", "IE"],
            "confidentiality_impact": "HIGH",
            "integrity_impact": "HIGH",
            "availability_impact": "HIGH",
        },
        "decision": {
            "decision_id": decision.get("decision_id", ""),
            "final_decision": decision.get("final_decision_type", ""),
            "confidence_score": decision.get("confidence_score", 0),
            "auto_decidable": decision.get("auto_decidable", True),
            "decision_maker": decision.get("reviewer", "Automated System"),
            "justification": decision.get("justification", ""),
            "rules_applied": [r["rule"] for r in decision.get("rules_fired", []) if r.get("triggered")],
        },
        "timeline": {
            "vulnerability_detected": now.strftime("%Y-%m-%dT00:00:00Z"),
            "internal_triage_completed": now.strftime("%Y-%m-%dT01:30:00Z"),
            "early_warning_submitted": now.isoformat() + "Z",
            "full_report_due": "Within 72 hours per Art. 14(3)",
            "final_report_due": "Within 90 days per Art. 14(4)",
        },
        "evidence": {
            "sbom_available": True,
            "sbom_format": "CycloneDX 1.6",
            "vex_statement_available": True,
            "audit_trail_entries": len(audit_trail) if audit_trail else 0,
        },
        "actions_taken": [
            "SBOM cross-referenced against CVE affected version range",
            "Automated decision pipeline executed (6 stages)",
            "Human review completed" if not decision.get("auto_decidable") else "Auto-decision applied",
            "ENISA early warning submitted within 24h",
        ],
        "contact": {
            "security_contact": "security@jtec.example.com",
            "cra_compliance_officer": "compliance@jtec.example.com",
            "eu_csirt": "cert@jtec-eu.example.com",
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# CSV Audit Log
# ─────────────────────────────────────────────────────────────────────────────

def generate_audit_csv(audit_trail, cve_id, product_name, decision_type):
    """Return CSV bytes of the complete pipeline audit trail."""
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["#", "timestamp", "action", "details",
                     "cve_id", "product", "decision"])
    for i, entry in enumerate(audit_trail, 1):
        writer.writerow([
            i,
            entry.get("timestamp", ""),
            entry.get("action", ""),
            entry.get("details", ""),
            cve_id, product_name, decision_type,
        ])
    return output.getvalue().encode("utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# PDF Audit Report (ReportLab)
# ─────────────────────────────────────────────────────────────────────────────

def generate_pdf_report(cve, product_name, product_data, sbom_match, decision,
                         audit_trail, scenario_name=""):
    """
    Generate a branded PDF compliance report using ReportLab.
    Returns bytes suitable for st.download_button.
    """
    if not REPORTLAB_AVAILABLE:
        return None

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=20*mm, bottomMargin=20*mm,
        title=f"CRA Compliance Report — {cve['cve_id']}",
        author="Geoglyph Inc. / J-TEC Co., Ltd.",
    )

    styles = getSampleStyleSheet()
    NAVY  = colors.HexColor("#003d82")
    BLUE  = colors.HexColor("#1d4ed8")
    GREEN = colors.HexColor("#166534")
    RED   = colors.HexColor("#dc2626")
    AMBER = colors.HexColor("#92400e")
    LGRAY = colors.HexColor("#f3f4f6")
    DGRAY = colors.HexColor("#374151")

    h1  = ParagraphStyle("h1",  parent=styles["Heading1"],  fontSize=18, textColor=NAVY,  spaceAfter=4)
    h2  = ParagraphStyle("h2",  parent=styles["Heading2"],  fontSize=12, textColor=BLUE,  spaceBefore=12, spaceAfter=4)
    h3  = ParagraphStyle("h3",  parent=styles["Heading3"],  fontSize=10, textColor=DGRAY, spaceBefore=6,  spaceAfter=2)
    bod = ParagraphStyle("bod", parent=styles["Normal"],     fontSize=9,  textColor=DGRAY, spaceAfter=3)
    sml = ParagraphStyle("sml", parent=styles["Normal"],     fontSize=8,  textColor=colors.HexColor("#6b7280"))
    ctr = ParagraphStyle("ctr", parent=styles["Normal"],     fontSize=9,  alignment=TA_CENTER)
    bold_style = ParagraphStyle("bold", parent=bod, fontName="Helvetica-Bold")

    def tbl(data, col_widths=None, header_bg=NAVY):
        t = Table(data, colWidths=col_widths, repeatRows=1)
        n_rows = len(data)
        style = TableStyle([
            ("BACKGROUND",  (0,0), (-1,0),  header_bg),
            ("TEXTCOLOR",   (0,0), (-1,0),  colors.white),
            ("FONTNAME",    (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",    (0,0), (-1,-1), 8),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, LGRAY]),
            ("GRID",        (0,0), (-1,-1), 0.4, colors.HexColor("#d1d5db")),
            ("VALIGN",      (0,0), (-1,-1), "TOP"),
            ("LEFTPADDING",  (0,0),(-1,-1), 5),
            ("RIGHTPADDING", (0,0),(-1,-1), 5),
            ("TOPPADDING",   (0,0),(-1,-1), 3),
            ("BOTTOMPADDING",(0,0),(-1,-1), 3),
        ])
        t.setStyle(style)
        return t

    story = []

    # ── Cover header ──
    story.append(Paragraph("CRA Compliance Decision Report", h1))
    story.append(Paragraph(
        "EU Cyber Resilience Act (2024/2847) — Article 14 Vulnerability Reporting",
        ParagraphStyle("sub", parent=bod, textColor=BLUE, fontSize=10)
    ))
    story.append(HRFlowable(width="100%", thickness=2, color=NAVY, spaceAfter=6))

    # Meta row
    meta = [
        ["Decision ID",     decision.get("decision_id","—"),   "Generated",  datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
        ["Manufacturer",    "J-TEC Co., Ltd.",                 "Scenario",   scenario_name or "—"],
        ["CRA Regulation",  "EU 2024/2847",                    "Reviewer",   decision.get("reviewer","Automated System")],
    ]
    story.append(tbl(
        [["Field","Value","Field","Value"]] + meta,
        col_widths=[38*mm, 55*mm, 38*mm, 55*mm],
        header_bg=NAVY
    ))
    story.append(Spacer(1, 6*mm))

    # ── Decision verdict ──
    dec_type = decision.get("final_decision_type","UNKNOWN")
    dec_color_hex = {"REPORT":"#dc2626","NOT_REPORT":"#166534"}.get(dec_type,"#92400e")
    dec_color_obj = RED if dec_type=="REPORT" else GREEN if dec_type=="NOT_REPORT" else AMBER
    story.append(Paragraph(
        f'<font color="{dec_color_hex}">'
        f'&#9654; Final Decision: <b>{dec_type}</b>  |  '
        f'Confidence: <b>{decision.get("confidence_score",0):.0%}</b>  |  '
        f'Auto-Decidable: <b>{"YES" if decision.get("auto_decidable") else "NO"}</b></font>',
        ParagraphStyle("verdict", parent=bod, fontSize=11, spaceBefore=4, spaceAfter=8,
                       borderPad=4, borderWidth=1,
                       borderColor=dec_color_obj, backColor=LGRAY)
    ))

    # ── Section 1: Vulnerability ──
    story.append(Paragraph("1. Vulnerability Details", h2))
    story.append(tbl([
        ["Attribute", "Value"],
        ["CVE ID",          cve["cve_id"]],
        ["Description",     cve.get("description","")[:120]+"…" if len(cve.get("description",""))>120 else cve.get("description","")],
        ["Severity",        cve["severity"]],
        ["CVSS Score",      str(cve["cvss_score"])],
        ["Exploit Available", "YES ⚠" if cve.get("exploit_available") else "NO ✓"],
        ["Affected Range",  f'{cve["affected_versions"]["range_start"]} → {cve["affected_versions"]["range_end"]}'],
    ], col_widths=[55*mm, 121*mm]))
    story.append(Spacer(1, 4*mm))

    # ── Section 2: Product & SBOM ──
    story.append(Paragraph("2. Product & SBOM Assessment", h2))
    story.append(tbl([
        ["Attribute", "Value"],
        ["Product Name",        product_name],
        ["Product Type",        product_data.get("type","")],
        ["Version",             product_data.get("version","")],
        ["Affected Component",  sbom_match.get("matching_component","—")],
        ["Component Version",   sbom_match.get("component_version","—")],
        ["Match Confidence",    f'{sbom_match.get("match_confidence",0):.0%}'],
        ["Match Reason",        sbom_match.get("match_reason","")],
    ], col_widths=[55*mm, 121*mm]))
    story.append(Spacer(1, 4*mm))

    # ── Section 3: Decision Rules ──
    story.append(Paragraph("3. Decision Rules Applied", h2))
    rules_data = [["Rule", "Triggered", "Reasoning"]]
    for r in decision.get("rules_fired", []):
        rules_data.append([
            r.get("rule",""),
            "✅ YES" if r.get("triggered") else "— NO",
            r.get("reasoning","")[:80],
        ])
    if len(rules_data) > 1:
        story.append(tbl(rules_data, col_widths=[45*mm, 20*mm, 111*mm]))
    story.append(Spacer(1, 4*mm))

    # ── Section 4: Justification ──
    story.append(Paragraph("4. Decision Justification", h2))
    story.append(Paragraph(decision.get("justification","No justification recorded."), bod))
    story.append(Spacer(1, 4*mm))

    # ── Section 5: Audit Trail ──
    story.append(Paragraph("5. Complete Pipeline Audit Trail", h2))
    audit_data = [["#", "Timestamp", "Action", "Details"]]
    for i, entry in enumerate(audit_trail, 1):
        ts = str(entry.get("timestamp",""))[-8:] if len(str(entry.get("timestamp","")))>8 else str(entry.get("timestamp",""))
        audit_data.append([
            str(i), ts,
            str(entry.get("action",""))[:30],
            str(entry.get("details",""))[:70],
        ])
    story.append(tbl(audit_data, col_widths=[8*mm, 22*mm, 45*mm, 101*mm]))
    story.append(Spacer(1, 6*mm))

    # ── Footer ──
    story.append(HRFlowable(width="100%", thickness=1, color=LGRAY))
    story.append(Spacer(1, 2*mm))
    story.append(Paragraph(
        "This report is generated by Geoglyph Inc. CRA Decision Traceability System on behalf of J-TEC Co., Ltd. "
        "It constitutes an official compliance artifact under EU Cyber Resilience Act (2024/2847) Article 14. "
        "Retain for a minimum of 5 years per CRA Article 14 audit requirements. "
        "© 2026 Geoglyph Inc. &amp; J-TEC Co., Ltd. All rights reserved.",
        sml
    ))

    doc.build(story)
    return buf.getvalue()
