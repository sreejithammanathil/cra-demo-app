"""
ENISA Reporter Module
Generates mock ENISA API submissions and PDF compliance artifacts
"""

from datetime import datetime
from io import BytesIO
import base64


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
