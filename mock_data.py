"""
Mock Data for CRA Decision Traceability Demo
Pre-loaded products, SBOMs, and CVE scenarios
"""

# ============= J-TEC PRODUCTS =============

PRODUCTS = {
    "BagMaker-X 2100": {
        "product_id": "prod-001",
        "manufacturer": "J-TEC Co., Ltd.",
        "version": "2.1.0",
        "type": "Bag-Making Machinery",
        "description": "High-speed reel-fed bag making machine with embedded PLC control",
        "sbom": {
            "components": [
                {
                    "name": "PLC Firmware",
                    "version": "3.2.1",
                    "vendor": "Siemens",
                    "type": "firmware",
                    "purl": "pkg:generic/siemens-plc@3.2.1"
                },
                {
                    "name": "HMI Operating System",
                    "version": "5.1.0",
                    "vendor": "Beckhoff",
                    "type": "software",
                    "purl": "pkg:generic/beckhoff-hmi@5.1.0"
                },
                {
                    "name": "OpenSSL",
                    "version": "1.1.1k",
                    "vendor": "OpenSSL Foundation",
                    "type": "library",
                    "purl": "pkg:deb/openssl@1.1.1k"
                }
            ]
        }
    },
    "TS5525": {
        "product_id": "prod-002",
        "manufacturer": "J-TEC Co., Ltd.",
        "version": "1.5.0",
        "type": "Sheet-Fed Bag-Making Machine",
        "description": "Sheet-fed type bag making machine with remote diagnostics",
        "sbom": {
            "components": [
                {
                    "name": "PLC Firmware",
                    "version": "2.1.5",
                    "vendor": "Mitsubishi",
                    "type": "firmware",
                    "purl": "pkg:generic/mitsubishi-plc@2.1.5"
                },
                {
                    "name": "OpenSSL",
                    "version": "1.0.2u",
                    "vendor": "OpenSSL Foundation",
                    "type": "library",
                    "purl": "pkg:deb/openssl@1.0.2u"
                },
                {
                    "name": "curl",
                    "version": "7.68.0",
                    "vendor": "curl project",
                    "type": "library",
                    "purl": "pkg:deb/curl@7.68.0"
                }
            ]
        }
    },
    "Model 137T": {
        "product_id": "prod-003",
        "manufacturer": "J-TEC Co., Ltd.",
        "version": "3.0.0",
        "type": "Advanced Bag-Making System",
        "description": "Advanced model with integrated IoT connectivity and AI diagnostics",
        "sbom": {
            "components": [
                {
                    "name": "PLC Firmware",
                    "version": "4.0.2",
                    "vendor": "OMRON",
                    "type": "firmware",
                    "purl": "pkg:generic/omron-plc@4.0.2"
                },
                {
                    "name": "nginx",
                    "version": "1.18.0",
                    "vendor": "nginx Inc",
                    "type": "software",
                    "purl": "pkg:deb/nginx@1.18.0"
                },
                {
                    "name": "libssl",
                    "version": "1.1.1",
                    "vendor": "OpenSSL Foundation",
                    "type": "library",
                    "purl": "pkg:deb/libssl@1.1.1"
                }
            ]
        }
    }
}


# ============= CVE SCENARIOS =============

CVE_SCENARIOS = {
    "scenario_a": {
        "name": "Scenario A: CVE Affects Component (REPORT)",
        "cve_id": "CVE-2026-0001",
        "cve_description": "Critical buffer overflow in OpenSSL 1.0.0-1.1.1 affects key exchange",
        "severity": "HIGH",
        "cvss_score": 8.5,
        "affected_versions": {
            "library": "OpenSSL",
            "range_start": "1.0.0",
            "range_end": "1.1.1"
        },
        "exploit_available": True,
        "affected_product": "TS5525",
        "matching_component": "OpenSSL 1.0.2u",
        "expected_decision": "REPORT",
        "decision_reason": "CVE affects installed version 1.0.2u (within 1.0.0-1.1.1 range). Exploit available. Severity HIGH > threshold."
    },
    
    "scenario_b": {
        "name": "Scenario B: Version Mismatch (NOT_REPORT)",
        "cve_id": "CVE-2026-0002",
        "cve_description": "Remote code execution in OpenSSL 1.0.0-1.0.9 via malformed certificate",
        "severity": "CRITICAL",
        "cvss_score": 9.2,
        "affected_versions": {
            "library": "OpenSSL",
            "range_start": "1.0.0",
            "range_end": "1.0.9"
        },
        "exploit_available": True,
        "affected_product": "BagMaker-X 2100",
        "matching_component": "OpenSSL 1.1.1k",
        "expected_decision": "NOT_REPORT",
        "decision_reason": "Installed version 1.1.1k is OUTSIDE affected range (1.0.0-1.0.9). Component not vulnerable."
    },
    
    "scenario_c": {
        "name": "Scenario C: Conflict Detection (VEX Override)",
        "cve_id": "CVE-2026-0003",
        "cve_description": "Potential DoS in nginx 1.18.0 via HTTP/2 connection handling",
        "severity": "MEDIUM",
        "cvss_score": 5.7,
        "affected_versions": {
            "library": "nginx",
            "range_start": "1.16.0",
            "range_end": "1.19.0"
        },
        "exploit_available": False,
        "affected_product": "Model 137T",
        "matching_component": "nginx 1.18.0",
        "initial_decision": "NOT_REPORT",
        "initial_reason": "SBOM shows nginx 1.18.0. Exploit NOT available. Severity MEDIUM < threshold.",
        "vex_arrives": True,
        "vex_statement": "AFFECTED - This vulnerability impacts all nginx versions. We have mitigations in place via configuration.",
        "vex_justification": "Our deployment uses HTTP/1.1 only, disabling HTTP/2 entirely. DoS vector does not apply.",
        "expected_decision": "NOT_REPORT (after VEX review)",
        "decision_reason": "VEX provides accepted mitigation. Despite vulnerability, our specific configuration prevents exploitation."
    },

    "scenario_d": {
        "name": "Scenario D: Ambiguous Evidence — Human Decision Required",
        "cve_id": "CVE-2026-0004",
        "cve_description": "Memory corruption in libssl 1.1.0–1.1.2 via malformed TLS ClientHello. No public PoC exploit confirmed. Theoretical remote code execution under specific conditions.",
        "severity": "MEDIUM",
        "cvss_score": 6.8,
        "affected_versions": {
            "library": "libssl",
            "range_start": "1.1.0",
            "range_end": "1.1.2"
        },
        "exploit_available": False,
        "affected_product": "Model 137T",
        "matching_component": "libssl 1.1.1",
        "vex_arrives": True,
        "vex_statement": "AFFECTED — libssl 1.1.1 is within the affected range (1.1.0–1.1.2).",
        "vex_justification": "Perimeter firewall rules restrict inbound TLS connections from untrusted networks. Risk is reduced but not fully eliminated — internal network exposure remains.",
        "expected_decision": "HUMAN DECISION REQUIRED",
        "decision_reason": (
            "CVSS 6.8 is below the HIGH threshold (7.0) — Rule R2 does not auto-trigger. "
            "Component IS in the affected range. No confirmed exploit. "
            "VEX mitigation is partial (firewall only). "
            "System confidence is 0.65 — below the 0.80 auto-decide threshold. "
            "A Compliance Officer must review and decide."
        ),
        "human_review_required": True
    }
}


# ============= DECISION RULES =============

DECISION_RULES = [
    {
        "rule_id": "R1",
        "name": "Critical Severity + Exploit Available",
        "condition": "cvss_score >= 8.5 AND exploit_available == True",
        "action": "REPORT",
        "auto_decidable": True,
        "confidence_boost": 0.95
    },
    {
        "rule_id": "R2",
        "name": "High Severity + Component Affected",
        "condition": "cvss_score >= 7.0 AND component_affected == True",
        "action": "REPORT",
        "auto_decidable": True,
        "confidence_boost": 0.85
    },
    {
        "rule_id": "R3",
        "name": "Version Mismatch (Outside Affected Range)",
        "condition": "component_affected == False",
        "action": "NOT_REPORT",
        "auto_decidable": True,
        "confidence_boost": 0.95
    },
    {
        "rule_id": "R4",
        "name": "VEX Provides Accepted Mitigation",
        "condition": "vex_status == 'NOT_AFFECTED' AND vex_justification != None",
        "action": "NOT_REPORT",
        "auto_decidable": False,  # Requires human review
        "confidence_boost": 0.70
    },
    {
        "rule_id": "R5",
        "name": "Conflicting Evidence Detected",
        "condition": "evidence_conflict == True",
        "action": "CONFLICT",
        "auto_decidable": False,  # Requires human review
        "confidence_boost": 0.0
    },
    {
        "rule_id": "R6",
        "name": "Ambiguous — Medium Severity + Partial Mitigation",
        "condition": "cvss_score >= 5.0 AND cvss_score < 7.0 AND component_affected == True AND exploit_available == False",
        "action": "HUMAN_REVIEW",
        "auto_decidable": False,
        "confidence_boost": 0.65
    }
]


# ============= DECISION THRESHOLDS =============

THRESHOLDS = {
    "auto_decide_confidence": 0.80,
    "critical_severity": 8.5,
    "high_severity": 7.0,
    "medium_severity": 5.0,
    "low_severity": 3.0,
    "sbom_match_confidence": 0.95,
    "vex_trust_score": 0.90
}


# ============= MOCK ENISA RESPONSE =============

ENISA_MOCK_RESPONSE = {
    "status": "202",
    "reference_id": "ENISA-2026-{uuid}",
    "message": "Vulnerability report accepted by ENISA",
    "received_timestamp": None,  # Will be set at runtime
    "sla_deadline": "24 hours"
}
