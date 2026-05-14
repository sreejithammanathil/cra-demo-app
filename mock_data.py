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


# ============= POST-ENISA COMPLIANCE LIFECYCLE DATA =============

POST_ENISA_DATA = {
    "case_ref": "CRA-2026-TS5525-001",
    "cve_id": "CVE-2025-0001",
    "product": "TS5525 Industrial Controller",
    "initial_report_ts": "2026-04-28 09:14 UTC",
    "enisa_submission_id": "ENISA-SUB-20260428-7742",

    # ── 12 operational phases ──
    "lifecycle_phases": [
        {"id":"L01","name":"Initial ENISA Report","name_ja":"ENISA初期報告",            "status":"COMPLETE",    "ts":"2026-04-28 09:14","sla_h":24, "elapsed_h":18,"owner":"Compliance Team"},
        {"id":"L02","name":"Regulatory Acknowledgement","name_ja":"規制機関確認",       "status":"COMPLETE",    "ts":"2026-04-29 11:02","sla_h":48, "elapsed_h":38,"owner":"ENISA"},
        {"id":"L03","name":"Internal Incident Coordination","name_ja":"社内調整",       "status":"COMPLETE",    "ts":"2026-04-29 14:30","sla_h":48, "elapsed_h":44,"owner":"CISO Office"},
        {"id":"L04","name":"Technical Investigation","name_ja":"技術調査",              "status":"IN_PROGRESS", "ts":None,              "sla_h":120,"elapsed_h":96,"owner":"Security Engineering"},
        {"id":"L05","name":"Root Cause Analysis","name_ja":"根本原因分析",              "status":"IN_PROGRESS", "ts":None,              "sla_h":168,"elapsed_h":72,"owner":"Platform Engineering"},
        {"id":"L06","name":"Remediation Planning","name_ja":"修正計画",                 "status":"IN_PROGRESS", "ts":None,              "sla_h":120,"elapsed_h":48,"owner":"Engineering Lead"},
        {"id":"L07","name":"Patch Development","name_ja":"パッチ開発",                  "status":"PENDING",     "ts":None,              "sla_h":336,"elapsed_h":0, "owner":"Platform Engineering"},
        {"id":"L08","name":"Security Validation","name_ja":"セキュリティ検証",          "status":"PENDING",     "ts":None,              "sla_h":48, "elapsed_h":0, "owner":"Security Team"},
        {"id":"L09","name":"Customer Notification","name_ja":"顧客通知",                "status":"IN_PROGRESS", "ts":None,              "sla_h":72, "elapsed_h":68,"owner":"Customer Success"},
        {"id":"L10","name":"Patch Rollout Monitoring","name_ja":"パッチ展開監視",       "status":"PENDING",     "ts":None,              "sla_h":720,"elapsed_h":0, "owner":"DevOps"},
        {"id":"L11","name":"Final ENISA Report","name_ja":"ENISA最終報告",              "status":"PENDING",     "ts":None,              "sla_h":2160,"elapsed_h":0,"owner":"Compliance Team"},
        {"id":"L12","name":"Compliance Closure","name_ja":"コンプライアンス完了",       "status":"PENDING",     "ts":None,              "sla_h":2880,"elapsed_h":0,"owner":"CISO Office"},
        {"id":"L13","name":"Audit Retention","name_ja":"監査保管",                      "status":"PENDING",     "ts":None,              "sla_h":None,"elapsed_h":0,"owner":"Legal & Compliance"},
    ],

    # ── Regulatory Coordination ──
    "regulatory": {
        "status": "MORE_EVIDENCE_REQUESTED",
        "case_manager": "Marie Dubois (ENISA NIS Unit)",
        "ack_ts": "2026-04-29 11:02 UTC",
        "ack_ref": "ENISA-ACK-2026-4421",
        "sla_days": 30, "days_elapsed": 15,
        "open_request": "Patch development timeline and interim mitigation effectiveness report",
        "response_deadline": "2026-05-20",
        "national_authority": "BSI (Germany) — primary market",
        "authority_statuses": [
            {"name":"ENISA",     "status":"MORE_EVIDENCE_REQUESTED","flag":"🇪🇺"},
            {"name":"BSI",       "status":"UNDER_REVIEW",           "flag":"🇩🇪"},
            {"name":"ANSSI",     "status":"AWAITING_NOTIFICATION",  "flag":"🇫🇷"},
            {"name":"ACN",       "status":"AWAITING_NOTIFICATION",  "flag":"🇮🇹"},
            {"name":"NCSC-IE",   "status":"AWAITING_NOTIFICATION",  "flag":"🇮🇪"},
            {"name":"CCN",       "status":"AWAITING_NOTIFICATION",  "flag":"🇪🇸"},
        ],
        "follow_ups": [
            {"date":"2026-05-02","from":"ENISA","type":"Information Request","subject":"Exploit chain analysis — PoC reproduction steps","status":"RESPONDED"},
            {"date":"2026-05-08","from":"BSI",  "type":"Additional Evidence", "subject":"Affected customer count by product version",        "status":"RESPONDED"},
            {"date":"2026-05-12","from":"ENISA","type":"Information Request","subject":"Patch timeline + interim mitigation effectiveness",   "status":"PENDING"},
        ],
        "comms_log": [
            {"ts":"2026-04-28 09:14","dir":"OUT","ch":"ENISA Portal",  "summary":"Initial 24h early warning — Article 14(2)"},
            {"ts":"2026-04-29 11:02","dir":"IN", "ch":"ENISA Portal",  "summary":"Acknowledgement — case assigned to NIS Unit"},
            {"ts":"2026-04-30 16:30","dir":"OUT","ch":"ENISA Portal",  "summary":"Full technical report — Article 14(3)"},
            {"ts":"2026-05-02 10:15","dir":"IN", "ch":"Secure Email",  "summary":"Request: exploit chain analysis"},
            {"ts":"2026-05-04 14:00","dir":"OUT","ch":"Secure Email",  "summary":"Exploit chain analysis — 12-page technical annex"},
            {"ts":"2026-05-08 09:00","dir":"IN", "ch":"ENISA Portal",  "summary":"BSI: customer impact breakdown by version"},
            {"ts":"2026-05-09 11:30","dir":"OUT","ch":"ENISA Portal",  "summary":"Customer impact data — 847 affected across v2.1-v2.8"},
            {"ts":"2026-05-12 15:00","dir":"IN", "ch":"Secure Email",  "summary":"New request: patch timeline + mitigation effectiveness (due 2026-05-20)"},
        ],
    },

    # ── Remediation Governance ──
    "remediation": {
        "status": "PATCH_IN_QA",
        "owner": "Dr. K. Watanabe — Platform Engineering Lead",
        "mitigation_available": True,
        "mitigation_desc": "Disable OpenSSL module v1.0.2u; upgrade to OpenSSL 3.0.x where operationally feasible",
        "workaround_published": True,
        "workaround_ts": "2026-04-30 08:00 UTC",
        "patch_eta": "2026-05-22",
        "patch_version": "v2.9.1",
        "validation_status": "IN_PROGRESS",
        "unresolved_systems": 847,
        "rollout_waves": [
            {"wave":1,"target":"Internal test environment",       "systems":12, "status":"COMPLETE",    "date":"2026-05-18"},
            {"wave":2,"target":"Staging & QA (external)",        "systems":35, "status":"IN_PROGRESS", "date":"2026-05-22"},
            {"wave":3,"target":"High-risk production (23 cust.)", "systems":156,"status":"PENDING",     "date":"2026-05-25"},
            {"wave":4,"target":"General production rollout",      "systems":644,"status":"PENDING",     "date":"2026-06-01"},
        ],
        "timeline": [
            {"date":"2026-04-28","event":"Vulnerability confirmed — remediation initiated"},
            {"date":"2026-04-30","event":"Interim mitigation published (disable module)"},
            {"date":"2026-05-05","event":"Patch development commenced"},
            {"date":"2026-05-12","event":"Internal code review complete"},
            {"date":"2026-05-15","event":"Patch submitted to QA"},
            {"date":"2026-05-22","event":"QA validation complete (ETA)"},
            {"date":"2026-05-25","event":"High-risk customer rollout (ETA)"},
            {"date":"2026-06-01","event":"General availability rollout (ETA)"},
        ],
    },

    # ── Customer Notifications ──
    "customer_notifications": {
        "advisory_id": "J-TEC-SA-2026-001",
        "advisory_ts": "2026-04-30 12:00 UTC",
        "notifications_sent": 847,
        "acknowledgements": 412,
        "high_risk": 23,
        "support_escalations": 7,
        "templates": [
            {"name":"Initial Advisory",              "name_ja":"初期アドバイザリー",    "status":"SENT",   "recipients":847,"ts":"2026-05-01 09:00"},
            {"name":"Mitigation Instructions",       "name_ja":"緩和手順書",           "status":"SENT",   "recipients":847,"ts":"2026-05-01 10:30"},
            {"name":"High-Risk Direct Contact",      "name_ja":"高リスク顧客直接連絡", "status":"SENT",   "recipients":23, "ts":"2026-05-01 08:00"},
            {"name":"Patch Availability Notice",     "name_ja":"パッチ提供通知",       "status":"PENDING","recipients":847,"ts":None},
            {"name":"Final Closure Notification",    "name_ja":"最終完了通知",         "status":"PENDING","recipients":847,"ts":None},
        ],
        "approval_chain": [
            {"role":"Security Lead",  "name":"Tanaka Hiroshi","approved":True, "ts":"2026-04-30 10:00"},
            {"role":"Legal Counsel",  "name":"Sarah Chen",    "approved":True, "ts":"2026-04-30 11:00"},
            {"role":"CMO",            "name":"Marco Bianchi", "approved":True, "ts":"2026-04-30 11:45"},
            {"role":"CISO",           "name":"Dr. Klaus Weber","approved":True,"ts":"2026-04-30 11:55"},
        ],
        "high_risk_detail": [
            {"id":"C-DE-001","country":"🇩🇪 DE","version":"v2.1","status":"ACKNOWLEDGED","escalation":False},
            {"id":"C-DE-007","country":"🇩🇪 DE","version":"v2.3","status":"PATCH_DEPLOYED","escalation":False},
            {"id":"C-FR-003","country":"🇫🇷 FR","version":"v2.1","status":"ACKNOWLEDGED","escalation":True},
            {"id":"C-IT-002","country":"🇮🇹 IT","version":"v2.5","status":"NOTIFIED",    "escalation":False},
            {"id":"C-IE-001","country":"🇮🇪 IE","version":"v2.8","status":"NOTIFIED",    "escalation":False},
        ],
    },

    # ── Root Cause Analysis ──
    "rca": {
        "status": "DRAFT",
        "owner": "Dr. Aiko Tanaka — Security Architecture",
        "started": "2026-04-29",
        "target_completion": "2026-05-19",
        "vuln_source": "Third-party OSS dependency — OpenSSL 1.0.2u (EOL Jan 2020)",
        "dep_origin": "Direct dependency introduced TS5525 v2.0 (2023-Q3)",
        "sdlc_gap": "SCA tooling subscription lapsed 2025-10-01, not renewed until 2026-03-15. No automated CVE-to-dependency alerting in CI/CD for TS5525 product line.",
        "detection_failure": "CVE-2025-0001 published 2025-11-14. Internal detection 2026-04-27 — 165-day gap.",
        "exploit_chain": "Remote attacker → HTTPS endpoint → Buffer overflow in OpenSSL handshake → Arbitrary code execution → Service account privilege escalation",
        "findings": "OpenSSL 1.0.2u (EOL) remained in production due to lapsed SCA tooling, absent upgrade automation, and insufficient third-party lifecycle governance. No active exploitation detected in J-TEC production environment.",
        "lessons_learned": [
            "SCA subscription must be a critical security control with auto-renewal + CISO approval gate",
            "Dependency upgrade policy: CVSS ≥7.0 CVEs trigger mandatory upgrade within 30 days",
            "SBOM must be refreshed quarterly for all active products",
            "CVE detection SLA: publication → internal alert ≤7 days for CRITICAL/HIGH",
        ],
        "preventive_actions": [
            {"action":"Integrate SCA into all product CI/CD",         "owner":"DevSecOps",         "deadline":"2026-06-30","status":"IN_PROGRESS"},
            {"action":"Automated upgrade policy CVSS ≥7.0",          "owner":"Platform Eng.",      "deadline":"2026-07-31","status":"PLANNED"},
            {"action":"Quarterly SBOM refresh — all active products", "owner":"Product Security",   "deadline":"2026-06-01","status":"IN_PROGRESS"},
            {"action":"7-day CVE detection SLA + auto alerting",      "owner":"Security Ops",       "deadline":"2026-06-15","status":"IN_PROGRESS"},
            {"action":"EOL component policy + exception process",     "owner":"Architecture Board", "deadline":"2026-08-31","status":"PLANNED"},
        ],
    },

    # ── Final ENISA Report ──
    "final_report": {
        "status": "NOT_STARTED",
        "due": "2026-07-27",
        "days_remaining": 74,
        "sections": [
            {"name":"Executive Summary",                "status":"DRAFT"},
            {"name":"Vulnerability Technical Details",  "status":"COMPLETE"},
            {"name":"Affected Versions & Systems",      "status":"COMPLETE"},
            {"name":"Timeline of Events",               "status":"IN_PROGRESS"},
            {"name":"Mitigation Effectiveness",         "status":"PENDING"},
            {"name":"Patch Deployment Status",          "status":"PENDING"},
            {"name":"Customer Impact Summary",          "status":"IN_PROGRESS"},
            {"name":"Root Cause Analysis Summary",      "status":"DRAFT"},
            {"name":"Residual Risk Assessment",         "status":"PENDING"},
            {"name":"Preventive Actions Committed",     "status":"IN_PROGRESS"},
            {"name":"Evidence Attachments Index",       "status":"PENDING"},
        ],
        "initial_vs_final": [
            {"field":"Scope",          "initial":"1 product, 1 CVE",    "final":"1 product, 1 CVE (confirmed)"},
            {"field":"Affected Count", "initial":"~900 systems (est.)", "final":"847 systems (confirmed)"},
            {"field":"Exploit Status", "initial":"Not confirmed",       "final":"No exploitation detected"},
            {"field":"Mitigation",     "initial":"Under investigation", "final":"Workaround published; patch in QA"},
            {"field":"Patch ETA",      "initial":"TBD",                 "final":"2026-05-22"},
        ],
    },

    # ── Audit Retention ──
    "audit": {
        "status": "ACTIVE",
        "retention_years": 5,
        "case_opened": "2026-04-28",
        "expected_closure": "2026-08-01",
        "retention_expiry": "2031-08-01",
        "completeness_pct": 60,
        "evidence_packages": [
            {"id":"EVP-001","name":"Initial ENISA Submission",    "type":"REGULATORY_FILING",   "size_kb":245, "hash":"sha256:a4f2b1c9…","status":"LOCKED",  "ts":"2026-04-28"},
            {"id":"EVP-002","name":"CVE Technical Analysis",      "type":"TECHNICAL_REPORT",    "size_kb":1820,"hash":"sha256:b7e3d2f1…","status":"LOCKED",  "ts":"2026-04-30"},
            {"id":"EVP-003","name":"SBOM Snapshot v2.8",          "type":"SBOM",                "size_kb":412, "hash":"sha256:c9a1e4b2…","status":"LOCKED",  "ts":"2026-04-28"},
            {"id":"EVP-004","name":"Exploit Chain Analysis",      "type":"TECHNICAL_REPORT",    "size_kb":3104,"hash":"sha256:d2f5c8a3…","status":"LOCKED",  "ts":"2026-05-04"},
            {"id":"EVP-005","name":"Customer Notification Records","type":"NOTIFICATION_LOG",   "size_kb":890, "hash":"sha256:e8b4d7c1…","status":"LOCKED",  "ts":"2026-05-01"},
            {"id":"EVP-006","name":"ENISA Communication Log",     "type":"COMMUNICATION_LOG",   "size_kb":156, "hash":"sha256:f1c6e9a4…","status":"LOCKED",  "ts":"2026-05-12"},
            {"id":"EVP-007","name":"RCA Draft Findings",          "type":"INVESTIGATION_REPORT","size_kb":0,   "hash":"pending…",        "status":"PENDING", "ts":None},
            {"id":"EVP-008","name":"Patch Release Notes v2.9.1",  "type":"PATCH_DOCUMENTATION", "size_kb":0,   "hash":"pending…",        "status":"PENDING", "ts":None},
            {"id":"EVP-009","name":"Final ENISA Report",          "type":"REGULATORY_FILING",   "size_kb":0,   "hash":"pending…",        "status":"PENDING", "ts":None},
            {"id":"EVP-010","name":"Audit Chain Export",          "type":"AUDIT_LOG",           "size_kb":0,   "hash":"pending…",        "status":"PENDING", "ts":None},
        ],
        "custody_log": [
            {"event":"Case opened",                    "actor":"System",               "ts":"2026-04-28 09:14"},
            {"event":"EVP-001 locked (ENISA filing)",  "actor":"Compliance Officer",   "ts":"2026-04-28 09:14"},
            {"event":"EVP-003 locked (SBOM snapshot)", "actor":"System",               "ts":"2026-04-28 09:14"},
            {"event":"EVP-002 locked (tech analysis)", "actor":"Security Engineer",    "ts":"2026-04-30 16:30"},
            {"event":"EVP-005 locked (notif records)", "actor":"Customer Success Lead","ts":"2026-05-01 09:30"},
            {"event":"EVP-004 locked (exploit chain)", "actor":"Security Engineer",    "ts":"2026-05-04 15:00"},
            {"event":"EVP-006 locked (ENISA comms)",   "actor":"Compliance Officer",   "ts":"2026-05-12 16:00"},
        ],
    },

    # ── Post-Closure Monitoring ──
    "monitoring": {
        "active": True,
        "monitoring_until": "2026-12-01",
        "last_kev_check": "2026-05-13 06:00 UTC",
        "exploit_intel_status": "NO_NEW_ACTIVITY",
        "patch_bypass": False,
        "sources": ["ENISA EUVDB", "CISA KEV", "NVD", "Vendor Security Bulletins", "BSI Advisories"],
        "reopen_triggers": [
            {"trigger":"Active exploitation detected",     "trigger_ja":"能動的エクスプロイト検出",    "status":"MONITORING"},
            {"trigger":"Mitigation bypass identified",     "trigger_ja":"緩和バイパス検出",           "status":"MONITORING"},
            {"trigger":"Regulator escalation",            "trigger_ja":"規制機関エスカレーション",    "status":"MONITORING"},
            {"trigger":"New affected products found",     "trigger_ja":"新たな影響製品発見",          "status":"MONITORING"},
            {"trigger":"KEV list addition",               "trigger_ja":"KEVリスト追加",               "status":"MONITORING"},
            {"trigger":"Customer-reported exploit",       "trigger_ja":"顧客報告エクスプロイト",      "status":"MONITORING"},
        ],
        "kev_log": [
            {"date":"2026-04-27","event":"CVE-2025-0001 not in KEV at detection"},
            {"date":"2026-05-01","event":"NVD severity confirmed: CRITICAL 9.8"},
            {"date":"2026-05-13","event":"No KEV addition — monitoring continues"},
        ],
    },

    # ── Executive & Legal Panel ──
    "executive": {
        "overall_risk": "MEDIUM",
        "unresolved_exposure": 847,
        "regulatory_risk": "MEDIUM",
        "regulatory_detail": "ENISA additional info requested — response due 2026-05-20",
        "litigation_risk": "LOW",
        "litigation_detail": "No customer-reported incidents. Proactive notification sent. Workaround available.",
        "sla_compliance_pct": 96.7,
        "sla_breaches": 1,
        "sla_breach_detail": "Customer notification SLA (72h) exceeded by 4h for 7 customers in non-EU timezone",
        "financial_low": 250000,
        "financial_high": 1500000,
        "days_open": 15,
        "days_to_patch": 8,
        "kpis": [
            {"name":"Time to Initial Report",   "name_ja":"初期報告時間",     "value":"18 h",       "target":"24 h",       "met":True},
            {"name":"Customer Notification",    "name_ja":"顧客通知",         "value":"72 h + 4 h", "target":"72 h",       "met":False},
            {"name":"Regulatory Response SLA",  "name_ja":"規制対応SLA",      "value":"On track",   "target":"2026-05-20", "met":True},
            {"name":"Patch ETA",                "name_ja":"パッチETA",        "value":"2026-05-22", "target":"30 days",    "met":True},
            {"name":"RCA Completion",           "name_ja":"RCA完了",          "value":"In progress","target":"2026-05-19", "met":True},
            {"name":"Evidence Package",         "name_ja":"証拠パッケージ",   "value":"60 %",       "target":"100 % by closure","met":True},
        ],
    },
}
