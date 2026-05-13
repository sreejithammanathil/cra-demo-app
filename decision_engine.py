"""
Decision Engine for CRA Decision Traceability System
Implements 6-stage pipeline: Ingestion → Matching → Conflict Detection → 
Decision Proposal → Human Review → ENISA Reporting
"""

from datetime import datetime
from typing import Dict, List, Tuple
import uuid


class DecisionEngine:
    """Orchestrates the 6-stage decision pipeline"""
    
    def __init__(self, products: Dict, cve_scenarios: Dict, decision_rules: List, thresholds: Dict):
        self.products = products
        self.cve_scenarios = cve_scenarios
        self.decision_rules = decision_rules
        self.thresholds = thresholds
        self.decisions = {}
        self.audit_trail = []
    
    # ============= STAGE 1: CVE INGESTION =============
    
    def ingest_cve(self, cve_id: str, scenario_key: str) -> Dict:
        """Stage 1: Load CVE from scenario"""
        scenario = self.cve_scenarios[scenario_key]
        
        cve_record = {
            "stage": 1,
            "cve_id": cve_id,
            "description": scenario["cve_description"],
            "severity": scenario["severity"],
            "cvss_score": scenario["cvss_score"],
            "affected_versions": scenario["affected_versions"],
            "exploit_available": scenario.get("exploit_available", False),
            "ingested_at": datetime.now().isoformat()
        }
        
        self._log_action("CVE_INGESTED", f"CVE {cve_id} loaded from NVD")
        return cve_record
    
    # ============= STAGE 2: MATCHING ENGINE =============
    
    def match_sbom(self, cve: Dict, product_name: str) -> Dict:
        """Stage 2: Match CVE against SBOM components"""
        product = self.products[product_name]
        sbom = product["sbom"]
        
        affected_library = cve["affected_versions"]["library"]
        range_start = cve["affected_versions"]["range_start"]
        range_end = cve["affected_versions"]["range_end"]
        
        match_result = {
            "stage": 2,
            "product_name": product_name,
            "affected_library": affected_library,
            "match_found": False,
            "matching_component": None,
            "component_version": None,
            "affected_range": f"{range_start} - {range_end}",
            "match_confidence": 0.0,
            "match_reason": ""
        }
        
        # Search for matching component in SBOM
        for component in sbom["components"]:
            if affected_library.lower() in component["name"].lower():
                match_result["matching_component"] = component["name"]
                match_result["component_version"] = component["version"]
                
                # Check if version is within affected range
                if self._is_version_in_range(component["version"], range_start, range_end):
                    match_result["match_found"] = True
                    match_result["match_confidence"] = 0.95
                    match_result["match_reason"] = f"Version {component['version']} is within affected range"
                else:
                    match_result["match_found"] = False
                    match_result["match_confidence"] = 0.95
                    match_result["match_reason"] = f"Version {component['version']} is OUTSIDE affected range"
                break
        
        if not match_result["matching_component"]:
            match_result["match_reason"] = f"{affected_library} not found in product SBOM"
        
        self._log_action("SBOM_MATCHED", f"Matched CVE against {product_name} SBOM")
        return match_result
    
    # ============= STAGE 3: CONFLICT DETECTOR =============
    
    def detect_conflicts(self, cve: Dict, sbom_match: Dict, scenario_key: str) -> Dict:
        """Stage 3: Detect conflicting evidence"""
        scenario = self.cve_scenarios[scenario_key]
        
        conflict_result = {
            "stage": 3,
            "conflict_detected": False,
            "conflict_type": None,
            "evidence_summary": [],
            "vex_available": scenario.get("vex_arrives", False)
        }
        
        # In Scenario C, conflict is detected between SBOM and VEX
        if scenario_key == "scenario_c" and scenario.get("vex_arrives"):
            conflict_result["conflict_detected"] = True
            conflict_result["conflict_type"] = "SBOM vs VEX"
            conflict_result["evidence_summary"] = [
                f"SBOM: Component FOUND ({sbom_match['matching_component']} {sbom_match['component_version']})",
                f"CVE: Affects {cve['affected_versions']['library']} {cve['affected_versions']['range_start']}-{cve['affected_versions']['range_end']}",
                f"SBOM Match: {sbom_match['match_reason']}",
                f"VEX: ARRIVED - States component IS AFFECTED but claims mitigation exists"
            ]
            self._log_action("CONFLICT_DETECTED", "Evidence conflict: SBOM vs VEX statement")
        else:
            conflict_result["evidence_summary"] = [
                f"SBOM: {sbom_match['matching_component'] if sbom_match['matching_component'] else 'Component NOT found'}",
                f"CVE: Affects {cve['affected_versions']['library']} {cve['affected_versions']['range_start']}-{cve['affected_versions']['range_end']}",
                f"Match Status: {sbom_match['match_reason']}"
            ]
        
        return conflict_result
    
    # ============= STAGE 4: DECISION PROPOSER =============
    
    def propose_decision(self, cve: Dict, sbom_match: Dict, conflict_info: Dict, scenario_key: str) -> Dict:
        """Stage 4: Apply decision rules and propose decision"""
        scenario = self.cve_scenarios[scenario_key]
        
        decision_proposal = {
            "stage": 4,
            "decision_type": None,
            "decision_maker_type": "SYSTEM_AUTO",
            "auto_decidable": True,
            "confidence_score": 0.0,
            "rules_fired": [],
            "evidence_weighting": {
                "sbom_confidence": sbom_match["match_confidence"],
                "cve_data_confidence": 0.98,
                "vex_confidence": 0.0
            }
        }
        
        # ===== RULE EVALUATION =====
        
        # Rule 1: Critical + Exploit
        if cve["cvss_score"] >= self.thresholds["critical_severity"] and cve.get("exploit_available"):
            decision_proposal["rules_fired"].append({
                "rule": "R1: Critical Severity + Exploit Available",
                "triggered": True,
                "reasoning": f"CVSS {cve['cvss_score']} >= {self.thresholds['critical_severity']} AND exploit available"
            })
            decision_proposal["decision_type"] = "REPORT"
            decision_proposal["confidence_score"] = 0.95
        
        # Rule 2: High Severity + Affected
        elif cve["cvss_score"] >= self.thresholds["high_severity"] and sbom_match["match_found"]:
            decision_proposal["rules_fired"].append({
                "rule": "R2: High Severity + Component Affected",
                "triggered": True,
                "reasoning": f"CVSS {cve['cvss_score']} >= {self.thresholds['high_severity']} AND component affected"
            })
            decision_proposal["decision_type"] = "REPORT"
            decision_proposal["confidence_score"] = 0.85
        
        # Rule 3: Version Mismatch
        elif not sbom_match["match_found"]:
            decision_proposal["rules_fired"].append({
                "rule": "R3: Version Mismatch (Outside Affected Range)",
                "triggered": True,
                "reasoning": f"Component version is outside affected range"
            })
            decision_proposal["decision_type"] = "NOT_REPORT"
            decision_proposal["confidence_score"] = 0.95
            decision_proposal["auto_decidable"] = True
        
        # Rule 5: Conflict Detected
        if conflict_info["conflict_detected"]:
            decision_proposal["rules_fired"].append({
                "rule": "R5: Conflicting Evidence Detected",
                "triggered": True,
                "reasoning": "Evidence conflict detected (SBOM vs VEX)"
            })
            decision_proposal["decision_type"] = "CONFLICT"
            decision_proposal["auto_decidable"] = False
            decision_proposal["decision_maker_type"] = "HUMAN"
            decision_proposal["confidence_score"] = 0.0
        
        # Determine if auto-decidable
        decision_proposal["auto_decidable"] = decision_proposal["confidence_score"] >= self.thresholds["auto_decide_confidence"]
        
        if not decision_proposal["auto_decidable"] and decision_proposal["decision_type"] != "CONFLICT":
            decision_proposal["decision_maker_type"] = "HUMAN"
        
        self._log_action("DECISION_PROPOSED", 
                        f"Proposed: {decision_proposal['decision_type']} (confidence: {decision_proposal['confidence_score']:.0%})")
        
        return decision_proposal
    
    # ============= STAGE 5: HUMAN REVIEW QUEUE =============
    
    def human_review(self, decision_proposal: Dict, reviewer_action: str = "APPROVE") -> Dict:
        """Stage 5: Human compliance officer reviews and approves/rejects"""
        review_result = {
            "stage": 5,
            "decision_id": str(uuid.uuid4()),
            "reviewer": "Compliance Officer",
            "review_timestamp": datetime.now().isoformat(),
            "action": reviewer_action,
            "final_decision_type": decision_proposal["decision_type"],
            "justification": ""
        }
        
        if reviewer_action == "APPROVE":
            if decision_proposal["decision_type"] == "CONFLICT":
                review_result["justification"] = "Reviewed evidence from multiple sources. Determined that VEX mitigation is sufficient to prevent exploitation."
            elif decision_proposal["decision_type"] == "REPORT":
                review_result["justification"] = "Confirmed: Component is vulnerable and must be reported to ENISA per CRA Article 14."
            else:  # NOT_REPORT
                review_result["justification"] = "Confirmed: Component version is outside affected range. No reporting required."
            
            review_result["status"] = "APPROVED"
        else:
            review_result["justification"] = "Decision rejected. Requesting additional evidence."
            review_result["status"] = "REJECTED"
        
        self._log_action("DECISION_REVIEWED", f"Human review: {reviewer_action} - {review_result['justification']}")
        
        return review_result
    
    # ============= STAGE 6: ENISA REPORTING =============
    
    def enisa_submit(self, decision: Dict, cve: Dict, product_name: str) -> Dict:
        """Stage 6: Submit to ENISA if decision is REPORT"""
        enisa_result = {
            "stage": 6,
            "submission_id": str(uuid.uuid4()),
            "submitted": False,
            "submission_timestamp": datetime.now().isoformat(),
            "enisa_reference_id": None,
            "status": "NOT_APPLICABLE"
        }
        
        if decision["final_decision_type"] == "REPORT":
            enisa_result["submitted"] = True
            enisa_result["status"] = "SUBMITTED"
            enisa_result["enisa_reference_id"] = f"ENISA-2026-{str(uuid.uuid4())[:8].upper()}"
            
            self._log_action("ENISA_SUBMITTED", 
                           f"Vulnerability report submitted: {enisa_result['enisa_reference_id']}")
        else:
            enisa_result["status"] = "SKIPPED"
            self._log_action("ENISA_SKIPPED", 
                           f"No ENISA submission (decision: {decision['final_decision_type']})")
        
        return enisa_result
    
    # ============= HELPER METHODS =============
    
    def _is_version_in_range(self, version: str, range_start: str, range_end: str) -> bool:
        """Check if a version falls within affected range (simple string comparison)"""
        try:
            v = tuple(map(int, version.split('.')))
            start = tuple(map(int, range_start.split('.')))
            end = tuple(map(int, range_end.split('.')))
            return start <= v <= end
        except:
            return False
    
    def _log_action(self, action: str, details: str):
        """Log action to audit trail"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "details": details
        }
        self.audit_trail.append(log_entry)
    
    def get_audit_trail(self) -> List[Dict]:
        """Return complete audit trail"""
        return self.audit_trail
    
    def reset_audit_trail(self):
        """Clear audit trail for new scenario"""
        self.audit_trail = []
