"""
CRA Decision Traceability System - Live Demo
Streamlit Application for Geoglyph Inc.

Demonstrates the complete 6-stage vulnerability decision pipeline:
1. CVE Ingestion → 2. SBOM Matching → 3. Conflict Detection →
4. Decision Proposal → 5. Human Review → 6. ENISA Reporting
"""

import streamlit as st
import pandas as pd
from datetime import datetime
import json

# Import custom modules
from mock_data import PRODUCTS, CVE_SCENARIOS, DECISION_RULES, THRESHOLDS
from decision_engine import DecisionEngine
from enisa_reporter import (
    generate_enisa_submission_json,
    generate_compliance_artifact_html,
    generate_html_download_link
)

# ============= PAGE CONFIG =============

st.set_page_config(
    page_title="CRA Decision Traceability System",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============= SESSION STATE INITIALIZATION =============

if "engine" not in st.session_state:
    st.session_state.engine = DecisionEngine(
        products=PRODUCTS,
        cve_scenarios=CVE_SCENARIOS,
        decision_rules=DECISION_RULES,
        thresholds=THRESHOLDS
    )

if "current_scenario" not in st.session_state:
    st.session_state.current_scenario = None

if "pipeline_results" not in st.session_state:
    st.session_state.pipeline_results = None

# ============= HELPER FUNCTIONS =============

def run_pipeline(scenario_key, product_name):
    """Execute the complete 6-stage pipeline"""
    engine = st.session_state.engine
    engine.reset_audit_trail()
    
    scenario = CVE_SCENARIOS[scenario_key]
    cve_id = scenario["cve_id"]
    
    # Stage 1: CVE Ingestion
    with st.spinner("⏳ Stage 1: Ingesting CVE from NVD..."):
        cve = engine.ingest_cve(cve_id, scenario_key)
        st.success(f"✅ Stage 1 Complete: CVE {cve_id} ingested")
    
    # Stage 2: SBOM Matching
    with st.spinner("⏳ Stage 2: Matching against SBOM..."):
        sbom_match = engine.match_sbom(cve, product_name)
        st.success(f"✅ Stage 2 Complete: {sbom_match['match_reason']}")
    
    # Stage 3: Conflict Detection
    with st.spinner("⏳ Stage 3: Detecting conflicts..."):
        conflict_info = engine.detect_conflicts(cve, sbom_match, scenario_key)
        if conflict_info["conflict_detected"]:
            st.warning(f"⚠️ Stage 3 Complete: Conflict detected ({conflict_info['conflict_type']})")
        else:
            st.success("✅ Stage 3 Complete: No conflicts detected")
    
    # Stage 4: Decision Proposal
    with st.spinner("⏳ Stage 4: Applying decision rules..."):
        decision_proposal = engine.propose_decision(cve, sbom_match, conflict_info, scenario_key)
        st.success(f"✅ Stage 4 Complete: Decision proposed ({decision_proposal['decision_type']})")
    
    # Stage 5: Human Review
    with st.spinner("⏳ Stage 5: Human review..."):
        review_result = engine.human_review(decision_proposal, "APPROVE")
        st.success(f"✅ Stage 5 Complete: Decision approved by Compliance Officer")
    
    # Stage 6: ENISA Reporting
    with st.spinner("⏳ Stage 6: ENISA submission..."):
        enisa_result = engine.enisa_submit(review_result, cve, product_name)
        st.success(f"✅ Stage 6 Complete: {enisa_result['status']}")
    
    # Compile results
    results = {
        "scenario_key": scenario_key,
        "scenario_name": scenario["name"],
        "product_name": product_name,
        "cve": cve,
        "sbom_match": sbom_match,
        "conflict_info": conflict_info,
        "decision_proposal": decision_proposal,
        "review_result": review_result,
        "enisa_result": enisa_result,
        "audit_trail": engine.get_audit_trail()
    }
    
    return results


def display_stage_card(stage_number, stage_name, stage_data):
    """Display a stage result card"""
    with st.container(border=True):
        col1, col2 = st.columns([1, 4])
        with col1:
            st.metric("Stage", stage_number, stage_name)
        with col2:
            st.json(stage_data)


# ============= MAIN HEADER =============

st.title("🔐 CRA Decision Traceability System")
st.markdown("**EU Cyber Resilience Act (2024/2847) - Live Demo for J-TEC**")
st.markdown("---")

# ============= SIDEBAR: SCENARIO SELECTOR =============

with st.sidebar:
    st.header("📋 Demo Scenarios")
    st.markdown("Select a vulnerability scenario to run through the complete pipeline.")
    
    scenarios = {
        "scenario_a": CVE_SCENARIOS["scenario_a"]["name"],
        "scenario_b": CVE_SCENARIOS["scenario_b"]["name"],
        "scenario_c": CVE_SCENARIOS["scenario_c"]["name"]
    }
    
    selected_scenario = st.selectbox(
        "Choose Scenario:",
        options=list(scenarios.keys()),
        format_func=lambda x: scenarios[x],
        key="scenario_selector"
    )
    
    st.markdown("---")
    
    st.header("🏭 J-TEC Products")
    product_names = list(PRODUCTS.keys())
    
    if selected_scenario == "scenario_a":
        selected_product = st.selectbox("Product:", product_names, index=1)  # Default: TS5525
    elif selected_scenario == "scenario_b":
        selected_product = st.selectbox("Product:", product_names, index=0)  # Default: BagMaker-X
    else:  # scenario_c
        selected_product = st.selectbox("Product:", product_names, index=2)  # Default: Model 137T
    
    st.markdown("---")
    
    if st.button("🚀 RUN DEMO PIPELINE", use_container_width=True, type="primary"):
        st.session_state.pipeline_results = run_pipeline(selected_scenario, selected_product)
        st.session_state.current_scenario = selected_scenario

# ============= MAIN CONTENT =============

if st.session_state.pipeline_results:
    results = st.session_state.pipeline_results
    
    # Top-level summary
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Scenario", results["scenario_name"].split(":")[0])
    with col2:
        st.metric("Product", results["product_name"])
    with col3:
        st.metric("CVE ID", results["cve"]["cve_id"])
    with col4:
        decision_color = "green" if results["review_result"]["final_decision_type"] == "REPORT" else "orange"
        st.metric("Final Decision", results["review_result"]["final_decision_type"], delta_color=decision_color)
    
    st.markdown("---")
    
    # ============= PIPELINE VISUALIZATION =============
    
    st.header("📊 Decision Pipeline (6 Stages)")
    
    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
        "1️⃣ Ingestion",
        "2️⃣ SBOM Match",
        "3️⃣ Conflict",
        "4️⃣ Rules",
        "5️⃣ Review",
        "6️⃣ ENISA",
        "📋 Artifacts"
    ])
    
    # ========== TAB 1: CVE INGESTION ==========
    with tab1:
        st.subheader("Stage 1: CVE Ingestion from NVD")
        col1, col2 = st.columns([1, 2])
        with col1:
            st.metric("CVE ID", results["cve"]["cve_id"])
            st.metric("CVSS Score", results["cve"]["cvss_score"])
            st.metric("Severity", results["cve"]["severity"])
        with col2:
            st.write("**Description:**")
            st.info(results["cve"]["description"])
            st.write("**Exploit Available:**", "✅ YES" if results["cve"]["exploit_available"] else "❌ NO")
            st.write("**Affected Versions:**", 
                    f"{results['cve']['affected_versions']['range_start']} → {results['cve']['affected_versions']['range_end']}")
    
    # ========== TAB 2: SBOM MATCHING ==========
    with tab2:
        st.subheader("Stage 2: SBOM Matching")
        
        match = results["sbom_match"]
        
        col1, col2 = st.columns([1, 2])
        with col1:
            st.metric("Product", match["product_name"])
            st.metric("Component Found", "✅ YES" if match["matching_component"] else "❌ NO")
            st.metric("Match Confidence", f"{match['match_confidence']:.0%}")
        with col2:
            st.write("**Component Details:**")
            if match["matching_component"]:
                st.write(f"- **Name:** {match['matching_component']}")
                st.write(f"- **Version:** {match['component_version']}")
                st.write(f"- **Affected Range:** {match['affected_range']}")
            st.write("**Match Result:**")
            if match["match_found"]:
                st.error(f"🔴 VULNERABLE - {match['match_reason']}")
            else:
                st.success(f"🟢 NOT VULNERABLE - {match['match_reason']}")
    
    # ========== TAB 3: CONFLICT DETECTION ==========
    with tab3:
        st.subheader("Stage 3: Conflict Detection")
        
        conflict = results["conflict_info"]
        
        if conflict["conflict_detected"]:
            st.warning(f"⚠️ **Conflict Detected:** {conflict['conflict_type']}")
        else:
            st.success("✅ No conflicts detected")
        
        st.write("**Evidence Summary:**")
        for evidence in conflict["evidence_summary"]:
            st.write(f"- {evidence}")
        
        if conflict["vex_available"]:
            st.info("📄 **VEX Document:** Available - Vendor provided statement")
    
    # ========== TAB 4: DECISION RULES & LOGIC ==========
    with tab4:
        st.subheader("Stage 4: Decision Proposer (Decision Rules)")
        
        decision = results["decision_proposal"]
        
        col1, col2 = st.columns([1, 2])
        with col1:
            st.metric("Proposed Decision", decision["decision_type"])
            st.metric("Confidence Score", f"{decision['confidence_score']:.0%}")
            st.metric("Auto-Decidable", "✅ YES" if decision["auto_decidable"] else "❌ NO")
        
        with col2:
            st.write("**Rules Fired:**")
            for rule in decision["rules_fired"]:
                with st.container(border=True):
                    st.write(f"**{rule['rule']}** - {'✅ TRIGGERED' if rule['triggered'] else '❌ Not triggered'}")
                    st.caption(rule["reasoning"])
        
        st.write("**Evidence Weighting:**")
        weighting = decision["evidence_weighting"]
        weighting_df = pd.DataFrame({
            "Evidence Source": ["SBOM Matching", "CVE Data (NVD)", "VEX Statement"],
            "Confidence": [
                f"{weighting['sbom_confidence']:.0%}",
                f"{weighting['cve_data_confidence']:.0%}",
                f"{weighting['vex_confidence']:.0%}"
            ]
        })
        st.dataframe(weighting_df, use_container_width=True, hide_index=True)
    
    # ========== TAB 5: HUMAN REVIEW ==========
    with tab5:
        st.subheader("Stage 5: Human Review Queue")
        
        review = results["review_result"]
        
        col1, col2 = st.columns([1, 2])
        with col1:
            st.metric("Reviewer", review["reviewer"])
            st.metric("Decision ID", review["decision_id"][:8] + "...")
            st.metric("Review Action", review["action"])
        with col2:
            st.write("**Justification:**")
            st.info(review["justification"])
    
    # ========== TAB 6: ENISA REPORTING ==========
    with tab6:
        st.subheader("Stage 6: ENISA Reporting")
        
        enisa = results["enisa_result"]
        
        col1, col2 = st.columns([1, 2])
        with col1:
            st.metric("Status", enisa["status"])
            st.metric("Submitted", "✅ YES" if enisa["submitted"] else "❌ NO")
        with col2:
            if enisa["submitted"]:
                st.success(f"✅ **ENISA Reference ID:** `{enisa['enisa_reference_id']}`")
                st.caption(f"Submitted at: {enisa['submission_timestamp']}")
            else:
                st.info("No ENISA submission required for this decision.")
    
    # ========== TAB 7: COMPLIANCE ARTIFACTS ==========
    with tab7:
        st.subheader("Stage 7: Compliance Artifacts")
        
        st.write("**Downloadable compliance artifacts for regulatory audit:**")
        
        # Generate HTML report
        html_report = generate_compliance_artifact_html(
            decision_id=results["review_result"]["decision_id"],
            cve=results["cve"],
            product_name=results["product_name"],
            sbom_match=results["sbom_match"],
            decision=results["review_result"],
            audit_trail=results["audit_trail"]
        )
        
        col1, col2 = st.columns(2)
        with col1:
            st.download_button(
                label="📥 Download HTML Compliance Report",
                data=html_report,
                file_name=f"CRA-Compliance-Report-{results['cve']['cve_id']}.html",
                mime="text/html",
                use_container_width=True
            )
        
        with col2:
            # Generate ENISA JSON
            enisa_json = generate_enisa_submission_json(
                decision=results["review_result"],
                cve=results["cve"],
                product_name=results["product_name"],
                sbom_match=results["sbom_match"],
                submission_id=results["enisa_result"]["submission_id"]
            )
            
            st.download_button(
                label="📋 Download ENISA JSON Payload",
                data=json.dumps(enisa_json, indent=2),
                file_name=f"ENISA-Report-{results['cve']['cve_id']}.json",
                mime="application/json",
                use_container_width=True
            )
    
    # ============= AUDIT TRAIL =============
    
    st.markdown("---")
    st.header("📋 Complete Audit Trail")
    st.markdown("**End-to-end traceability: Every decision step is logged and timestamped**")
    
    audit_df = pd.DataFrame(results["audit_trail"])
    if not audit_df.empty:
        audit_df["timestamp"] = pd.to_datetime(audit_df["timestamp"])
        st.dataframe(
            audit_df[["timestamp", "action", "details"]],
            use_container_width=True,
            hide_index=True
        )
    
else:
    # Initial state: Show instructions
    st.info("👈 **Select a scenario from the sidebar and click 'RUN DEMO PIPELINE' to begin**")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.subheader("Scenario A: CVE Affects Component")
        st.write(CVE_SCENARIOS["scenario_a"]["name"])
        st.caption("✓ Shows REPORT decision when component is vulnerable")
    
    with col2:
        st.subheader("Scenario B: Version Mismatch")
        st.write(CVE_SCENARIOS["scenario_b"]["name"])
        st.caption("✓ Shows NOT_REPORT decision when version is outside range")
    
    with col3:
        st.subheader("Scenario C: Conflict Detection")
        st.write(CVE_SCENARIOS["scenario_c"]["name"])
        st.caption("✓ Shows CONFLICT resolution when VEX overrides SBOM")

# ============= FOOTER =============

st.markdown("---")
st.markdown("""
<div style='text-align: center; font-size: 12px; color: gray;'>
    <p>🔐 <strong>CRA Decision Traceability System</strong> - Geoglyph Inc.</p>
    <p>Demo for J-TEC Co., Ltd. | EU Cyber Resilience Act (2024/2847)</p>
    <p>Built with Streamlit | All decision logic visible for audit compliance</p>
</div>
""", unsafe_allow_html=True)
