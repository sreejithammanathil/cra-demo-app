# CRA Decision Traceability System - Live Demo

**EU Cyber Resilience Act (2024/2847) - Interactive Demonstration for J-TEC Co., Ltd.**

---

## 📋 Project Overview

This is a **standalone Streamlit application** that demonstrates the complete **6-stage vulnerability decision pipeline** for EU CRA compliance:

1. **CVE Ingestion** → Load vulnerability from NVD
2. **SBOM Matching** → Check if product component is affected
3. **Conflict Detection** → Identify evidence conflicts (SBOM vs VEX)
4. **Decision Proposal** → Apply rule-based decision logic
5. **Human Review** → Compliance officer approval
6. **ENISA Reporting** → Submit to ENISA (if REPORT decision)

---

## 🚀 Quick Start

### Option 1: Deploy to Streamlit Cloud (Recommended - Shareable Link)

1. **Push to GitHub:**
   ```bash
   git init
   git add .
   git commit -m "Initial commit: CRA demo"
   git push origin main
   ```

2. **Deploy on Streamlit Cloud:**
   - Go to https://share.streamlit.io
   - Click "New app"
   - Select your GitHub repo, branch, and `app.py`
   - Click Deploy
   - **Your shareable link is ready!** ✅

### Option 2: Run Locally

```bash
# Install dependencies
pip install -r requirements.txt

# Run the app
streamlit run app.py

# Opens at http://localhost:8501
```

---

## 📊 Demo Scenarios

### Scenario A: CVE Affects Component (REPORT)
- **CVE:** CVE-2026-0001 (Critical OpenSSL vulnerability)
- **Product:** TS5525
- **Result:** Component version 1.0.2u is WITHIN affected range → **REPORT to ENISA**

### Scenario B: Version Mismatch (NOT_REPORT)
- **CVE:** CVE-2026-0002 (OpenSSL 1.0.0-1.0.9)
- **Product:** BagMaker-X 2100
- **Result:** Component version 1.1.1k is OUTSIDE affected range → **NOT_REPORT**

### Scenario C: Conflict Detection (VEX Override)
- **CVE:** CVE-2026-0003 (nginx DoS)
- **Product:** Model 137T
- **Initial:** NOT_REPORT (no exploit available)
- **VEX Arrives:** Vendor says AFFECTED but mitigated via config
- **Final:** NOT_REPORT (accepted mitigation) → Manual approval required

---

## 🏭 J-TEC Products

Pre-loaded product SBOMs:

| Product | Components | Type |
|---------|-----------|------|
| **BagMaker-X 2100** | Siemens PLC 3.2, Beckhoff HMI 5.1, OpenSSL 1.1.1k | Reel-Fed |
| **TS5525** | Mitsubishi PLC 2.1, OpenSSL 1.0.2u, curl 7.68 | Sheet-Fed |
| **Model 137T** | OMRON PLC 4.0, nginx 1.18, libssl 1.1 | Advanced |

---

## 📂 Project Structure

```
cra-demo/
├── app.py                  # Main Streamlit application
├── mock_data.py            # Products, SBOMs, CVE scenarios
├── decision_engine.py      # 6-stage pipeline logic
├── enisa_reporter.py       # Compliance artifact generation
├── requirements.txt        # Python dependencies
├── .gitignore             # Git configuration
└── README.md              # This file
```

---

## ⚙️ Technical Architecture

### Core Components

**`mock_data.py`** - Pre-loaded data:
- J-TEC product definitions with SBOM components
- 3 complete CVE scenarios (A, B, C)
- Decision rules (5 rules with confidence scoring)
- Regulatory thresholds

**`decision_engine.py`** - 6-stage pipeline:
```python
engine.ingest_cve(cve_id, scenario_key)      # Stage 1
engine.match_sbom(cve, product_name)         # Stage 2
engine.detect_conflicts(cve, sbom, scenario) # Stage 3
engine.propose_decision(cve, sbom, conflict) # Stage 4
engine.human_review(decision_proposal)       # Stage 5
engine.enisa_submit(review_result, cve)      # Stage 6
```

**`enisa_reporter.py`** - Compliance artifacts:
- HTML compliance report (audit trail, evidence, justification)
- JSON ENISA submission payload
- Download links for regulatory records

**`app.py`** - Streamlit UI:
- Scenario selector (sidebar)
- 7-tab pipeline visualization
- Real-time decision logic transparency
- Downloadable compliance artifacts
- Complete audit trail (every decision step logged)

---

## 🔍 Key Features

✅ **Complete Decision Transparency** - See all rules fire, confidence scores, evidence weighting

✅ **Multi-Jurisdiction Support** - Built for EU CRA + Japanese regulations (24-hour vs 60-day SLA)

✅ **Conflict Detection** - Handles SBOM vs VEX conflicts with human override

✅ **Regulatory Audit Trail** - Every decision logged with timestamps, reasoning, and approval chain

✅ **Downloadable Artifacts** - HTML compliance reports + ENISA JSON for regulatory submission

✅ **No ML / Deterministic Logic** - Rule-based decisions (appropriate for low-volume CVE decisions)

---

## 🎯 Demo Flow (Live)

1. **Select scenario** from sidebar (A, B, or C)
2. **Select product** (BagMaker-X, TS5525, or Model 137T)
3. **Click "RUN DEMO PIPELINE"**
4. **Watch all 6 stages execute** in real-time with detailed logging
5. **View decision dashboard** with evidence weighting and rules applied
6. **Download compliance artifacts** (HTML report + ENISA JSON)
7. **Review audit trail** showing complete decision history

---

## 📋 Compliance & Standards

- **EU Cyber Resilience Act (2024/2847)** - Article 14 (vulnerability reporting), Article 20 (record-keeping)
- **ENISA NVD Integration** - 24-hour reporting SLA
- **SBOM Standards** - CycloneDX/SPDX compatible
- **VEX Support** - VEX document override logic
- **Audit Trail** - 10+ year retention requirement

---

## 🔐 Security & Privacy

- ✅ No sensitive data in code (all mock/demo data)
- ✅ No external API calls (fully self-contained)
- ✅ No database (stateless, session-based)
- ✅ No user authentication required (internal demo)
- ✅ HTTPS ready (Streamlit Cloud handles SSL)

---

## 📞 Support

- **Geoglyph Inc.** - Toyofumi Tabata (CEO), Anvesh Anmeshaan (Technical Advisor)
- **For J-TEC Partnership:** Masato Shimizu (J-TEC CEO) - info@jtec.tokyo

---

## 📜 License

Internal demo for Geoglyph Inc. internship project. All rights reserved.

---

**Created:** May 2026 | **Status:** Ready for Live Demonstration
