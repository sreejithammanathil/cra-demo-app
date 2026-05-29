"""
CRA Readiness Assessment — Lead Capture
Saves contact form submissions to a local CSV and returns the saved record.
No Streamlit imports — pure logic.
"""

import csv
import os
from datetime import datetime

LEADS_CSV = os.path.join(os.path.dirname(__file__), "leads.csv")

FIELDNAMES = [
    "timestamp",
    "name",
    "email",
    "company",
    "role",
    "country",
    "score_pct",
    "readiness_level",
    "consent",
]


def save_lead(
    name: str,
    email: str,
    company: str,
    role: str,
    country: str,
    score_pct: float,
    readiness_level: str,
    consent: bool,
) -> dict:
    """
    Append one lead record to leads.csv.
    Returns the saved record dict.
    """
    record = {
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "name": name.strip(),
        "email": email.strip().lower(),
        "company": company.strip(),
        "role": role.strip(),
        "country": country.strip(),
        "score_pct": round(score_pct, 1),
        "readiness_level": readiness_level,
        "consent": "yes" if consent else "no",
    }

    file_exists = os.path.isfile(LEADS_CSV)
    with open(LEADS_CSV, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        if not file_exists:
            writer.writeheader()
        writer.writerow(record)

    return record


def load_leads() -> list[dict]:
    """Return all leads as a list of dicts (empty list if file not found)."""
    if not os.path.isfile(LEADS_CSV):
        return []
    with open(LEADS_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return list(reader)
