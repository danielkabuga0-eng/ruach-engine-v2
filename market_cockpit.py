"""EU market-entry launch cockpit: evidence, owners, remediation and review gates."""
from __future__ import annotations
from datetime import datetime, timezone
import hashlib, json

ALLOWED_STATUSES = {"OPEN", "IN_PROGRESS", "BLOCKED", "READY_FOR_REVIEW", "APPROVED"}

def _hash(payload):
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def build_work_items(assessment: dict):
    items=[]
    for item in assessment.get("items", []):
        if item.get("status") == "ACTION_REQUIRED":
            items.append({
                "requirement_id": item["id"],
                "title": item["title"],
                "severity": item["severity"],
                "owner_role": "COMPLIANCE_OWNER",
                "status": "OPEN",
                "missing_evidence": item.get("missing_evidence", []),
                "source_url": item.get("source_url"),
                "authority": item.get("authority"),
            })
    return items

def create_cockpit(assessment: dict):
    work = build_work_items(assessment)
    payload = {
        "assessment_hash": assessment["assessment_hash"],
        "decision": assessment["decision"],
        "work_items": work,
        "market_ready": False,
        "review_gate": "AUTHORIZED_REVIEW_REQUIRED",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    payload["cockpit_hash"] = _hash(payload)
    return payload

def recompute_status(work_items: list[dict], approved: bool=False):
    if not approved:
        return "BLOCKED" if any(x.get("severity") == "BLOCKING" and x.get("status") != "APPROVED" for x in work_items) else "IN_REVIEW"
    if any(x.get("status") != "APPROVED" for x in work_items):
        return "BLOCKED"
    return "MARKET_READY"
