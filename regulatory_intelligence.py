"""Regulatory intelligence primitives for RUACH.

This module intentionally separates *observed regulatory changes* from *active
compliance rules*. A source snapshot or extracted proposal can never silently
change production tax behaviour. Human/authorized review is required before a
rule version becomes ACTIVE.
"""
from dataclasses import dataclass, asdict
from datetime import date
from hashlib import sha256
from typing import Any
from urllib.parse import urlparse
import re
from .network_security import validate_https_public_url

@dataclass(frozen=True)
class RegulatorySource:
    source_id: str
    jurisdiction: str
    authority: str
    title: str
    url: str
    source_type: str
    authoritative: bool = True
    notes: str = ""

# Official/primary source catalogue. URLs are references for monitoring; they do
# not by themselves activate a rule. Deployments can extend this catalogue.
SOURCES = (
    RegulatorySource("EU_TAXATION_CUSTOMS", "EU", "European Commission", "Taxation and Customs Union", "https://taxation-customs.ec.europa.eu/", "official_portal"),
    RegulatorySource("EU_VAT_VIES", "EU", "European Commission", "VIES VAT validation", "https://ec.europa.eu/taxation_customs/vies/", "validation"),
    RegulatorySource("EU_EINVOICING", "EU", "European Commission", "European eInvoicing", "https://single-market-economy.ec.europa.eu/single-market/public-procurement/digital-procurement/einvoicing_en", "standard_and_policy"),
    RegulatorySource("UK_HMRC_VAT", "GB", "HM Revenue & Customs", "VAT guidance", "https://www.gov.uk/government/organisations/hm-revenue-customs", "official_portal"),
    RegulatorySource("KE_KRA", "KE", "Kenya Revenue Authority", "Tax administration", "https://www.kra.go.ke/", "official_portal"),
    RegulatorySource("ZA_SARS", "ZA", "South African Revenue Service", "Tax administration", "https://www.sars.gov.za/", "official_portal"),
    RegulatorySource("NG_FIRS", "NG", "Federal Inland Revenue Service", "Tax administration", "https://www.firs.gov.ng/", "official_portal"),
    RegulatorySource("AE_FTA", "AE", "Federal Tax Authority", "Tax administration", "https://tax.gov.ae/", "official_portal"),
    RegulatorySource("SA_ZATCA", "SA", "ZATCA", "E-invoicing and tax administration", "https://zatca.gov.sa/", "official_portal"),
    RegulatorySource("IN_GST", "IN", "Goods and Services Tax", "GST portal", "https://www.gst.gov.in/", "official_portal"),
    RegulatorySource("AU_TAX", "AU", "Australian Taxation Office", "Tax administration", "https://www.ato.gov.au/", "official_portal"),
    RegulatorySource("SG_IRAS", "SG", "Inland Revenue Authority of Singapore", "Tax administration", "https://www.iras.gov.sg/", "official_portal"),
    RegulatorySource("JP_NTA", "JP", "National Tax Agency", "Tax administration", "https://www.nta.go.jp/", "official_portal"),
)

DOCUMENT_FORMATS = {"PDF", "XML", "JSON", "UBL", "PEPPOL_BIS", "API", "PORTAL_UPLOAD", "OTHER"}

@dataclass(frozen=True)
class RegulatoryChange:
    jurisdiction: str
    rule_id: str
    version: str
    effective_from: str | None
    change_type: str
    title: str
    summary: str
    source_id: str
    source_url: str
    affected_document_types: tuple[str, ...] = ()
    required_formats: tuple[str, ...] = ()
    submission_channel: str | None = None
    confidence: float = 0.0
    status: str = "DETECTED"


def sources() -> list[dict]:
    return [asdict(s) for s in SOURCES]


def validate_format_list(values: list[str] | tuple[str, ...]) -> list[str]:
    normalized = [str(v).upper().strip() for v in values]
    invalid = [v for v in normalized if v not in DOCUMENT_FORMATS]
    if invalid:
        raise ValueError(f"Unsupported document format(s): {', '.join(invalid)}")
    return list(dict.fromkeys(normalized))


def build_change_proposal(payload: dict) -> RegulatoryChange:
    country = str(payload.get("jurisdiction", "")).upper()
    if country != "EU" and not re.fullmatch(r"[A-Z]{2}", country):
        raise ValueError("jurisdiction must be EU or a two-letter ISO code")
    source_id = str(payload.get("source_id", "")).strip()
    rule_id = str(payload.get("rule_id", "")).strip()
    version = str(payload.get("version", "")).strip()
    title = str(payload.get("title", "")).strip()
    summary = str(payload.get("summary", "")).strip()
    if not rule_id or not version or not title or not summary:
        raise ValueError("rule_id, version, title and summary are required")
    source = next((s for s in SOURCES if s.source_id == source_id and s.jurisdiction in {country, "EU"}), None)
    if not source:
        raise ValueError("source_id must reference a configured authoritative source for the jurisdiction")
    confidence = float(payload.get("confidence", 0))
    if not 0 <= confidence <= 1:
        raise ValueError("confidence must be between 0 and 1")
    formats = tuple(validate_format_list(payload.get("required_formats", [])))
    docs = tuple(str(x).strip().upper() for x in payload.get("affected_document_types", []))
    return RegulatoryChange(
        jurisdiction=country,
        rule_id=rule_id[:128],
        version=version[:128],
        effective_from=payload.get("effective_from"),
        change_type=str(payload.get("change_type", "DOCUMENT_REQUIREMENT")).strip().upper(),
        title=title[:256],
        summary=summary[:2000],
        source_id=source.source_id,
        source_url=source.url,
        affected_document_types=docs,
        required_formats=formats,
        submission_channel=str(payload.get("submission_channel", "")).strip() or None,
        confidence=confidence,
        status="DETECTED",
    )


def diff_requirements(before: dict, after: dict) -> dict:
    """Produce a deterministic compliance diff; no legal interpretation is implied."""
    keys = ("required_formats", "submission_channel", "required_fields", "accepted_document_types")
    changes = []
    for key in keys:
        old = before.get(key)
        new = after.get(key)
        if old != new:
            changes.append({"field": key, "before": old, "after": new})
    return {"changed": bool(changes), "changes": changes}


def classify_document_requirement(requirement: dict, document_format: str) -> dict:
    fmt = str(document_format).upper().strip()
    accepted = [str(x).upper() for x in requirement.get("accepted_document_types", [])]
    required = [str(x).upper() for x in requirement.get("required_formats", [])]
    if fmt not in DOCUMENT_FORMATS:
        return {"status": "REVIEW", "accepted": False, "reason": "Unknown document format"}
    if required and fmt not in required:
        return {"status": "REJECTED", "accepted": False, "reason": "Format is not in the configured required format set"}
    if accepted and fmt not in accepted:
        return {"status": "REJECTED", "accepted": False, "reason": "Document format is not accepted by the configured requirement"}
    if not required and not accepted:
        return {"status": "REVIEW", "accepted": False, "reason": "No authoritative format requirement is configured"}
    return {"status": "CLEARED", "accepted": True, "reason": "Format matches the configured requirement"}


def hash_snapshot(content: bytes) -> str:
    return sha256(content).hexdigest()


def safe_source_url(url: str, *, allowed_hosts: set[str] | None = None) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname:
            return False
        host = parsed.hostname.lower().rstrip(".")
        return not allowed_hosts or host in allowed_hosts
    except Exception:
        return False


def source_authority_profile(source: dict) -> dict:
    """Return explicit authority metadata used to gate regulatory evidence."""
    authoritative = bool(source.get("authoritative", False))
    source_type = str(source.get("source_type", "")).lower()
    score = 1.0 if authoritative and source_type in {"official_portal", "standard_and_policy", "validation"} else 0.5 if authoritative else 0.0
    return {"authoritative": authoritative, "authority_score": score, "source_type": source_type}


def normalize_effective_window(requirement: dict) -> dict:
    """Normalize effective date plus optional transition/grace period without interpreting law."""
    return {
        "effective_from": requirement.get("effective_from"),
        "transition_until": requirement.get("transition_until"),
        "effective_window_source": requirement.get("effective_window_source"),
        "review_required": bool(requirement.get("review_required", True)),
    }

# --- Regulatory-to-machine-rule intelligence ---
# These helpers deliberately produce a PROPOSED requirement. They never activate
# production compliance logic and are intended to be reviewed by an authorized
# compliance/tax professional.

FORMAT_ALIASES = {
    "PDF": "PDF", "XML": "XML", "UBL": "UBL", "JSON": "JSON",
    "PEPPOL BIS": "PEPPOL_BIS", "PEPPOL_BIS": "PEPPOL_BIS",
    "API": "API", "PORTAL": "PORTAL_UPLOAD", "PORTAL UPLOAD": "PORTAL_UPLOAD",
}


def extract_machine_requirements(text: str, *, jurisdiction: str, source_id: str,
                                  rule_id: str, version: str, effective_from: str | None = None) -> dict:
    """Extract conservative, testable requirements from regulatory prose.

    This is intentionally deterministic. It creates a *proposal* and assigns
    REVIEW_REQUIRED unless the text contains enough explicit signals. It is not
    legal interpretation and should be paired with expert review.
    """
    raw = str(text or "")
    normalized = re.sub(r"\s+", " ", raw).strip()
    if not normalized:
        raise ValueError("regulatory text is required")
    jurisdiction = str(jurisdiction).upper().strip()
    if jurisdiction != "EU" and not re.fullmatch(r"[A-Z]{2}", jurisdiction):
        raise ValueError("jurisdiction must be EU or a two-letter ISO code")
    source = next((s for s in SOURCES if s.source_id == str(source_id) and s.jurisdiction in {jurisdiction, "EU"}), None)
    if not source:
        raise ValueError("source_id must reference a configured authoritative source for the jurisdiction")
    upper = normalized.upper()
    formats: list[str] = []
    for token, fmt in FORMAT_ALIASES.items():
        # API/portal are submission channels, not document serialization formats.
        if fmt in {"API", "PORTAL_UPLOAD"}:
            continue
        if re.search(rf"\b{re.escape(token)}\b", upper) and fmt not in formats:
            formats.append(fmt)

    required_fields: list[str] = []
    field_patterns = {
        "seller_tax_id": r"(?:SELLER|SUPPLIER).*?(?:TAX|VAT)[ -]?ID",
        "buyer_tax_id": r"(?:BUYER|CUSTOMER).*?(?:TAX|VAT)[ -]?ID",
        "invoice_number": r"INVOICE[ -]?NUMBER",
        "issue_date": r"ISSUE[ -]?DATE",
        "currency": r"\bCURRENCY\b",
    }
    for field, pattern in field_patterns.items():
        if re.search(pattern, upper):
            required_fields.append(field)

    # Conservative document acceptance semantics. We distinguish “required”
    # from “mentioned” and explicitly capture common rejection language so a
    # statement such as “PDF is no longer accepted; XML/UBL is required” does
    # not accidentally treat PDF as an allowed format.
    rejected_formats: list[str] = []
    for token, fmt in FORMAT_ALIASES.items():
        if fmt in {"API", "PORTAL_UPLOAD"}:
            continue
        if re.search(rf"\b{re.escape(token)}\b\s+(?:IS\s+)?(?:NO\s+LONGER\s+)?(?:NOT|UNACCEPTED|UNACCEPTABLE|REJECTED|DISALLOWED|ACCEPTED)", upper):
            rejected_formats.append(fmt)
        elif re.search(rf"\b(?:NO\s+LONGER\s+ACCEPT(?:ED|ABLE)|NOT\s+ACCEPT(?:ED|ABLE)|REJECT(?:ED|ED)|DISALLOW(?:ED)?)\b[^.\n]*\b{re.escape(token)}\b", upper):
            rejected_formats.append(fmt)

    channel = None
    if re.search(r"\b(?:SUBMIT|SUBMISSION|TRANSMIT|REPORT).*?\bAPI\b", upper):
        channel = "API"
    elif re.search(r"\bPORTAL\b", upper):
        channel = "PORTAL_UPLOAD"
    elif re.search(r"\bPEPPOL\b", upper):
        channel = "PEPPOL_NETWORK"

    date_match = re.search(r"(?:EFFECTIVE|FROM|STARTING)(?:\s+ON)?\s+(\d{4}-\d{2}-\d{2})", upper)
    detected_effective = date_match.group(1) if date_match else effective_from

    # Scope extraction is deliberately small and explicit; unknown scope stays
    # absent and therefore remains review-gated.
    scope = None
    scope_match = re.search(r"\b(B2B|B2C|B2G|C2B|C2C)\b", upper)
    if scope_match:
        scope = scope_match.group(1)

    # A requirement is only promoted to a required format when the prose uses
    # an explicit obligation signal. Mere mentions remain evidence, not rules.
    obligation = bool(re.search(r"\b(?:MUST|REQUIRED|REQUIRES|SHALL|MANDATORY|ONLY|NO LONGER ACCEPTED)\b", upper))
    if not obligation:
        formats = []
    accepted_formats = [fmt for fmt in formats if fmt not in rejected_formats]

    explicit = sum(bool(x) for x in (accepted_formats, rejected_formats, required_fields, channel, detected_effective, scope))
    confidence = min(0.95, 0.35 + explicit * 0.15)
    if not formats and not required_fields and not channel:
        confidence = 0.20

    return {
        "jurisdiction": str(jurisdiction).upper(),
        "rule_id": str(rule_id),
        "version": str(version),
        "effective_from": detected_effective,
        "source_id": str(source_id),
        "required_formats": accepted_formats,
        "rejected_formats": sorted(set(rejected_formats)),
        "accepted_document_types": ["INVOICE"] if re.search(r"\bINVOICE(?:S)?\b", upper) else [],
        "required_fields": required_fields,
        "submission_channel": channel,
        "scope": scope,
        "confidence": round(confidence, 3),
        "status": "REVIEW_REQUIRED",
        "authority_mode": "PROPOSED_MACHINE_RULE",
        "source_excerpt_hash": sha256(normalized.encode("utf-8")).hexdigest(),
        "review_required": True,
        "warning": "Extracted requirements are engineering proposals, not legal advice or automatically active rules.",
    }


def semantic_requirement_diff(before: dict, after: dict) -> dict:
    """Compare normalized compliance requirements and classify engineering impact."""
    fields = (
        "required_formats", "rejected_formats", "accepted_document_types", "required_fields",
        "submission_channel", "effective_from", "jurisdiction", "scope",
    )
    changes = []
    for key in fields:
        old = before.get(key)
        new = after.get(key)
        if isinstance(old, list): old = sorted({str(x).upper() for x in old})
        if isinstance(new, list): new = sorted({str(x).upper() for x in new})
        if old != new:
            severity = "HIGH" if key in {"required_formats", "submission_channel"} else "MEDIUM"
            changes.append({"field": key, "before": old, "after": new, "severity": severity})
    high = sum(c["severity"] == "HIGH" for c in changes)
    return {
        "changed": bool(changes),
        "change_count": len(changes),
        "high_impact_changes": high,
        "risk": "HIGH" if high else ("MEDIUM" if changes else "LOW"),
        "changes": changes,
        "engineering_actions": [
            f"Update validation for {c['field']}" for c in changes
            if c["field"] in {"required_formats", "required_fields", "accepted_document_types"}
        ] + (["Update submission integration"] if any(c["field"] == "submission_channel" for c in changes) else []),
    }


def build_customer_impact_plan(requirement: dict, customer_systems: list[dict]) -> dict:
    """Map a proposed requirement to customer-owned systems/templates."""
    affected = []
    required_formats = {str(x).upper() for x in requirement.get("required_formats", [])}
    required_fields = {str(x) for x in requirement.get("required_fields", [])}
    channel = requirement.get("submission_channel")
    for system in customer_systems or []:
        current_formats = {str(x).upper() for x in system.get("document_formats", [])}
        missing_formats = sorted(required_formats - current_formats)
        missing_fields = sorted(required_fields - {str(x) for x in system.get("fields", [])})
        channel_gap = bool(channel and str(system.get("submission_channel", "")).upper() != str(channel).upper())
        if missing_formats or missing_fields or channel_gap:
            affected.append({
                "system": system.get("system", "unknown"),
                "missing_formats": missing_formats,
                "missing_fields": missing_fields,
                "submission_channel_gap": channel_gap,
                "risk": "HIGH" if channel_gap or missing_formats else "MEDIUM",
            })
    return {
        "affected_systems": len(affected),
        "affected": affected,
        "total_systems_reviewed": len(customer_systems or []),
        "review_required": True,
        "authoritative": False,
    }


def execute_document_compliance(requirement: dict, document: dict, *, evaluated_at: str | None = None) -> dict:
    """Execute an approved document requirement against a concrete transaction.

    This is the differentiating RUACH execution layer: regulatory intelligence is
    converted into a deterministic, explainable transaction decision. The caller
    must supply an already-approved/active requirement. No legal interpretation
    or rule activation occurs here.
    """
    from datetime import date
    evaluated = evaluated_at or date.today().isoformat()
    fmt = str(document.get("document_format", "")).upper().strip()
    channel = str(document.get("submission_channel", "")).upper().strip()
    fields = {str(x) for x in (document.get("fields") or [])}
    violations = []
    required_formats = {str(x).upper() for x in (requirement.get("required_formats") or [])}
    accepted = {str(x).upper() for x in (requirement.get("accepted_document_types") or [])}
    required_fields = {str(x) for x in (requirement.get("required_fields") or [])}
    effective_from = requirement.get("effective_from")

    if effective_from and str(effective_from) > evaluated:
        return {
            "status": "REVIEW", "decision_code": "RULE_NOT_YET_EFFECTIVE",
            "violations": [], "remediation": [], "review_required": True,
            "reason": "The authoritative rule is not yet effective.",
            "evidence": _execution_evidence(requirement, document, evaluated, "REVIEW", "RULE_NOT_YET_EFFECTIVE"),
        }
    if fmt not in DOCUMENT_FORMATS:
        violations.append({"code": "UNKNOWN_FORMAT", "message": "Document format is not recognized."})
    if required_formats and fmt not in required_formats:
        violations.append({"code": "FORMAT_NOT_ALLOWED", "message": f"Required format set is {sorted(required_formats)}."})
    if accepted and str(document.get("document_type", "INVOICE")).upper() not in accepted:
        violations.append({"code": "DOCUMENT_TYPE_NOT_ACCEPTED", "message": "Document type is outside the approved requirement."})
    if requirement.get("submission_channel") and channel != str(requirement["submission_channel"]).upper():
        violations.append({"code": "SUBMISSION_CHANNEL_MISMATCH", "message": f"Submission channel must be {requirement['submission_channel']}."})
    for field in sorted(required_fields - fields):
        violations.append({"code": "MISSING_REQUIRED_FIELD", "field": field, "message": f"Required field missing: {field}."})

    if violations:
        remediation = []
        if any(v["code"] == "FORMAT_NOT_ALLOWED" for v in violations):
            remediation.append("Emit the document in an approved structured format.")
        if any(v["code"] == "SUBMISSION_CHANNEL_MISMATCH" for v in violations):
            remediation.append("Route the submission through the configured authoritative channel.")
        remediation.extend([f"Populate required field: {v['field']}." for v in violations if v.get("field")])
        status = "REJECTED"
        code = "REGULATORY_REQUIREMENT_VIOLATION"
    else:
        remediation = []
        status = "CLEARED"
        code = "REGULATORY_REQUIREMENTS_SATISFIED"
    return {
        "status": status, "decision_code": code, "violations": violations,
        "remediation": remediation, "review_required": False,
        "rule_id": requirement.get("rule_id"), "rule_version": requirement.get("version"),
        "effective_from": effective_from, "source_id": requirement.get("source_id"),
        "evidence": _execution_evidence(requirement, document, evaluated, status, code),
    }


def _execution_evidence(requirement: dict, document: dict, evaluated_at: str, status: str, code: str) -> dict:
    import json
    payload = {
        "rule_id": requirement.get("rule_id"), "version": requirement.get("version"),
        "effective_from": requirement.get("effective_from"), "source_id": requirement.get("source_id"),
        "document": document, "evaluated_at": evaluated_at, "status": status, "decision_code": code,
    }
    digest = sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()
    return {"provenance": {"source_id": requirement.get("source_id"), "rule_id": requirement.get("rule_id"), "version": requirement.get("version")}, "evaluation_hash": digest, "evaluated_at": evaluated_at, "status": status}
