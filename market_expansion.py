"""EU product-market expansion readiness engine.

This module is intentionally conservative: it produces a REVIEW-gated readiness
plan from structured product facts and configured requirements. It never claims
that a product is legally marketable merely because a checklist item matches.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from datetime import date
from typing import Any
import hashlib, json

TARGET_COUNTRIES = {
    "DE": "Germany", "FR": "France", "NL": "Netherlands", "ES": "Spain",
    "IT": "Italy", "BE": "Belgium", "PL": "Poland", "AT": "Austria",
}

@dataclass(frozen=True)
class Requirement:
    id: str
    title: str
    scope: str
    status: str
    severity: str
    rationale: str
    evidence_needed: tuple[str, ...]
    source_url: str
    authority: str
    effective_from: str | None = None

EU_REQUIREMENTS = (
    Requirement(
        "EU-CE-SCOPE", "CE conformity assessment", "product categories subject to EU harmonisation legislation",
        "REVIEW", "BLOCKING", "Confirm which EU harmonisation acts apply to the exact product and whether conformity assessment is required.",
        ("applicable legislation", "conformity assessment record", "EU Declaration of Conformity", "technical documentation"),
        "https://single-market-economy.ec.europa.eu/single-market/goods/ce-marking/manufacturers_en", "European Commission"
    ),
    Requirement(
        "EU-GPSR-SCOPE", "General Product Safety review", "non-food consumer products where applicable",
        "REVIEW", "HIGH", "Confirm whether the General Product Safety Regulation applies or a more specific product regime governs the product.",
        ("product classification", "risk assessment", "traceability information", "instructions/warnings"),
        "https://eur-lex.europa.eu/eli/reg/2023/988/oj", "European Union"
    ),
    Requirement(
        "EU-LANGUAGE", "Instructions and safety information", "products requiring accompanying information",
        "REVIEW", "HIGH", "Determine the languages and presentation required for the target market and product regime.",
        ("label artwork", "instructions", "safety warnings", "translation evidence"),
        "https://single-market-economy.ec.europa.eu/single-market/goods/building-blocks/conformity-assessment_en", "European Commission"
    ),
    Requirement(
        "EU-EPR-PACKAGING", "Packaging / EPR assessment", "products and packaging placed on national markets",
        "REVIEW", "HIGH", "Check national extended-producer-responsibility and packaging obligations for the target market.",
        ("packaging composition", "producer role", "national registration evidence"),
        "https://environment.ec.europa.eu/topics/waste-and-recycling/packaging-waste_en", "European Commission"
    ),
    Requirement(
        "EU-DPP", "Digital Product Passport applicability", "product groups covered by ESPR delegated measures",
        "REVIEW", "HIGH", "Determine whether the product group is covered by an applicable ecodesign delegated act and DPP requirements.",
        ("product group", "unique product identifier", "required product data", "DPP implementation evidence"),
        "https://single-market-economy.ec.europa.eu/news/digital-product-passport-registry-now-live-2026-07-20_en", "European Commission",
        "2027-02-18"
    ),
)

COUNTRY_REVIEW = {
    c: Requirement(
        f"{c}-NATIONAL", f"{TARGET_COUNTRIES[c]} national layer", "national rules that may supplement EU harmonised requirements",
        "REVIEW", "HIGH", "National implementation, language, packaging/EPR, registration, market-surveillance or sector-specific requirements require product-specific review.",
        ("target-country classification", "national registration evidence where applicable", "local-language evidence where applicable"),
        "https://single-market-economy.ec.europa.eu/single-market/strategy_en", "European Commission"
    ) for c in TARGET_COUNTRIES
}


def _hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def assess_market_entry(product: dict[str, Any], target_country: str) -> dict[str, Any]:
    country = str(target_country).upper().strip()
    if country not in TARGET_COUNTRIES:
        raise ValueError("target_country must be one of the configured EU launch markets")
    category = str(product.get("category", "")).strip().lower()
    consumer = bool(product.get("consumer_product", False))
    battery = bool(product.get("contains_battery", False))
    manufacturer_role = str(product.get("economic_operator_role", "manufacturer")).lower()
    existing_evidence = {str(x).upper() for x in (product.get("evidence") or [])}

    reqs = []
    for base in EU_REQUIREMENTS:
        include = True
        if base.id == "EU-GPSR-SCOPE" and not consumer:
            include = False
        if base.id == "EU-DPP" and not (battery or category in {"electronics", "electrical", "textiles", "furniture", "battery"}):
            include = True  # retained as a scope-check, never asserted as applicable
        if include:
            reqs.append(base)
    reqs.append(COUNTRY_REVIEW[country])

    items = []
    for r in reqs:
        missing = [x for x in r.evidence_needed if x.upper() not in existing_evidence]
        status = "READY_FOR_REVIEW" if not missing else "ACTION_REQUIRED"
        items.append({**asdict(r), "status": status, "missing_evidence": missing})

    blockers = sum(1 for x in items if x["status"] == "ACTION_REQUIRED" and x["severity"] == "BLOCKING")
    actions = sum(1 for x in items if x["status"] == "ACTION_REQUIRED")
    payload = {
        "target_country": country,
        "product": {"category": category, "consumer_product": consumer, "contains_battery": battery, "economic_operator_role": manufacturer_role},
        "items": items,
        "summary": {"total_requirements": len(items), "actions_required": actions, "blocking_actions": blockers},
        "decision": "REVIEW_REQUIRED",
        "policy": "RUACH does not declare legal marketability from this assessment; an authorized reviewer must resolve all applicable requirements.",
    }
    payload["assessment_hash"] = _hash(payload)
    return payload
