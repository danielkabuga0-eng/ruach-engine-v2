from dataclasses import dataclass
from decimal import Decimal
from .tax_rules import tax_treatment, get_standard_vat_rate, EU_MEMBER_STATES
from .jurisdiction import JurisdictionAssessment

RULE_VERSION = "EU-B2B-BASELINE-2026.08"

@dataclass
class ComplianceDecision:
    code: str
    status: str
    tax_rate: Decimal
    treatment: str
    confidence: float
    reasons: list[str]


def decide(assessment: JurisdictionAssessment, seller_validation: dict, buyer_validation: dict, supply_type: str) -> ComplianceDecision:
    reasons = list(assessment.reasons)
    if assessment.review_required:
        return ComplianceDecision("REVIEW_JURISDICTION", "REVIEW", Decimal("0"), "UNDETERMINED", assessment.confidence,
                                  reasons + ["Jurisdiction evidence is insufficient for an automated compliance decision"])
    seller, buyer = assessment.seller_country, assessment.buyer_country
    if seller_validation.get("status") == "INVALID" or buyer_validation.get("status") == "INVALID":
        return ComplianceDecision("INVALID_TAX_ID", "REJECTED", Decimal("0"), "REJECTED", 1.0,
                                  reasons + ["At least one authoritative VAT validation returned INVALID"])
    if seller_validation.get("status") in {"DEGRADED", "UNSUPPORTED"} or buyer_validation.get("status") in {"DEGRADED", "UNSUPPORTED"}:
        return ComplianceDecision("VALIDATION_UNAVAILABLE", "REVIEW", Decimal("0"), "PENDING_VALIDATION", assessment.confidence,
                                  reasons + ["Authoritative VAT validation could not be confirmed"])
    buyer_valid = buyer_validation.get("status") in {"VALID", "ASSUMED_VALID"}
    treatment, rate = tax_treatment(seller, buyer, buyer_valid, supply_type)
    if treatment == "REVERSE_CHARGE":
        reasons += ["Seller and buyer are in different EU Member States", "Buyer VAT registration validated by VIES", "Baseline EU B2B reverse-charge treatment selected"]
        return ComplianceDecision("REVERSE_CHARGE", "CLEARED", Decimal("0"), treatment, 0.98, reasons)
    rate = get_standard_vat_rate(seller)
    reasons.append(f"Domestic/standard treatment uses configured {seller} standard VAT rate")
    return ComplianceDecision("STANDARD_VAT", "CLEARED", rate, treatment, 0.95, reasons)


def build_evidence(invoice, assessment, seller_validation, buyer_validation, decision, localization):
    nodes = [
        {"id":"invoice", "type":"input", "value":invoice.invoice_number},
        {"id":"seller_jurisdiction", "type":"jurisdiction", "value":assessment.seller_country, "source":assessment.seller_source},
        {"id":"buyer_jurisdiction", "type":"jurisdiction", "value":assessment.buyer_country, "source":assessment.buyer_source},
        {"id":"seller_validation", "type":"validation", "provider":seller_validation.get("provider"), "status":seller_validation.get("status")},
        {"id":"buyer_validation", "type":"validation", "provider":buyer_validation.get("provider"), "status":buyer_validation.get("status")},
        {"id":"tax_decision", "type":"decision", "code":decision.code, "treatment":decision.treatment, "rate":str(decision.tax_rate)},
        {"id":"localization", "type":"localization", "country":localization.get("country"), "currency":localization.get("currency"), "timezone":localization.get("timezone")},
    ]
    edges = [
        {"from":"invoice","to":"seller_jurisdiction","reason":"jurisdiction resolution"},
        {"from":"invoice","to":"buyer_jurisdiction","reason":"jurisdiction resolution"},
        {"from":"seller_jurisdiction","to":"seller_validation","reason":"VAT validation"},
        {"from":"buyer_jurisdiction","to":"buyer_validation","reason":"VAT validation"},
        {"from":"seller_validation","to":"tax_decision","reason":"compliance rule evaluation"},
        {"from":"buyer_validation","to":"tax_decision","reason":"compliance rule evaluation"},
    ]
    return {"rule_version": RULE_VERSION, "nodes": nodes, "edges": edges, "reasons": decision.reasons, "confidence": decision.confidence}
