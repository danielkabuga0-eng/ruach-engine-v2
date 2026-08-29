from dataclasses import dataclass
from typing import Optional
from .tax_rules import EU_MEMBER_STATES, normalize_country

@dataclass(frozen=True)
class JurisdictionAssessment:
    seller_country: Optional[str]
    buyer_country: Optional[str]
    seller_source: str
    buyer_source: str
    confidence: float
    review_required: bool
    reasons: list[str]


def assess_party_country(country: Optional[str], inferred_country: Optional[str], party_name: str) -> tuple[Optional[str], str, float, list[str]]:
    explicit = normalize_country(country)
    inferred = normalize_country(inferred_country)
    if explicit:
        return explicit, "invoice", 1.0, [f"{party_name} jurisdiction supplied explicitly"]
    if inferred:
        return inferred, "tax_id_prefix", 0.85, [f"{party_name} jurisdiction inferred from normalized VAT ID prefix"]
    return None, "unknown", 0.0, [f"{party_name} jurisdiction could not be established"]


def assess_jurisdictions(seller_country: Optional[str], buyer_country: Optional[str],
                         seller_inferred: Optional[str], buyer_inferred: Optional[str]) -> JurisdictionAssessment:
    seller, seller_source, seller_conf, seller_reasons = assess_party_country(seller_country, seller_inferred, "Seller")
    buyer, buyer_source, buyer_conf, buyer_reasons = assess_party_country(buyer_country, buyer_inferred, "Buyer")
    confidence = min(seller_conf, buyer_conf)
    reasons = seller_reasons + buyer_reasons
    review = seller is None or buyer is None or confidence < 0.8
    if seller and buyer and seller != buyer and seller in EU_MEMBER_STATES and buyer in EU_MEMBER_STATES:
        reasons.append("Cross-border EU jurisdiction pair detected")
    return JurisdictionAssessment(seller, buyer, seller_source, buyer_source, confidence, review, reasons)
