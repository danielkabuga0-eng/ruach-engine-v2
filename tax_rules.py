from decimal import Decimal
from typing import Dict, Optional, Tuple

COUNTRY_VAT_RATES: Dict[str, Decimal] = {
    "AT":Decimal("20"),"BE":Decimal("21"),"BG":Decimal("20"),"HR":Decimal("25"),
    "CY":Decimal("19"),"CZ":Decimal("21"),"DE":Decimal("19"),"DK":Decimal("25"),
    "EE":Decimal("24"),"EL":Decimal("24"),"ES":Decimal("21"),"FI":Decimal("25.5"),
    "FR":Decimal("20"),"GR":Decimal("24"),"HU":Decimal("27"),"IE":Decimal("23"),
    "IT":Decimal("22"),"LT":Decimal("21"),"LU":Decimal("17"),"LV":Decimal("21"),
    "MT":Decimal("18"),"NL":Decimal("21"),"PL":Decimal("23"),"PT":Decimal("23"),
    "RO":Decimal("21"),"SE":Decimal("25"),"SI":Decimal("22"),"SK":Decimal("23"),
    "GB":Decimal("20"),"US":Decimal("0"),"KE":Decimal("16"),"AU":Decimal("10"),
}
EU_MEMBER_STATES = set("""
AT BE BG HR CY CZ DE DK EE EL ES FI FR GR HU IE IT LT LU LV MT NL PL PT RO
SE SI SK
""".split())

def normalize_country(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    v = value.strip().upper()
    return v if len(v) == 2 else None

def detect_country_from_tax_id(tax_id: str) -> Optional[str]:
    if not tax_id or len(tax_id) < 2:
        return None
    p = tax_id[:2].upper()
    return p if p in COUNTRY_VAT_RATES else None

def get_standard_vat_rate(country: str) -> Decimal:
    c = normalize_country(country)
    if c not in COUNTRY_VAT_RATES:
        raise ValueError(f"No configured VAT rate for jurisdiction {country!r}")
    return COUNTRY_VAT_RATES[c]

def tax_treatment(seller_country: str, buyer_country: str, buyer_vat_valid: bool,
                  supply_type: str = "services") -> Tuple[str, Decimal]:
    seller = normalize_country(seller_country)
    buyer = normalize_country(buyer_country)
    if not seller or not buyer:
        raise ValueError("Both seller and buyer jurisdictions are required")
    if seller != buyer and seller in EU_MEMBER_STATES and buyer in EU_MEMBER_STATES and buyer_vat_valid:
        return "REVERSE_CHARGE", Decimal("0")
    return "STANDARD", get_standard_vat_rate(seller)
