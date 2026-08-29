from datetime import date
from .tax_rules import EU_MEMBER_STATES

# Metadata registry. A jurisdiction is only "LIVE" for a capability when an
# authoritative provider/rule pack is actually configured. Metadata alone is not
# presented as legal/tax coverage.
_COUNTRIES = {
    "AT": ("EUR", "Europe/Vienna"), "BE": ("EUR", "Europe/Brussels"), "BG": ("BGN", "Europe/Sofia"),
    "HR": ("EUR", "Europe/Zagreb"), "CY": ("EUR", "Asia/Nicosia"), "CZ": ("CZK", "Europe/Prague"),
    "DE": ("EUR", "Europe/Berlin"), "DK": ("DKK", "Europe/Copenhagen"), "EE": ("EUR", "Europe/Tallinn"),
    "ES": ("EUR", "Europe/Madrid"), "FI": ("EUR", "Europe/Helsinki"), "FR": ("EUR", "Europe/Paris"),
    "GR": ("EUR", "Europe/Athens"), "HU": ("HUF", "Europe/Budapest"), "IE": ("EUR", "Europe/Dublin"),
    "IT": ("EUR", "Europe/Rome"), "LT": ("EUR", "Europe/Vilnius"), "LU": ("EUR", "Europe/Luxembourg"),
    "LV": ("EUR", "Europe/Riga"), "MT": ("EUR", "Europe/Malta"), "NL": ("EUR", "Europe/Amsterdam"),
    "PL": ("PLN", "Europe/Warsaw"), "PT": ("EUR", "Europe/Lisbon"), "RO": ("RON", "Europe/Bucharest"),
    "SE": ("SEK", "Europe/Stockholm"), "SI": ("EUR", "Europe/Ljubljana"), "SK": ("EUR", "Europe/Bratislava"),
    "GB": ("GBP", "Europe/London"), "CH": ("CHF", "Europe/Zurich"), "NO": ("NOK", "Europe/Oslo"),
    "IS": ("ISK", "Atlantic/Reykjavik"), "US": ("USD", "America/New_York"), "CA": ("CAD", "America/Toronto"),
    "MX": ("MXN", "America/Mexico_City"), "BR": ("BRL", "America/Sao_Paulo"), "AR": ("ARS", "America/Argentina/Buenos_Aires"),
    "AE": ("AED", "Asia/Dubai"), "SA": ("SAR", "Asia/Riyadh"), "QA": ("QAR", "Asia/Qatar"),
    "BH": ("BHD", "Asia/Bahrain"), "OM": ("OMR", "Asia/Muscat"), "IL": ("ILS", "Asia/Jerusalem"),
    "KE": ("KES", "Africa/Nairobi"), "ZA": ("ZAR", "Africa/Johannesburg"), "NG": ("NGN", "Africa/Lagos"),
    "GH": ("GHS", "Africa/Accra"), "TZ": ("TZS", "Africa/Dar_es_Salaam"), "UG": ("UGX", "Africa/Kampala"),
    "RW": ("RWF", "Africa/Kigali"), "EG": ("EGP", "Africa/Cairo"),
    "IN": ("INR", "Asia/Kolkata"), "SG": ("SGD", "Asia/Singapore"), "AU": ("AUD", "Australia/Sydney"),
    "NZ": ("NZD", "Pacific/Auckland"), "JP": ("JPY", "Asia/Tokyo"), "KR": ("KRW", "Asia/Seoul"),
}


def capabilities(country: str) -> dict:
    c = country.upper()
    currency, timezone = _COUNTRIES.get(c, (None, None))
    live_vat = c in EU_MEMBER_STATES
    tax_id = "LIVE" if live_vat else "NOT_CONFIGURED"
    tax_det = "BASELINE_EU_B2B" if live_vat else "NOT_CONFIGURED"
    if live_vat:
        overall = "BASELINE"
    elif currency is not None:
        overall = "METADATA_ONLY"
    else:
        overall = "UNKNOWN"
    return {
        "jurisdiction": c,
        "known": currency is not None,
        "overall_status": overall,
        "currency": currency,
        "timezone": timezone,
        "tax_id_validation": tax_id,
        "tax_determination": tax_det,
        "e_invoicing": "NOT_CONFIGURED",
        "government_clearance": "NOT_CONFIGURED",
        "reporting": "NOT_CONFIGURED",
        "rule_version": "EU-B2B-BASELINE-2026.08" if live_vat else None,
        "effective_from": "2026-08-01" if live_vat else None,
        "note": (
            "LIVE/BASELINE only where an authoritative provider or rule pack is configured. "
            "Metadata presence is not legal coverage."
        ),
    }


def registry() -> list[dict]:
    return [capabilities(c) for c in sorted(_COUNTRIES)]


def coverage_summary() -> dict:
    """Aggregate honest coverage counts for /v1/status and ops views."""
    items = registry()
    return {
        "total": len(items),
        "baseline": sum(1 for j in items if j["overall_status"] == "BASELINE"),
        "metadata_only": sum(1 for j in items if j["overall_status"] == "METADATA_ONLY"),
        "live_providers": ["EU_VIES"],
        "policy": "Unsupported capabilities return REVIEW or NOT_CONFIGURED — never fabricated approval.",
    }
