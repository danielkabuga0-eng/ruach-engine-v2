import logging
import httpx
import pybreaker
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

from .config import settings
from .tax_rules import EU_MEMBER_STATES

logger = logging.getLogger(__name__)

class TaxValidator:
    """Authoritative VAT validation adapter for EU VAT IDs via EU VIES.

    A network failure is REVIEW/DEGRADED, never CLEARED. A successful VIES
    response with valid=false is REJECTED. This deliberately avoids treating
    any HTTP 200 response as proof of tax-ID validity.
    """
    def __init__(self):
        self.breaker = pybreaker.CircuitBreaker(
            fail_max=settings.CIRCUIT_BREAKER_FAIL_THRESHOLD,
            reset_timeout=settings.CIRCUIT_BREAKER_COOLDOWN,
        )
        self._client = None

    async def _get_client(self):
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=settings.TAX_VALIDATION_TIMEOUT)
        return self._client

    @retry(
        stop=stop_after_attempt(2),
        wait=wait_exponential(multiplier=0.2, max=1),
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.NetworkError)),
        reraise=True,
    )
    async def _call_vies(self, country: str, tax_id: str):
        client = await self._get_client()
        envelope = f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <checkVat xmlns="urn:ec.europa.eu:taxud:vies:services:checkVat:types">
      <countryCode>{escape(country)}</countryCode>
      <vatNumber>{escape(tax_id[2:] if tax_id[:2].upper()==country else tax_id)}</vatNumber>
    </checkVat>
  </soap:Body>
</soap:Envelope>"""
        return await client.post(
            settings.VIES_API_URL,
            content=envelope,
            headers={"Content-Type": "text/xml; charset=utf-8", "SOAPAction": ""},
        )

    async def validate_tax_id(self, tax_id: str, country: str) -> dict:
        country = country.upper()
        if country not in EU_MEMBER_STATES:
            return {"status": "UNSUPPORTED", "reason": "VIES supports EU VAT validation only", "country": country}
        try:
            resp = await self.breaker.call_async(self._call_vies, country, tax_id)
            if resp.status_code != 200:
                raise RuntimeError(f"VIES HTTP {resp.status_code}")
            root = ET.fromstring(resp.text)
            valid = None
            for el in root.iter():
                if el.tag.endswith("}valid"):
                    valid = (el.text or "").strip().lower() == "true"
                    break
            if valid is True:
                return {"status": "VALID", "source": "EU_VIES", "country": country}
            if valid is False:
                return {"status": "INVALID", "source": "EU_VIES", "country": country}
            raise RuntimeError("VIES response did not contain a valid field")
        except pybreaker.CircuitBreakerError:
            return {"status": "DEGRADED", "reason": "circuit_open", "country": country}
        except Exception as exc:
            logger.warning("vies_validation_failed", extra={"country": country, "error": str(exc)})
            return {"status": "DEGRADED", "reason": "validation_unavailable", "country": country}

    async def close(self):
        if self._client:
            await self._client.aclose()

    def get_state(self):
        return {"state": self.breaker.current_state, "fail_count": self.breaker.fail_counter}

tax_validator = TaxValidator()
