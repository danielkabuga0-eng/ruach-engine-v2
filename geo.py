import logging
import ipaddress
import httpx
from .config import settings

logger = logging.getLogger(__name__)

async def localize_ip(client_ip: str | None) -> dict:
    if not client_ip:
        return {"status": "UNAVAILABLE", "reason": "no_client_ip"}
    try:
        ipaddress.ip_address(client_ip)
    except ValueError:
        return {"status": "UNAVAILABLE", "reason": "invalid_client_ip"}

    # Do not geolocate loopback/private addresses in development.
    if ipaddress.ip_address(client_ip).is_private or ipaddress.ip_address(client_ip).is_loopback:
        return {"status": "LOCAL", "ip": client_ip, "country": None, "currency": None, "timezone": None}

    url = settings.IP_GEO_URL_TEMPLATE.format(ip=client_ip)
    try:
        async with httpx.AsyncClient(timeout=settings.IP_GEO_TIMEOUT) as client:
            r = await client.get(url)
            r.raise_for_status()
            d = r.json()
        return {
            "status": "OK",
            "ip": client_ip,
            "country": d.get("country_code") or d.get("country"),
            "currency": d.get("currency"),
            "timezone": d.get("timezone"),
            "source": "configured_ip_geolocation_provider",
        }
    except Exception as exc:
        logger.warning("ip_geolocation_failed", extra={"error": str(exc)})
        return {"status": "DEGRADED", "ip": client_ip, "reason": "geolocation_unavailable"}
