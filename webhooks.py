import asyncio
import hashlib
import hmac
import ipaddress
import json
import socket
import logging
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse
import httpx
from .database import db
from .config import settings
from .network_security import validate_https_public_url

MAX_ATTEMPTS = 8
logger = logging.getLogger(__name__)

def _validate_destination(url: str):
    validate_https_public_url(url, timeout=settings.REGULATORY_DNS_TIMEOUT)

def validate_destination(url: str):
    _validate_destination(url)
    return url

async def deliver_webhook(delivery_id: str):
    row = await db.get_webhook_delivery(delivery_id)
    if not row or row["status"] != "PENDING":
        return
    try:
        _validate_destination(row["url"])
    except Exception as exc:
        retry_at = datetime.now(timezone.utc) + timedelta(hours=1)
        await db.mark_webhook(delivery_id, False, None, str(exc)[:500], retry_at)
        return
    body = json.dumps({
        "id": row["event_id"],
        "type": row["event_type"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "data": row["payload"],
    }, separators=(",", ":"), sort_keys=True).encode()
    signature = hmac.new(row["secret"].encode(), body, hashlib.sha256).hexdigest()
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=False, trust_env=False) as client:
            response = await client.post(row["url"], content=body, headers={
                "Content-Type": "application/json",
                "X-RUACH-Event": row["event_type"],
                "X-RUACH-Signature": f"sha256={signature}",
                "User-Agent": "RUACH-Webhooks/1.0",
            })
        ok = 200 <= response.status_code < 300
        retry_at = datetime.now(timezone.utc) + timedelta(seconds=min(3600, 2 ** max(0, row["attempt"])))
        await db.mark_webhook(delivery_id, ok, response.status_code, None if ok else response.text[:500], retry_at)
    except Exception as exc:
        retry_at = datetime.now(timezone.utc) + timedelta(seconds=min(3600, 2 ** max(0, row["attempt"])))
        await db.mark_webhook(delivery_id, False, None, str(exc)[:500], retry_at)

async def queue_and_deliver(api_key_hash: str, event_type: str, payload: dict):
    try:
        deliveries = await db.queue_webhook(api_key_hash, event_type, payload)
        for delivery_id, _event_id in deliveries:
            asyncio.create_task(deliver_webhook(delivery_id))
    except Exception:
        logger.exception("webhook.queue_failed")
